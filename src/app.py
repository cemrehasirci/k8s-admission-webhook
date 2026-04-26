import os
import time
import logging

from fastapi import FastAPI, Request
import uvicorn

from prometheus_client import Counter, Histogram, start_http_server

from policies import (
    init_k8s_client,
    get_namespace_environment,
    load_policy_for_environment,
    validate_storage,
    validate_images,
    validate_security,
    validate_resources,
)

# =====================================================
# LOGGING SETUP
# =====================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("admission-webhook")

# =====================================================
# METRICS SERVER
# =====================================================
# Prometheus metrics endpoint: http://<pod-ip>:9091/metrics
start_http_server(9091)

# =====================================================
# PROMETHEUS METRICS (GENERIC)
# =====================================================
ADMISSION_REQUESTS = Counter("admission_requests_total", "Total admission requests")
ADMISSION_ALLOWED = Counter("admission_requests_allowed_total", "Allowed admission requests")
ADMISSION_DENIED = Counter("admission_requests_denied_total", "Denied admission requests")

ADMISSION_LATENCY = Histogram(
    "admission_request_duration_seconds",
    "Admission webhook latency"
)

# =====================================================
# FASTAPI APP
# =====================================================
app = FastAPI()

# =====================================================
# CONFIG
# =====================================================
ENFORCED_STORAGE_CLASS = os.getenv("ENFORCED_STORAGE_CLASS", "longhorn")

POLICY_CONFIGMAP_NAME = os.getenv("POLICY_CONFIGMAP_NAME", "webhook-policy-config")
POLICY_CONFIGMAP_NAMESPACE = os.getenv("POLICY_CONFIGMAP_NAMESPACE", "webhook-system")
DEFAULT_ENVIRONMENT = os.getenv("DEFAULT_ENVIRONMENT", "dev")

# =====================================================
# K8S CLIENT
# =====================================================
# Needed for:
# - PVC lookup in storage policy
# - Namespace label lookup for environment detection
# - ConfigMap lookup for environment-based policies
core_v1 = init_k8s_client()

# =====================================================
# ADMISSION RESPONSE
# =====================================================
def admission_response(uid: str, allowed: bool, message: str, warnings: list[str] | None = None) -> dict:
    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
            "status": {
                "message": message
            }
        }
    }

    # Kubernetes AdmissionReview supports warning messages.
    # In dev environment, root user usage can be allowed but returned as warning.
    if warnings:
        response["response"]["warnings"] = warnings

    return response

# =====================================================
# WEBHOOK ENDPOINT
# =====================================================
@app.post("/validate")
async def validate(request: Request):
    start_time = time.time()
    body = await request.json()
    ADMISSION_REQUESTS.inc()

    req = body.get("request", {}) or {}
    uid = req.get("uid", "")

    # Only Pod objects
    if req.get("kind", {}).get("kind") != "Pod":
        ADMISSION_ALLOWED.inc()
        logger.info("DECISION=ALLOW POLICY=non-pod RESOURCE=non-pod")
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, True, "Non-Pod resource allowed")

    pod = req.get("object", {}) or {}
    spec = pod.get("spec", {}) or {}
    meta = pod.get("metadata", {}) or {}
    pod_name = meta.get("name", "unknown")

    # Namespace can come from AdmissionReview request.
    # If not available there, fallback to pod metadata.
    namespace = req.get("namespace") or meta.get("namespace", "default")

    # 0) Environment-based policy loading
    environment = get_namespace_environment(
        core_v1=core_v1,
        namespace=namespace,
        default_environment=DEFAULT_ENVIRONMENT
    )

    policy = load_policy_for_environment(
        core_v1=core_v1,
        configmap_name=POLICY_CONFIGMAP_NAME,
        configmap_namespace=POLICY_CONFIGMAP_NAMESPACE,
        environment=environment
    )

    logger.info(
        f"POLICY_LOAD ENVIRONMENT={environment} POD={pod_name} NAMESPACE={namespace}"
    )

    # 1) Storage policy
    ok, msg = validate_storage(pod, core_v1, ENFORCED_STORAGE_CLASS)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=storage ENVIRONMENT={environment} REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # 2) Image policy
    # dev  -> latest tag is allowed
    # test -> latest or tagless images are denied
    ok, msg = validate_images(spec, policy)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=image ENVIRONMENT={environment} REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # 3) Security policy
    # dev  -> root user returns warning but does not deny
    # test -> root user is denied
    ok, msg, warnings = validate_security(spec, policy)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=security ENVIRONMENT={environment} REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # 4) Resource policy
    # Resource requests and limits are mandatory in both dev and test.
    if policy.get("requireResources", True):
        ok, msg = validate_resources(spec)
        if not ok:
            ADMISSION_DENIED.inc()
            logger.warning(
                f"DECISION=DENY POLICY=resources ENVIRONMENT={environment} REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
            )
            ADMISSION_LATENCY.observe(time.time() - start_time)
            return admission_response(uid, False, msg)

    # Allow
    ADMISSION_ALLOWED.inc()

    if warnings:
        logger.info(
            f"DECISION=ALLOW_WITH_WARNING ENVIRONMENT={environment} WARNINGS='{warnings}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, True, "Allowed with warnings", warnings)

    logger.info(
        f"DECISION=ALLOW ENVIRONMENT={environment} POD={pod_name} NAMESPACE={namespace}"
    )
    ADMISSION_LATENCY.observe(time.time() - start_time)
    return admission_response(uid, True, "Allowed")


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="/tls/tls.key",
        ssl_certfile="/tls/tls.crt"
    )