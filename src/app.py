import os
import time
import logging

from fastapi import FastAPI, Request
import uvicorn

from prometheus_client import Counter, Histogram, start_http_server

from policies import (
    init_k8s_client,
    validate_storage,
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

# =====================================================
# K8S CLIENT (needed for PVC lookup in storage policy)
# =====================================================
core_v1 = init_k8s_client()

# =====================================================
# ADMISSION RESPONSE
# =====================================================
def admission_response(uid: str, allowed: bool, message: str) -> dict:
    return {
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
    namespace = meta.get("namespace", "default")

    # 1) Storage policy
    ok, msg = validate_storage(pod, core_v1, ENFORCED_STORAGE_CLASS)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=storage REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # 2) Security policy
    ok, msg = validate_security(spec)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=security REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # 3) Resource policy (v4.0)
    ok, msg = validate_resources(spec)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=resources REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # Allow
    ADMISSION_ALLOWED.inc()
    logger.info(f"DECISION=ALLOW POD={pod_name} NAMESPACE={namespace}")
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