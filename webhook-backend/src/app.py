import os
import time
import logging
import uvicorn

from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Optional

from prometheus_client import Counter, Histogram, start_http_server

from audit_logger import save_audit_log

from audit_summary import get_audit_summary, check_database_health
from fastapi.responses import JSONResponse


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
# RESPONSE MODELS
# =====================================================
class AuditItem(BaseModel):
    policy: Optional[str] = None
    namespace: Optional[str] = None
    count: int = 0


class AuditSummaryResponse(BaseModel):
    total_requests: int
    allowed_requests: int
    denied_requests: int
    most_denied_policy: Optional[AuditItem] = None
    most_problematic_namespace: Optional[AuditItem] = None

# =====================================================
# FASTAPI APP
# =====================================================
app = FastAPI(
    title="Kubernetes Admission Webhook API",
    description=(
        "A Validating Admission Webhook API for Kubernetes Pod security policies. "
        "It validates Pod creation requests, records admission decisions, "
        "and provides audit analytics from PostgreSQL."
    ),
    version="6.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# =====================================================
# CONFIG
# =====================================================
ALLOWED_STORAGE_CLASSES = [
    sc.strip()
    for sc in os.getenv("ALLOWED_STORAGE_CLASSES", "longhorn,standard").split(",")
    if sc.strip()
]

POLICY_CONFIGMAP_NAME = os.getenv("POLICY_CONFIGMAP_NAME", "webhook-policy-config")
POLICY_CONFIGMAP_NAMESPACE = os.getenv("POLICY_CONFIGMAP_NAMESPACE", "webhook-system")
DEFAULT_ENVIRONMENT = os.getenv("DEFAULT_ENVIRONMENT", "dev")

# =====================================================
# K8S CLIENT
# =====================================================
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

    if warnings:
        response["response"]["warnings"] = warnings

    return response


# =====================================================
# STRUCTURED DECISION LOGGING
# =====================================================
def colorize_decision(decision: str) -> str:
    """
    Adds ANSI color codes to the DECISION value.
    - ALLOW              -> green
    - ALLOW_WITH_WARNING -> yellow
    - DENY               -> red
    """
    if decision == "ALLOW":
        return f"\033[92m{decision}\033[0m"
    if decision == "ALLOW_WITH_WARNING":
        return f"\033[93m{decision}\033[0m"
    if decision == "DENY":
        return f"\033[91m{decision}\033[0m"
    return decision


def log_decision(
    level: str,
    uid: str,
    decision: str,
    policy: str,
    environment: str,
    namespace: str,
    pod_name: str,
    reason: str,
    start_time: float,
    warnings: list[str] | None = None
) -> None:
    latency = time.time() - start_time
    warning_text = ",".join(warnings) if warnings else "-"
    colored_decision = colorize_decision(decision)

    message = (
        f"EVENT=admission_review "
        f"DECISION={colored_decision} "
        f"POLICY={policy} "
        #f"ENV={environment} "
        f"NAMESPACE={namespace} "
        f"POD={pod_name} "
        f"REASON=\"{reason}\" "
        f"WARNINGS=\"{warning_text}\" "
        #f"LATENCY={latency:.4f}s"
    )

    if level == "warning":
        logger.warning(message)
    else:
        logger.info(message)


# =====================================================
# WEBHOOK ENDPOINT
# =====================================================
@app.post(
    "/validate",
    include_in_schema=False
)

async def validate(request: Request):
    start_time = time.time()
    body = await request.json()
    ADMISSION_REQUESTS.inc()

    req = body.get("request", {}) or {}
    uid = req.get("uid", "")

    # Only Pod objects
    if req.get("kind", {}).get("kind") != "Pod":
        ADMISSION_ALLOWED.inc()
        ADMISSION_LATENCY.observe(time.time() - start_time)

        log_decision(
            level="info",
            uid=uid,
            decision="ALLOW",
            policy="non-pod",
            environment="-",
            namespace=req.get("namespace", "-"),
            pod_name="-",
            reason="Non-Pod resource allowed",
            start_time=start_time
        )

        return admission_response(uid, True, "Non-Pod resource allowed")

    pod = req.get("object", {}) or {}
    spec = pod.get("spec", {}) or {}
    meta = pod.get("metadata", {}) or {}
    pod_name = meta.get("name", "unknown")

    # Extract container images
    containers = spec.get("containers", [])
    images = [container.get("image", "unknown") for container in containers]
    image_text = ",".join(images)

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

    # 1) Storage policy
    ok, msg = validate_storage(pod, core_v1, ALLOWED_STORAGE_CLASSES)
    if not ok:
        ADMISSION_DENIED.inc()
        ADMISSION_LATENCY.observe(time.time() - start_time)

        log_decision(
            level="warning",
            uid=uid,
            decision="DENY",
            policy="storage",
            environment=environment,
            namespace=namespace,
            pod_name=pod_name,
            reason=msg,
            start_time=start_time
        )

        save_audit_log(
            namespace=namespace,
            pod_name=pod_name,
            image=image_text,
            decision="deny",
            policy="storage",
            reason=msg,
            environment=environment
        )

        return admission_response(uid, False, msg)

    # 2) Image policy
    # dev  -> latest tag is allowed
    # test -> latest or tagless images are denied
    ok, msg = validate_images(spec, policy)
    if not ok:
        ADMISSION_DENIED.inc()
        ADMISSION_LATENCY.observe(time.time() - start_time)

        log_decision(
            level="warning",
            uid=uid,
            decision="DENY",
            policy="image",
            environment=environment,
            namespace=namespace,
            pod_name=pod_name,
            reason=msg,
            start_time=start_time
        )

        save_audit_log(
            namespace=namespace,
            pod_name=pod_name,
            image=image_text,
            decision="deny",
            policy="image",
            reason=msg,
            environment=environment
        )

        return admission_response(uid, False, msg)

    # 3) Security policy
    # dev  -> root user returns warning but does not deny
    # test -> root user is denied
    ok, msg, warnings = validate_security(spec, policy)
    if not ok:
        ADMISSION_DENIED.inc()
        ADMISSION_LATENCY.observe(time.time() - start_time)

        log_decision(
            level="warning",
            uid=uid,
            decision="DENY",
            policy="security",
            environment=environment,
            namespace=namespace,
            pod_name=pod_name,
            reason=msg,
            start_time=start_time
        )

        save_audit_log(
            namespace=namespace,
            pod_name=pod_name,
            image=image_text,
            decision="deny",
            policy="security",
            reason=msg,
            environment=environment
        )

        return admission_response(uid, False, msg)

    # 4) Resource policy
    # Resource requests and limits are mandatory in both dev and test.
    if policy.get("requireResources", True):
        ok, msg = validate_resources(spec)
        if not ok:
            ADMISSION_DENIED.inc()
            ADMISSION_LATENCY.observe(time.time() - start_time)

            log_decision(
                level="warning",
                uid=uid,
                decision="DENY",
                policy="resources",
                environment=environment,
                namespace=namespace,
                pod_name=pod_name,
                reason=msg,
                start_time=start_time
            )

            save_audit_log(
                namespace=namespace,
                pod_name=pod_name,
                image=image_text,
                decision="deny",
                policy="resources",
                reason=msg,
                environment=environment
            )

            return admission_response(uid, False, msg)

    # Allow
    ADMISSION_ALLOWED.inc()
    ADMISSION_LATENCY.observe(time.time() - start_time)

    if warnings:
        log_decision(
            level="info",
            uid=uid,
            decision="ALLOW_WITH_WARNING",
            policy="security",
            environment=environment,
            namespace=namespace,
            pod_name=pod_name,
            reason="Allowed with warnings",
            start_time=start_time,
            warnings=warnings
        )

        save_audit_log(
            namespace=namespace,
            pod_name=pod_name,
            image=image_text,
            decision="allow_with_warning",
            policy="security",
            reason="Allowed with warnings",
            environment=environment
        )

        return admission_response(uid, True, "Allowed with warnings", warnings)

    log_decision(
        level="info",
        uid=uid,
        decision="ALLOW",
        policy="all",
        environment=environment,
        namespace=namespace,
        pod_name=pod_name,
        reason="Allowed",
        start_time=start_time
    )

    save_audit_log(
        namespace=namespace,
        pod_name=pod_name,
        image=image_text,
        decision="allow",
        policy="all",
        reason="Allowed",
        environment=environment
    )

    return admission_response(uid, True, "Allowed")

# =====================================================
# HEALTH ENDPOINT
# =====================================================
@app.get(
    "/health",
    tags=["Health"],
    summary="Check webhook health",
    description="Returns basic health status of the admission webhook application."
)
async def health():
    return {
        "status": "healthy",
        "service": "pod-security-webhook"
    }


# =====================================================
# DATABASE HEALTH ENDPOINT
# =====================================================
@app.get(
    "/health/db",
    tags=["Health"],
    summary="Check PostgreSQL health",
    description="Checks whether the webhook can connect to the PostgreSQL audit database."
)
async def database_health():
    result = check_database_health()

    if result.get("status") == "unhealthy":
        return JSONResponse(
            status_code=500,
            content=result
        )

    return result

# =====================================================
# AUDIT SUMMARY ENDPOINT
# =====================================================
@app.get(
    "/audit/summary",
    tags=["Audit Analytics"],
    summary="Get admission audit summary",
    description="Returns aggregated admission decision statistics from PostgreSQL, including allow/deny counts, most denied policy, and most problematic namespace.",
    response_model=AuditSummaryResponse
)
async def audit_summary():
    summary = get_audit_summary()

    if "error" in summary:
        return JSONResponse(
            content={
                "status": "error",
                "message": summary["error"]
            },
            status_code=500
        )

    return summary

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="/tls/tls.key",
        ssl_certfile="/tls/tls.crt",
        access_log=False
    )