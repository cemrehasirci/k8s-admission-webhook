from fastapi import FastAPI, Request
import time
import os
import uvicorn
import logging

from prometheus_client import Counter, Histogram, start_http_server

# Kubernetes API Client
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException

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
start_http_server(9091)

# =====================================================
# PROMETHEUS METRICS
# =====================================================
ADMISSION_REQUESTS = Counter("admission_requests_total", "Total admission requests")
ADMISSION_ALLOWED = Counter("admission_requests_allowed_total", "Allowed admission requests")
ADMISSION_DENIED = Counter("admission_requests_denied_total", "Denied admission requests")

DENY_PRIVILEGED = Counter("admission_deny_privileged_total", "Denied privileged container")
DENY_ROOT = Counter("admission_deny_root_user_total", "Denied runAsUser=0")
DENY_ESCALATION = Counter("admission_deny_privilege_escalation_total", "Denied privilege escalation")
DENY_NON_ROOT = Counter("admission_deny_non_root_total", "Denied runAsNonRoot violation")

DENY_HOSTPATH = Counter("admission_deny_hostpath_total", "Denied hostPath volume")
DENY_NON_LONGHORN_PVC = Counter("admission_deny_non_longhorn_pvc_total", "Denied non-longhorn PVC")
DENY_PVC_LOOKUP_FAILED = Counter("admission_deny_pvc_lookup_failed_total", "Denied PVC lookup failure")

ADMISSION_LATENCY = Histogram(
    "admission_request_duration_seconds",
    "Admission webhook latency"
)

# =====================================================
# FASTAPI APP
# =====================================================
app = FastAPI()

# =====================================================
# K8S CLIENT INIT
# =====================================================
ENFORCED_STORAGE_CLASS = os.getenv("ENFORCED_STORAGE_CLASS", "longhorn")

def init_k8s_client():
    if os.getenv("USE_KUBECONFIG", "false").lower() == "true":
        k8s_config.load_kube_config()
    else:
        k8s_config.load_incluster_config()
    return k8s_client.CoreV1Api()

core_v1 = init_k8s_client()

# =====================================================
# STORAGE POLICY
# =====================================================
def validate_storage(pod: dict) -> tuple[bool, str]:
    spec = pod.get("spec", {})
    volumes = spec.get("volumes", [])
    namespace = pod.get("metadata", {}).get("namespace", "default")

    for v in volumes:
        if v.get("hostPath") is not None:
            DENY_HOSTPATH.inc()
            return False, "hostPath volume not allowed"

    for v in volumes:
        pvc_ref = v.get("persistentVolumeClaim")
        if not pvc_ref:
            continue

        claim_name = pvc_ref.get("claimName")
        try:
            pvc = core_v1.read_namespaced_persistent_volume_claim(
                name=claim_name,
                namespace=namespace
            )
        except ApiException as e:
            DENY_PVC_LOOKUP_FAILED.inc()
            return False, f"PVC lookup failed: {e.reason}"

        scn = pvc.spec.storage_class_name
        if scn != ENFORCED_STORAGE_CLASS:
            DENY_NON_LONGHORN_PVC.inc()
            return False, f"PVC storageClass '{scn}' not allowed"

    return True, "Storage policy passed"

# =====================================================
# SECURITY POLICY
# =====================================================
def validate_security(spec: dict) -> tuple[bool, str]:
    pod_sc = spec.get("securityContext", {})
    containers = spec.get("containers", []) + spec.get("initContainers", [])

    for c in containers:
        name = c.get("name", "<noname>")
        sc = c.get("securityContext", {})

        if sc.get("privileged") is True:
            DENY_PRIVILEGED.inc()
            return False, f"Privileged container: {name}"

        if sc.get("allowPrivilegeEscalation") is True:
            DENY_ESCALATION.inc()
            return False, f"Privilege escalation: {name}"

        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_user == 0:
            DENY_ROOT.inc()
            return False, f"Running as root: {name}"

        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        if run_as_non_root is not True:
            DENY_NON_ROOT.inc()
            return False, f"runAsNonRoot not true: {name}"

    return True, "Security policy passed"

# =====================================================
# WEBHOOK ENDPOINT
# =====================================================
@app.post("/validate")
async def validate(request: Request):
    start_time = time.time()
    body = await request.json()
    ADMISSION_REQUESTS.inc()

    req = body.get("request", {})
    uid = req.get("uid")

    if req.get("kind", {}).get("kind") != "Pod":
        ADMISSION_ALLOWED.inc()
        logger.info("DECISION=ALLOW POLICY=non-pod RESOURCE=non-pod")
        return admission_response(uid, True, "Non-Pod resource allowed")

    pod = req.get("object", {})
    spec = pod.get("spec", {})
    meta = pod.get("metadata", {})
    pod_name = meta.get("name", "unknown")
    namespace = meta.get("namespace", "default")

    ok, msg = validate_storage(pod)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=storage REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    ok, msg = validate_security(spec)
    if not ok:
        ADMISSION_DENIED.inc()
        logger.warning(
            f"DECISION=DENY POLICY=security REASON='{msg}' POD={pod_name} NAMESPACE={namespace}"
        )
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    ADMISSION_ALLOWED.inc()
    logger.info(
        f"DECISION=ALLOW POD={pod_name} NAMESPACE={namespace}"
    )
    ADMISSION_LATENCY.observe(time.time() - start_time)
    return admission_response(uid, True, "Allowed")

# =====================================================
# ADMISSION RESPONSE
# =====================================================
def admission_response(uid, allowed, message):
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

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="/tls/tls.key",
        ssl_certfile="/tls/tls.crt"
    )