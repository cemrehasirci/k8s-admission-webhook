from fastapi import FastAPI, Request
import time
import os
import uvicorn
import ssl

from prometheus_client import Counter, Histogram, start_http_server

# ✅ Kubernetes API Client
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException

# =====================================================
# METRICS SERVER (Prometheus scrape)
# =====================================================
start_http_server(9091)

# =====================================================
# PROMETHEUS METRICS
# =====================================================
ADMISSION_REQUESTS = Counter(
    "admission_requests_total",
    "Total number of admission review requests"
)

ADMISSION_ALLOWED = Counter(
    "admission_requests_allowed_total",
    "Total number of allowed admission requests"
)

ADMISSION_DENIED = Counter(
    "admission_requests_denied_total",
    "Total number of denied admission requests"
)

DENY_PRIVILEGED = Counter(
    "admission_deny_privileged_total",
    "Denied due to privileged container"
)

DENY_ROOT = Counter(
    "admission_deny_root_user_total",
    "Denied due to runAsUser=0"
)

DENY_ESCALATION = Counter(
    "admission_deny_privilege_escalation_total",
    "Denied due to allowPrivilegeEscalation"
)

DENY_NON_ROOT = Counter(
    "admission_deny_non_root_total",
    "Denied due to runAsNonRoot not true"
)

# ✅ v3 storage deny metrics
DENY_HOSTPATH = Counter(
    "admission_deny_hostpath_total",
    "Denied due to hostPath volume"
)

DENY_NON_LONGHORN_PVC = Counter(
    "admission_deny_non_longhorn_pvc_total",
    "Denied due to PVC storageClass not longhorn"
)

DENY_PVC_LOOKUP_FAILED = Counter(
    "admission_deny_pvc_lookup_failed_total",
    "Denied because PVC could not be fetched from API"
)

ADMISSION_LATENCY = Histogram(
    "admission_request_duration_seconds",
    "Admission webhook request latency"
)

# =====================================================
# FASTAPI APP
# =====================================================
app = FastAPI()

# =====================================================
# K8S CLIENT INIT (in-cluster)
# =====================================================
# StorageClass name we enforce for v3:
ENFORCED_STORAGE_CLASS = os.getenv("ENFORCED_STORAGE_CLASS", "longhorn")

def init_k8s_client():
    """
    In-cluster config loads ServiceAccount token automatically.
    If you test locally, you can set USE_KUBECONFIG=true and it loads kubeconfig.
    """
    use_kubeconfig = os.getenv("USE_KUBECONFIG", "false").lower() == "true"

    if use_kubeconfig:
        k8s_config.load_kube_config()
    else:
        k8s_config.load_incluster_config()

    return k8s_client.CoreV1Api()

core_v1 = init_k8s_client()


# =====================================================
# v3 – STORAGE POLICY
# =====================================================
def validate_storage(pod: dict) -> tuple[bool, str]:
    spec = pod.get("spec", {})
    volumes = spec.get("volumes", [])
    namespace = pod.get("metadata", {}).get("namespace") or "default"

    # 1) hostPath deny
    for v in volumes:
        vname = v.get("name", "<noname>")
        if v.get("hostPath") is not None:
            DENY_HOSTPATH.inc()
            return False, f"hostPath volume not allowed: {vname}"

    # 2) PVC storageClass must be longhorn
    # Pod volumes can reference PVCs by name
    for v in volumes:
        pvc_ref = v.get("persistentVolumeClaim")
        if not pvc_ref:
            continue

        claim_name = pvc_ref.get("claimName")
        if not claim_name:
            DENY_PVC_LOOKUP_FAILED.inc()
            return False, "PVC reference missing claimName"

        try:
            pvc = core_v1.read_namespaced_persistent_volume_claim(
                name=claim_name,
                namespace=namespace
            )
        except ApiException as e:
            # If we cannot fetch PVC, fail closed (failurePolicy=Fail already)
            DENY_PVC_LOOKUP_FAILED.inc()
            return False, f"PVC lookup failed for '{claim_name}' in ns '{namespace}': {e.reason}"

        scn = pvc.spec.storage_class_name  # may be None
        if scn != ENFORCED_STORAGE_CLASS:
            DENY_NON_LONGHORN_PVC.inc()
            return False, (
                f"PVC '{claim_name}' storageClass must be '{ENFORCED_STORAGE_CLASS}', got '{scn}'"
            )

    return True, "Storage policy passed"


# =====================================================
# v2 – SECURITY POLICY (existing)
# =====================================================
def validate_security(spec: dict) -> tuple[bool, str]:
    pod_sc = spec.get("securityContext", {})
    containers = spec.get("containers", []) + spec.get("initContainers", [])

    for c in containers:
        name = c.get("name", "<noname>")
        sc = c.get("securityContext", {})

        # 1) privileged
        if sc.get("privileged") is True:
            DENY_PRIVILEGED.inc()
            return False, f"Privileged container not allowed: {name}"

        # 2) privilege escalation
        if sc.get("allowPrivilegeEscalation") is True:
            DENY_ESCALATION.inc()
            return False, f"Privilege escalation not allowed: {name}"

        # 3) runAsUser == 0
        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_user == 0:
            DENY_ROOT.inc()
            return False, f"Running as root is not allowed: {name}"

        # 4) runAsNonRoot zorunlu
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        if run_as_non_root is not True:
            DENY_NON_ROOT.inc()
            return False, f"runAsNonRoot must be true: {name}"

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

    # Pod değilse dokunma
    if req.get("kind", {}).get("kind") != "Pod":
        ADMISSION_ALLOWED.inc()
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, True, "Non-Pod resource allowed")

    pod = req.get("object", {})
    spec = pod.get("spec", {})

    # =============================
    # v3 – STORAGE POLICY
    # =============================
    ok, msg = validate_storage(pod)
    if not ok:
        ADMISSION_DENIED.inc()
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # =============================
    # v2 – SECURITY POLICY
    # =============================
    ok, msg = validate_security(spec)
    if not ok:
        ADMISSION_DENIED.inc()
        ADMISSION_LATENCY.observe(time.time() - start_time)
        return admission_response(uid, False, msg)

    # Allow
    ADMISSION_ALLOWED.inc()
    ADMISSION_LATENCY.observe(time.time() - start_time)
    return admission_response(uid, True, "Allowed")


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
