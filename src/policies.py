import os
from typing import Tuple

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes.client.rest import ApiException

from prometheus_client import Counter

# =====================================================
# PROMETHEUS METRICS (POLICY-SPECIFIC)
# =====================================================
DENY_PRIVILEGED = Counter("admission_deny_privileged_total", "Denied privileged container")
DENY_ROOT = Counter("admission_deny_root_user_total", "Denied runAsUser=0")
DENY_ESCALATION = Counter("admission_deny_privilege_escalation_total", "Denied privilege escalation")
DENY_NON_ROOT = Counter("admission_deny_non_root_total", "Denied runAsNonRoot violation")

DENY_HOSTPATH = Counter("admission_deny_hostpath_total", "Denied hostPath volume")
DENY_NON_LONGHORN_PVC = Counter("admission_deny_non_longhorn_pvc_total", "Denied non-longhorn PVC")
DENY_PVC_LOOKUP_FAILED = Counter("admission_deny_pvc_lookup_failed_total", "Denied PVC lookup failure")

# v4.0 Resource Enforcement metrics
DENY_MISSING_REQUESTS_CPU = Counter(
    "admission_deny_missing_requests_cpu_total",
    "Denied missing resources.requests.cpu"
)
DENY_MISSING_REQUESTS_MEMORY = Counter(
    "admission_deny_missing_requests_memory_total",
    "Denied missing resources.requests.memory"
)
DENY_MISSING_LIMITS_CPU = Counter(
    "admission_deny_missing_limits_cpu_total",
    "Denied missing resources.limits.cpu"
)
DENY_MISSING_LIMITS_MEMORY = Counter(
    "admission_deny_missing_limits_memory_total",
    "Denied missing resources.limits.memory"
)

# =====================================================
# K8S CLIENT INIT
# =====================================================
def init_k8s_client() -> k8s_client.CoreV1Api:
    """
    Initializes Kubernetes CoreV1Api client.
    - USE_KUBECONFIG=true -> uses local kubeconfig
    - otherwise -> uses in-cluster config
    """
    if os.getenv("USE_KUBECONFIG", "false").lower() == "true":
        k8s_config.load_kube_config()
    else:
        k8s_config.load_incluster_config()
    return k8s_client.CoreV1Api()


# =====================================================
# STORAGE POLICY
# =====================================================
def validate_storage(
    pod: dict,
    core_v1: k8s_client.CoreV1Api,
    enforced_storage_class: str
) -> Tuple[bool, str]:
    spec = pod.get("spec", {})
    volumes = spec.get("volumes", [])
    namespace = pod.get("metadata", {}).get("namespace", "default")

    # 1) hostPath deny
    for v in volumes:
        if v.get("hostPath") is not None:
            DENY_HOSTPATH.inc()
            return False, "hostPath volume not allowed"

    # 2) PVC storageClass enforcement
    for v in volumes:
        pvc_ref = v.get("persistentVolumeClaim")
        if not pvc_ref:
            continue

        claim_name = pvc_ref.get("claimName")
        if not claim_name:
            DENY_PVC_LOOKUP_FAILED.inc()
            return False, "PVC claimName missing"

        try:
            pvc = core_v1.read_namespaced_persistent_volume_claim(
                name=claim_name,
                namespace=namespace
            )
        except ApiException as e:
            DENY_PVC_LOOKUP_FAILED.inc()
            return False, f"PVC lookup failed: {e.reason}"

        scn = pvc.spec.storage_class_name
        if scn != enforced_storage_class:
            DENY_NON_LONGHORN_PVC.inc()
            return False, f"PVC storageClass '{scn}' not allowed"

    return True, "Storage policy passed"


# =====================================================
# SECURITY POLICY
# =====================================================
def validate_security(spec: dict) -> Tuple[bool, str]:
    pod_sc = spec.get("securityContext", {}) or {}
    containers = (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])

    for c in containers:
        name = c.get("name", "<noname>")
        sc = c.get("securityContext", {}) or {}

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
# RESOURCE POLICY (v4.0)
# =====================================================
def _is_missing(val) -> bool:
    if val is None:
        return True
    if isinstance(val, str) and val.strip() == "":
        return True
    return False


def validate_resources(spec: dict) -> Tuple[bool, str]:
    containers = (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])

    for c in containers:
        name = c.get("name", "<noname>")
        resources = c.get("resources", {}) or {}
        requests = (resources.get("requests", {}) or {})
        limits = (resources.get("limits", {}) or {})

        req_cpu = requests.get("cpu")
        req_mem = requests.get("memory")
        lim_cpu = limits.get("cpu")
        lim_mem = limits.get("memory")

        if _is_missing(req_cpu):
            DENY_MISSING_REQUESTS_CPU.inc()
            return False, f"Missing resources.requests.cpu: {name}"

        if _is_missing(req_mem):
            DENY_MISSING_REQUESTS_MEMORY.inc()
            return False, f"Missing resources.requests.memory: {name}"

        if _is_missing(lim_cpu):
            DENY_MISSING_LIMITS_CPU.inc()
            return False, f"Missing resources.limits.cpu: {name}"

        if _is_missing(lim_mem):
            DENY_MISSING_LIMITS_MEMORY.inc()
            return False, f"Missing resources.limits.memory: {name}"

    return True, "Resource policy passed"