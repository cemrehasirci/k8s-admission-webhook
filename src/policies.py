import os
import yaml
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
WARN_ROOT = Counter("admission_warn_root_user_total", "Warned runAsUser=0")
DENY_ESCALATION = Counter("admission_deny_privilege_escalation_total", "Denied privilege escalation")
DENY_NON_ROOT = Counter("admission_deny_non_root_total", "Denied runAsNonRoot violation")

DENY_LATEST_IMAGE = Counter("admission_deny_latest_image_total", "Denied latest or tagless image")

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
# ENVIRONMENT POLICY CONFIG
# =====================================================
def get_namespace_environment(
    core_v1: k8s_client.CoreV1Api,
    namespace: str,
    default_environment: str = "dev"
) -> str:
    """
    Reads the namespace label 'environment'.
    Example:
    - environment=dev
    - environment=test

    If the label is missing or namespace lookup fails, default_environment is used.
    """
    try:
        ns = core_v1.read_namespace(name=namespace)
        labels = ns.metadata.labels or {}
        return labels.get("environment", default_environment)
    except ApiException:
        return default_environment


def load_policy_for_environment(
    core_v1: k8s_client.CoreV1Api,
    configmap_name: str,
    configmap_namespace: str,
    environment: str
) -> dict:
    """
    Loads environment-based policy from ConfigMap.
    Expected ConfigMap keys:
    - dev.yaml
    - test.yaml
    """
    try:
        cm = core_v1.read_namespaced_config_map(
            name=configmap_name,
            namespace=configmap_namespace
        )

        data = cm.data or {}
        policy_key = f"{environment}.yaml"
        raw_policy = data.get(policy_key)

        if not raw_policy:
            raise ValueError(f"Policy key not found in ConfigMap: {policy_key}")

        return yaml.safe_load(raw_policy) or {}

    except Exception:
        # Fail-safe default policy.
        # This prevents the webhook from becoming too permissive if ConfigMap cannot be read.
        return {
            "allowLatestTag": False,
            "blockPrivileged": True,
            "blockRootUser": True,
            "warnRootUser": False,
            "requireResources": True
        }


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
# IMAGE POLICY
# =====================================================
def _is_latest_or_tagless_image(image: str) -> bool:
    """
    Detects latest or tagless images.
    Examples:
    - nginx             -> tagless, treated as latest
    - nginx:latest      -> latest
    - nginx:1.25        -> valid
    - repo/nginx:1.25   -> valid
    """
    if not image:
        return True

    image_without_digest = image.split("@")[0]
    last_part = image_without_digest.split("/")[-1]

    if ":" not in last_part:
        return True

    tag = last_part.split(":")[-1]
    return tag == "latest"


def validate_images(spec: dict, policy: dict) -> Tuple[bool, str]:
    containers = (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])

    allow_latest = policy.get("allowLatestTag", False)

    if allow_latest:
        return True, "Image policy passed"

    for c in containers:
        name = c.get("name", "<noname>")
        image = c.get("image", "")

        if _is_latest_or_tagless_image(image):
            DENY_LATEST_IMAGE.inc()
            return False, f"Latest or tagless image not allowed: {name} ({image})"

    return True, "Image policy passed"


# =====================================================
# SECURITY POLICY
# =====================================================
def validate_security(spec: dict, policy: dict) -> Tuple[bool, str, list[str]]:
    pod_sc = spec.get("securityContext", {}) or {}
    containers = (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])

    warnings = []

    for c in containers:
        name = c.get("name", "<noname>")
        sc = c.get("securityContext", {}) or {}

        if policy.get("blockPrivileged", True) and sc.get("privileged") is True:
            DENY_PRIVILEGED.inc()
            return False, f"Privileged container: {name}", warnings

        if sc.get("allowPrivilegeEscalation") is True:
            DENY_ESCALATION.inc()
            return False, f"Privilege escalation: {name}", warnings

        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_user == 0:
            if policy.get("blockRootUser", True):
                DENY_ROOT.inc()
                return False, f"Running as root: {name}", warnings

            if policy.get("warnRootUser", False):
                WARN_ROOT.inc()
                warnings.append(f"Container '{name}' is running as root user")

        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))

        if policy.get("blockRootUser", True) and run_as_non_root is not True:
            DENY_NON_ROOT.inc()
            return False, f"runAsNonRoot not true: {name}", warnings

    return True, "Security policy passed", warnings


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