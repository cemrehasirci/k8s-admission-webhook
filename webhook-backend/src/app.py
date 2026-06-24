import os
import time
import logging
import uvicorn

from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Optional

from prometheus_client import Counter, Histogram, start_http_server

from audit_logger import save_audit_log

from audit_summary import get_audit_summary, check_database_health, get_dashboard_stats
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

logging.Formatter.converter = time.localtime

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

ADMISSION_POD_ALLOWED = Counter(
    "admission_pod_allowed_total",
    "Allowed Pod admission requests with pod details",
    ["namespace", "pod_name", "environment", "image"]
)

ADMISSION_POD_DENIED = Counter(
    "admission_pod_denied_total",
    "Denied Pod admission requests with pod details",
    ["namespace", "pod_name", "environment", "policy", "reason", "image"]
)

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
        ADMISSION_POD_DENIED.labels(
            namespace=namespace,
            pod_name=pod_name,
            environment=environment,
            policy="storage",
            reason=msg,
            image=image_text
        ).inc()
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
        ADMISSION_POD_DENIED.labels(
            namespace=namespace,
            pod_name=pod_name,
            environment=environment,
            policy="image",
            reason=msg,
            image=image_text
        ).inc()
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
        ADMISSION_POD_DENIED.labels(
            namespace=namespace,
            pod_name=pod_name,
            environment=environment,
            policy="security",
            reason=msg,
            image=image_text
        ).inc()
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
            ADMISSION_POD_DENIED.labels(
                namespace=namespace,
                pod_name=pod_name,
                environment=environment,
                policy="resources",
                reason=msg,
                image=image_text
            ).inc()
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
    ADMISSION_POD_ALLOWED.labels(
        namespace=namespace,
        pod_name=pod_name,
        environment=environment,
        image=image_text
    ).inc()

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

# =====================================================
# UI API ENDPOINTS
# =====================================================

@app.get("/api/namespaces", tags=["UI API"])
async def get_namespaces():
    try:
        res = await run_in_threadpool(core_v1.list_namespace)
        namespaces = [ns.metadata.name for ns in res.items]
        return {"namespaces": namespaces}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/dashboard/stats", tags=["UI API"])
async def dashboard_stats():
    stats = get_dashboard_stats()
    if "error" in stats:
        return JSONResponse(status_code=500, content={"error": stats["error"]})
    return stats


@app.get("/api/pods", tags=["UI API"])
async def get_pods():
    try:
        res = await run_in_threadpool(core_v1.list_pod_for_all_namespaces)
        pods = []
        for p in res.items:
            exact_status = p.status.phase or 'Unknown'
            if p.status.container_statuses:
                for c in p.status.container_statuses:
                    if c.state.waiting and c.state.waiting.reason:
                        exact_status = c.state.waiting.reason
                        break
                    elif c.state.terminated and c.state.terminated.reason:
                        exact_status = c.state.terminated.reason
                        break
            
            pods.append({
                "name": p.metadata.name or 'Unknown',
                "namespace": p.metadata.namespace or 'Unknown',
                "status": exact_status,
                "startTime": p.status.start_time.strftime("%Y-%m-%d %H:%M:%S") if p.status.start_time else 'N/A'
            })
        return {"pods": pods}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.delete("/api/pods", tags=["UI API"])
async def delete_pod(name: str, namespace: str):
    if not name or not namespace:
        return JSONResponse(status_code=400, content={"error": "Name ve namespace gereklidir."})
    try:
        await run_in_threadpool(core_v1.delete_namespaced_pod, name=name, namespace=namespace)
        return {"success": True, "message": f"Pod {name} başarıyla silindi."}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/logs", tags=["UI API"])
async def get_logs():
    try:
        pods = await run_in_threadpool(core_v1.list_namespaced_pod, namespace="webhook-system")
        webhook_pod = None
        for p in pods.items:
            if p.metadata.name and p.metadata.name.startswith("pod-security-webhook-") and p.status.phase == "Running" and not p.metadata.deletion_timestamp:
                webhook_pod = p
                break
        
        if not webhook_pod:
            return {"logs": "Webhook pod bulunamadı. Lütfen webhook-system namespace'ini ve pod isimlerini kontrol edin."}
        
        logs = await run_in_threadpool(
            core_v1.read_namespaced_pod_log,
            name=webhook_pod.metadata.name,
            namespace="webhook-system",
            container="webhook",
            tail_lines=1000
        )
            
        return {"logs": logs}
    except Exception as e:
        return {"logs": f"Loglar alınırken hata oluştu: {str(e)}"}

@app.post("/api/pod", tags=["UI API"])
async def create_pod(request: Request):
    try:
        body = await request.json()
        pod_name = f"test-pod-{int(time.time())}"
        
        image = body.get("image")
        if image == "unprivileged":
            image = "nginxinc/nginx-unprivileged:alpine"
        elif image == "latest":
            image = "nginx:latest"
        elif image == "alpine":
            image = "nginx:alpine"
            
        containers_spec = {
            "name": "test-container",
            "image": image,
            "securityContext": {},
            "volumeMounts": [],
            "env": []
        }
        
        # Kubernetes API'sinin çelişkileri (privileged=True & allowPrivilegeEscalation=False) 
        # yakalayabilmesi için alanları gizlemek yerine açıkça True/False olarak gönderiyoruz
        if "privileged" in body:
            containers_spec["securityContext"]["privileged"] = bool(body.get("privileged"))
        if "allowPrivilegeEscalation" in body:
            containers_spec["securityContext"]["allowPrivilegeEscalation"] = bool(body.get("allowPrivilegeEscalation"))
            
        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name,
                "namespace": body.get("namespace", "default"),
                "labels": {
                    "app": "webhook-test"
                },
                "annotations": {}
            },
            "spec": {
                "securityContext": {},
                "containers": [containers_spec],
                "volumes": []
            }
        }
        
        if body.get("runAsNonRoot"):
            pod_manifest["spec"]["securityContext"]["runAsNonRoot"] = True
            
        if body.get("runAsRoot"):
            pod_manifest["spec"]["securityContext"]["runAsUser"] = 0
            
        if body.get("vaultAnnotations"):
            pod_manifest["metadata"]["annotations"]["vault.hashicorp.com/agent-inject"] = "true"
            pod_manifest["metadata"]["annotations"]["vault.hashicorp.com/role"] = "app-role"
            
        volume_type = body.get("volumeType")
        if volume_type == "hostPath":
            pod_manifest["spec"]["volumes"].append({
                "name": "test-vol",
                "hostPath": {"path": "/tmp/test"}
            })
            containers_spec["volumeMounts"].append({
                "name": "test-vol",
                "mountPath": "/data"
            })
        elif volume_type == "emptyDir":
            pod_manifest["spec"]["volumes"].append({
                "name": "test-vol",
                "emptyDir": {}
            })
            containers_spec["volumeMounts"].append({
                "name": "test-vol",
                "mountPath": "/data"
            })
        elif volume_type == "pvc":
            pod_manifest["spec"]["volumes"].append({
                "name": "test-vol",
                "persistentVolumeClaim": {"claimName": body.get("pvcName", "test-pvc")}
            })
            containers_spec["volumeMounts"].append({
                "name": "test-vol",
                "mountPath": "/data"
            })
            
        if body.get("useNativeSecret"):
            containers_spec["env"].append({
                "name": "SECRET_KEY",
                "valueFrom": {
                    "secretKeyRef": {
                        "name": "my-secret",
                        "key": "password"
                    }
                }
            })
            
        if body.get("includeResources"):
            containers_spec["resources"] = {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": "200m", "memory": "256Mi"}
            }
            
        if not containers_spec["volumeMounts"]:
            del containers_spec["volumeMounts"]
        if not containers_spec["env"]:
            del containers_spec["env"]
        if not pod_manifest["spec"]["volumes"]:
            del pod_manifest["spec"]["volumes"]
        if not pod_manifest["metadata"]["annotations"]:
            del pod_manifest["metadata"]["annotations"]
            
        try:
            res = await run_in_threadpool(
                core_v1.create_namespaced_pod,
                namespace=pod_manifest["metadata"]["namespace"],
                body=pod_manifest
            )
            return {"success": True, "message": "Pod başarıyla oluşturuldu (ALLOW)", "pod": res.to_dict()}
        except Exception as err:
            import json
            try:
                err_body = json.loads(err.body)
                msg = err_body.get("message", str(err))
                reason = err_body.get("reason", "DENY")
            except:
                msg = str(err)
                reason = "DENY"
            return JSONResponse(status_code=400, content={"success": False, "message": msg, "reason": reason})
            
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# =====================================================
# NEXT.JS UI STATIC FILE SERVING
# =====================================================

@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    static_path = os.path.join(os.path.dirname(__file__), "static")
    path = request.url.path
    
    html_file = os.path.join(static_path, path.lstrip('/') + '.html')
    if os.path.isfile(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
            
    index_file = os.path.join(static_path, "index.html")
    if os.path.isfile(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    
    return JSONResponse(status_code=404, content={"detail": "Not Found"})

static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_path):
    app.mount("/", StaticFiles(directory=static_path, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="/tls/tls.key",
        ssl_certfile="/tls/tls.crt",
        access_log=False
    )