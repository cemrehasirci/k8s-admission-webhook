from fastapi import FastAPI, Request
import time
import uvicorn

from prometheus_client import Counter, Histogram, start_http_server

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

ADMISSION_LATENCY = Histogram(
    "admission_request_duration_seconds",
    "Admission webhook request latency"
)

# =====================================================
# FASTAPI APP
# =====================================================
app = FastAPI()

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
    pod_sc = spec.get("securityContext", {})

    containers = spec.get("containers", []) + spec.get("initContainers", [])

    allow = True
    message = "Allowed"

    for c in containers:
        name = c.get("name", "<noname>")
        sc = c.get("securityContext", {})

        # 1) privileged
        if sc.get("privileged") is True:
            DENY_PRIVILEGED.inc()
            allow = False
            message = f"Privileged container not allowed: {name}"
            break

        # 2) privilege escalation
        if sc.get("allowPrivilegeEscalation") is True:
            DENY_ESCALATION.inc()
            allow = False
            message = f"Privilege escalation not allowed: {name}"
            break

        # 3) runAsUser == 0
        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_user == 0:
            DENY_ROOT.inc()
            allow = False
            message = f"Running as root is not allowed: {name}"
            break

        # 4) runAsNonRoot zorunlu
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        if run_as_non_root is not True:
            DENY_NON_ROOT.inc()
            allow = False
            message = f"runAsNonRoot must be true: {name}"
            break

    if allow:
        ADMISSION_ALLOWED.inc()
    else:
        ADMISSION_DENIED.inc()

    ADMISSION_LATENCY.observe(time.time() - start_time)
    return admission_response(uid, allow, message)


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
