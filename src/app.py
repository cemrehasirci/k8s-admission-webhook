from fastapi import FastAPI, Request
import time
import uvicorn

from prometheus_client import (
    Counter,
    Histogram,
    start_http_server
)

# =====================================================
# METRICS SERVER (9091)
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

PRIVILEGED_DENIED = Counter(
    "admission_privileged_denied_total",
    "Number of pods denied due to privileged containers"
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
    uid = body["request"]["uid"]
    pod = body["request"]["object"]

    ADMISSION_REQUESTS.inc()

    # Varsayılan: izin ver
    allow = True
    message = "Allowed"

    # Pod içindeki container'ları kontrol et
    containers = pod.get("spec", {}).get("containers", [])
    for c in containers:
        sec = c.get("securityContext", {})
        if sec.get("privileged") is True:
            allow = False
            message = f"Privileged containers are not allowed: {c.get('name')}"
            PRIVILEGED_DENIED.inc()
            break

    # Karar metrikleri
    if allow:
        ADMISSION_ALLOWED.inc()
    else:
        ADMISSION_DENIED.inc()

    ADMISSION_LATENCY.observe(time.time() - start_time)

    # AdmissionReview cevabı
    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allow,
            "status": {
                "message": message
            }
        }
    }

    print("AdmissionReview decision:", response)
    return response


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="/tls/tls.key",
        ssl_certfile="/tls/tls.crt"
    )
