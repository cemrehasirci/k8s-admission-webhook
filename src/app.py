from fastapi import FastAPI, Request
import time

from prometheus_client import Counter, Histogram, start_http_server

# === METRICS SERVER BAŞLAT (EN KRİTİK SATIR) ===
start_http_server(9091)

app = FastAPI()

# === METRICS ===
ADMISSION_REQUESTS = Counter(
    "admission_requests_total",
    "Total number of admission review requests"
)

ADMISSION_LATENCY = Histogram(
    "admission_request_duration_seconds",
    "Latency of admission webhook"
)

@app.post("/validate")
async def validate(request: Request):
    start_time = time.time()

    body = await request.json()
    uid = body["request"]["uid"]

    ADMISSION_REQUESTS.inc()

    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": True,
            "status": {
                "message": "Webhook test: allowed = true"
            }
        }
    }

    ADMISSION_LATENCY.observe(time.time() - start_time)
    return response
