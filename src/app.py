from fastapi import FastAPI, Request
import uvicorn

app = FastAPI()

@app.post("/validate")
async def validate(request: Request):
    body = await request.json()

    uid = body["request"]["uid"]

    # Şimdilik her isteği kabul ediyoruz
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

    print("AdmissionReview request received:", body)

    return response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8443)