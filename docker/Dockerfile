FROM python:3.10-slim

WORKDIR /app

COPY src/app.py .

RUN pip install fastapi uvicorn

# Webhook 8443 üzerinden çalışacak
EXPOSE 8443

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8443"]