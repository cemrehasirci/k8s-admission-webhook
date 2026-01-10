FROM python:3.10-slim

WORKDIR /app

COPY src/app.py .

RUN pip install fastapi uvicorn prometheus_client

# Admission webhook (HTTPS)
EXPOSE 8443
# Metrics
EXPOSE 9091

CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8443","--ssl-keyfile","/tls/tls.key","--ssl-certfile","/tls/tls.crt"]