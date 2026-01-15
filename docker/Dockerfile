FROM python:3.10-slim

WORKDIR /app

# (Opsiyonel ama iyi pratik) requirements ile kur
COPY src/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Source kodları kopyala
COPY src/ /app/src/

# Admission webhook (HTTPS)
EXPOSE 8443
# Metrics
EXPOSE 9091

# src içinden app:app import edebilmek için --app-dir kullan
CMD ["uvicorn","--app-dir","src","app:app","--host","0.0.0.0","--port","8443","--ssl-keyfile","/tls/tls.key","--ssl-certfile","/tls/tls.crt"]