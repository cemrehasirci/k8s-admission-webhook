# Kubernetes Admission Webhook

Kubernetes üzerinde çalışan Pod’ların güvenlik ve kaynak politikalarına uygunluğunu kontrol eden bir **Validating Admission Webhook** projesidir.

Webhook, Pod oluşturma isteklerini değerlendirerek belirlenen kurallara göre **ALLOW / DENY** kararı verir.

Admission kararları aşağıdaki yapılar ile gözlemlenebilir hale getirilmiştir:

- Prometheus Metrics
- Grafana Dashboards
- Structured Logging
- PostgreSQL Audit Logging
- Swagger/OpenAPI Documentation

---

## Architecture

![Architecture](assets/architecture.png)

---

# Policy Matrix

Webhook namespace label'larına göre farklı policy davranışları uygular.

| Policy | Dev | Test |
|----------|----------|----------|
| Latest Image (`nginx:latest`) | ✅ ALLOW | ❌ DENY |
| Root User (`runAsUser=0`) | ⚠️ WARNING | ❌ DENY |
| Privileged Container | ❌ DENY | ❌ DENY |
| allowPrivilegeEscalation=true | ❌ DENY | ❌ DENY |
| runAsNonRoot=true | ✅ REQUIRED | ✅ REQUIRED |
| hostPath Volume | ❌ DENY | ❌ DENY |
| Approved StorageClass | ✅ ALLOW | ✅ ALLOW |
| CPU Requests | ✅ REQUIRED | ✅ REQUIRED |
| Memory Requests | ✅ REQUIRED | ✅ REQUIRED |
| CPU Limits | ✅ REQUIRED | ✅ REQUIRED |
| Memory Limits | ✅ REQUIRED | ✅ REQUIRED |

---

# Storage Policy

Webhook, Pod içerisinde kullanılan storage yapılarını kontrol eder.

| Storage Usage | Result | Description |
|----------|----------|----------|
| hostPath Volume | ❌ DENY | Host dosya sistemine doğrudan erişim riski oluşturduğu için reddedilir. |
| Approved StorageClass | ✅ ALLOW | İzin verilen StorageClass değerleri kabul edilir. |
| Unapproved StorageClass | ❌ DENY | İzin verilen listede olmayan StorageClass değerleri reddedilir. |

v6.3 ile birlikte webhook birden fazla StorageClass kabul edecek şekilde güncellenmiştir.

```yaml
ALLOWED_STORAGE_CLASSES=longhorn,standard
```

---

# Observability

| Feature | Description |
|----------|----------|
| Prometheus Metrics | Admission request, allow, deny ve latency metrikleri |
| Grafana Dashboards | Admission davranışlarının görselleştirilmesi |
| Structured Logging | Kararların standart formatta loglanması |
| PostgreSQL Audit Logging | Admission kararlarının kalıcı olarak saklanması |
| Audit Analytics API | Audit verilerinin özetlenmesi |
| Health Endpoints | Uygulama ve veritabanı sağlık kontrolleri |
| Swagger/OpenAPI | API dokümantasyonu |

---

# Stateful Audit Logging

Webhook tarafından verilen tüm admission kararları PostgreSQL üzerinde saklanmaktadır.

## Saklanan Alanlar

| Field |
|----------|
| namespace |
| pod_name |
| image |
| decision |
| policy |
| reason |
| environment |
| timestamp |

## Sağlanan Analizler

- En çok reddedilen policy
- Problemli namespace analizi
- Admission geçmişi incelemesi
- Güvenlik ve uyumluluk raporlaması

### Örnek Decision Log

```text
2026-05-13 18:04:55,100 WARNING EVENT=admission_review DECISION=DENY POLICY=image NAMESPACE=test POD=test-latest-deny REASON="Latest or tagless image not allowed: nginx (nginx:latest)" WARNINGS="-"
```

### Örnek Audit Kaydı

```text
id | namespace | pod_name              | image        | decision | policy   | reason
---|-----------|----------------------|--------------|----------|----------|------------------------------
2  | test      | test-privileged-deny | nginx:1.25   | deny     | security | Privileged container: nginx
```

---

# API Endpoints

| Endpoint | Description |
|----------|----------|
| `/audit/summary` | Audit istatistiklerini döndürür |
| `/health` | Webhook sağlık durumunu döndürür |
| `/health/db` | PostgreSQL bağlantı durumunu kontrol eder |

---

# Swagger UI

```text
https://localhost:8443/docs
```

---

# Technology Stack

| Category | Technology |
|----------|----------|
| Language | Python |
| Framework | FastAPI |
| Containerization | Docker |
| Orchestration | Kubernetes |
| Local Cluster | Minikube |
| Monitoring | Prometheus |
| Visualization | Grafana |
| Database | PostgreSQL |
| API Documentation | Swagger / OpenAPI |