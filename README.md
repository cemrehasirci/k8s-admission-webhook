# Kubernetes Admission Webhook

Kubernetes üzerinde çalışan Pod’ların güvenlik ve kaynak politikalarına uygunluğunu kontrol eden bir **Validating Admission Webhook** projesidir.

Webhook, Pod oluşturma isteklerini değerlendirerek belirlenen kurallara göre **ALLOW / DENY** kararı verir.

Admission kararları aşağıdaki yapılar ile gözlemlenebilir hale getirilmiştir:

- Prometheus metrikleri
- Grafana dashboard’ları
- Structured logging
- PostgreSQL tabanlı audit logging
- Swagger/OpenAPI dokümantasyonu

---

# Features

## Security Policies
- `privileged=true` → DENY
- `allowPrivilegeEscalation=true` → DENY
- `runAsUser=0` → Ortama göre WARNING / DENY
- `runAsNonRoot=true` zorunlu

## Storage Policies
- `hostPath` volume → DENY
- Sadece izin verilen `storageClass` kullanımı → ALLOW

## Resource Policies
Her container için aşağıdaki resource alanları zorunludur:

- CPU requests/limits
- Memory requests/limits

Eksik olması durumunda → DENY

---

## Environment-Based Policies

Webhook, namespace label’larına göre farklı policy davranışları uygular.


| Policy | Dev Environment | Test Environment |
|---|---|---|
| latest image | ALLOW | DENY |
| root user | WARNING | DENY |
| privileged | DENY | DENY |
| resource limits | REQUIRED | REQUIRED |

---

# Observability

Webhook aşağıdaki gözlemlenebilirlik özelliklerini sağlar:

- Prometheus metrics
- Grafana dashboards
- Structured decision logging
- Admission latency tracking
- PostgreSQL audit analytics
- Health check endpointleri
- Swagger/OpenAPI desteği

---

# Stateful Audit Logging

Tüm admission kararları PostgreSQL üzerinde kalıcı olarak saklanmaktadır.

Saklanan bilgiler:

- namespace
- pod name
- image
- decision
- policy
- reason
- environment
- timestamp

Bu yapı sayesinde:

- En çok reddedilen policy analizi
- Namespace bazlı güvenlik analizi
- Admission geçmişi incelemesi
- Audit analytics raporlaması

gerçekleştirilebilir.

## Örnek log:

```text
2026-05-13 18:04:55,100 WARNING EVENT=admission_review DECISION=DENY POLICY=image NAMESPACE=test POD=test-latest-deny REASON="Latest or tagless image not allowed: nginx (nginx:latest)" WARNINGS="-"
```

## Örnek Audit Kaydı

```text
id | namespace | pod_name              | image        | decision | policy   | reason
---|-----------|----------------------|--------------|----------|-----------|------------------------------
2  | test      | test-privileged-deny | nginx:1.25   | deny     | security | Privileged container: nginx
```

---

# API Endpointleri

| Endpoint | Açıklama |
|---|---|
| `/audit/summary` | Admission audit özet bilgilerini döndürür |
| `/health` | Webhook sağlık durumunu döndürür |
| `/health/db` | PostgreSQL bağlantı durumunu kontrol eder |

Swagger UI:

```text
https://localhost:8443/docs
```