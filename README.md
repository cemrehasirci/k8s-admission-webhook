# Kubernetes Admission Webhook

Kubernetes üzerinde çalışan Pod’ların güvenlik ve kaynak politikalarına uygunluğunu kontrol eden bir **Validating Admission Webhook** projesidir.

Webhook, Pod oluşturma isteklerini değerlendirerek belirlenen kurallara göre **ALLOW / DENY** kararı verir. Ayrıca admission kararları Prometheus metrikleri, Grafana dashboard’ları ve structured logging ile gözlemlenebilir hale getirilmiştir.

---

# Özellikler

## Security Policies
- `privileged=true` → DENY
- `allowPrivilegeEscalation=true` → DENY
- `runAsUser=0` → Ortama göre WARNING / DENY
- `runAsNonRoot=true` zorunlu

## Storage Policies
- `hostPath` volume → DENY
- Sadece belirlenen storageClass kullanımı → ALLOW
- Farklı storageClass → DENY

## Resource Policies
Her container için zorunlu:
- `resources.requests.cpu`
- `resources.requests.memory`
- `resources.limits.cpu`
- `resources.limits.memory`

Eksik olması durumunda → DENY

---

# Environment-Based Policies

Webhook namespace label’larına göre farklı policy davranışları uygular.

## Dev Environment
| Policy | Davranış |
|---|---|
| latest image | ALLOW |
| root user | WARNING |
| privileged | DENY |
| resource limits | REQUIRED |

## Test Environment
| Policy | Davranış |
|---|---|
| latest image | DENY |
| root user | DENY |
| privileged | DENY |
| resource limits | REQUIRED |

---

# Observability

- Prometheus metrics
- Grafana dashboards
- Structured decision logging
- Admission latency tracking

Örnek log:

```text
2026-05-13 18:04:55,100 WARNING EVENT=admission_review DECISION=DENY POLICY=image NAMESPACE=test POD=test-latest-deny REASON="Latest or tagless image not allowed: nginx (nginx:latest)" WARNINGS="-"
```

---

# Teknolojiler
- Python
- FastAPI
- Kubernetes
- Prometheus
- Grafana
- Docker
- Minikube