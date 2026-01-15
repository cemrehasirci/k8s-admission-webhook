# Kubernetes Admission Webhook

Kubernetes **Validating Admission Webhook** projesidir. Amaç; Pod’lar cluster’a alınmadan önce belirlenen kurallara göre
**ALLOW / DENY** kararı vererek standart dışı ve riskli kullanımın önüne geçmektir.

Webhook kararları **Prometheus metrikleri** ile ölçülür, **Grafana dashboard**’ları ile izlenir.

---

## Projenin Kapsadığı Politikalar

### 1) Security Policies (v2 ile olgunlaştı)
Pod içindeki `containers` ve `initContainers` için temel güvenlik kontrolleri uygulanır:
- **privileged** container → DENY
- **allowPrivilegeEscalation=true** → DENY
- **runAsUser=0 (root)** → DENY
- **runAsNonRoot=true zorunlu** (değilse) → DENY

### 2) Storage Policies (v3.0)
Storage standardı ve node güvenliği için:
- **hostPath volume** → DENY
- **Sadece belirlenen storageClass (default: longhorn) PVC** → ALLOW
- Longhorn dışı storageClass → DENY
- PVC lookup hatası (RBAC/NotFound vb.) → DENY

### 3) Resource Policies (v4.0)
Kaynak disiplini için her container/initContainer’da zorunlu:
- `resources.requests.cpu` ve `resources.requests.memory`
- `resources.limits.cpu` ve `resources.limits.memory`
Eksik olan her durumda → **DENY** (ayrı deny reason + metric)

---

## Gözlemlenebilirlik (Prometheus + Grafana)
Webhook şu metrikleri üretir:
- Toplam admission request sayısı
- Allowed / Denied sayıları
- Policy bazlı **deny reason** sayaçları (security/storage/resources)
- Admission latency (Histogram)

Grafana panellerinde `rate()` / `increase()` kullanılarak zaman penceresi bazlı analiz yapılır.

---

## Versiyon Özeti
- **v1.x:** TLS ile çalışan admission webhook temel altyapısı
- **v2.x:** Security policy enforcement + metrik/karar takibi genişletmeleri
- **v3.0:** Storage policy enforcement (hostPath deny + Longhorn standardı) + dashboard’lar
- **v4.0:** CPU/Memory requests+limits zorunluluğu (resource enforcement) + yeni deny metrics/dashboard’lar
