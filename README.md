# Kubernetes Admission Webhook – v2.0

## Amaç
v2.0 sürümünün amacı, Kubernetes Admission Webhook altyapısını **aktif güvenlik politikaları** ile genişletmek ve pod’ların cluster’a alınmadan önce **policy bazlı olarak denetlenmesini ve engellenmesini** sağlamaktır.

Bu sürümde webhook yalnızca gözlem yapan bir bileşen olmaktan çıkarılmış, **güvenlik enforcement** (zorlayıcı denetim) mekanizması haline getirilmiştir.

Ayrıca, uygulanan politikaların etkisi **Prometheus ve Grafana metrikleri** üzerinden ölçülerek doğrulanmıştır.



## v2.0 – Güvenlik Politikaları ve Enforcement

### Uygulanan Admission Politikaları
Webhook, pod oluşturma isteklerini aşağıdaki kurallara göre değerlendirmektedir:

- **Root kullanıcı ile çalışan pod’lar engellenir**
  - `runAsUser: 0`
- **Privileged container içeren pod’lar engellenir**
  - `securityContext.privileged: true`
- **Non-root çalışmayı garanti etmeyen pod’lar engellenir**
  - `runAsNonRoot: true` eksikliği
- **Privilege Escalation’a izin veren pod’lar engellenir**
  - `allowPrivilegeEscalation: true`

Bu koşullardan herhangi birini sağlayan pod’lar **Admission aşamasında reddedilir** ve Kubernetes cluster’a alınmaz.



## v2.0 – Metrics ve Gözlemlenebilirlik (Genişletilmiş)

### Yeni Eklenen Prometheus Metrikleri
v2.0 ile birlikte politika bazlı metrikler eklenmiştir:

- Toplam admission request sayısı
- İzin verilen (allowed) pod sayısı
- Reddedilen (denied) pod sayısı
- **Policy bazlı deny sayaçları:**
  - Root user ihlalleri
  - Privileged container ihlalleri
  - Non-root policy ihlalleri
  - Privilege escalation ihlalleri
- Admission webhook gecikme süresi (latency)

Tüm metrikler `Counter` ve `Histogram` tiplerinde tanımlanmıştır.



## Grafana Dashboard’ları
Grafana üzerinde aşağıdaki paneller oluşturulmuştur:

- Admission Requests (Toplam / Rate)
- Allowed vs Denied Requests
- Ortalama Webhook Latency
- **Denied Pods – Root User**
- **Denied Pods – Privileged**
- **Denied Pods – NonRoot Violation**
- **Denied Pods – Privilege Escalation**
- Webhook Availability (UP / DOWN)

Bu paneller sayesinde:
- Hangi güvenlik kuralının ne sıklıkla tetiklendiği,
- Admission Webhook’un aktif olarak policy enforcement yaptığı
görsel olarak doğrulanabilmektedir.



## Test Senaryoları
Her güvenlik politikası için ayrı test pod’ları oluşturulmuştur:

- Root kullanıcıyla çalışan pod → **DENY**
- Privileged container → **DENY**
- Non-root garantisi olmayan pod → **DENY**
- Privilege escalation açık pod → **DENY**
- Non-root, escalation kapalı ve privileged olmayan pod → **ALLOW**

Test sonuçları:
- `kubectl` hata çıktıları
- Webhook logları
- Grafana metrikleri
üzerinden doğrulanmıştır.


## Sonuç
v2.0 sürümü ile birlikte Admission Webhook altyapısı:

- Pasif gözlem yapan bir bileşenden çıkarılmış,
- **Aktif güvenlik denetimi uygulayan bir kontrol noktası** haline getirilmiş,
- Pod’ların daha cluster’a alınmadan önce güvenlik açısından filtrelenmesini sağlamış,
- Tüm kararları metrikler ve dashboard’lar üzerinden ölçülebilir ve doğrulanabilir kılmıştır.

Bu yapı, Kubernetes ortamlarında **policy-driven security enforcement** yaklaşımının uygulanabilirliğini göstermektedir.
