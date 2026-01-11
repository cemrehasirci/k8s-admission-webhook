# Kubernetes Admission Webhook – v3.0

## Amaç
v3.0 sürümünün amacı, Kubernetes Admission Webhook altyapısını **storage-aware güvenlik politikaları** ile genişleterek,
pod’ların cluster’a alınmadan önce **kullandıkları storage tipine göre** denetlenmesini ve standart dışı kullanımın
engellenmesini sağlamaktır.

Bu sürüm ile birlikte webhook yalnızca container-level güvenlik politikalarını değil,
aynı zamanda **kalıcı veri (storage) kullanımını** da kontrol eden merkezi bir policy enforcement bileşeni haline getirilmiştir.

Ayrıca, uygulanan storage politikalarının etkisi Prometheus metrikleri ve Grafana dashboard’ları üzerinden ölçülerek
gözlemlenebilirlik sağlanmıştır.



## v3.0 – Storage Policy Enforcement

### Uygulanan Storage Politikaları
Webhook, pod oluşturma isteklerini aşağıdaki storage kurallarına göre değerlendirmektedir:

- **hostPath volume kullanan pod’lar engellenir**
  - `volumes[].hostPath` tanımı bulunan pod’lar Admission aşamasında reddedilir
- **Sadece Longhorn tabanlı PVC’lere izin verilir**
  - `storageClassName: longhorn`
- Longhorn dışındaki tüm storageClass’lar (Ceph, MinIO vb.) reddedilir

Bu sayede:
- Node filesystem erişimi engellenmiş,
- Stateful workload’lar için **tek tip ve yönetilebilir storage standardı** sağlanmıştır.


## Namespace ve Self-Protection Mekanizması

Admission Webhook’un kendi kendini kilitlemesini önlemek amacıyla:

- Webhook pod’u `objectSelector` mekanizması ile doğrulama kapsamı dışında bırakılmıştır
- Aynı namespace içerisinde çalışan test pod’ları policy denetimine **devam etmektedir**

Bu yaklaşım, namespace bazlı tamamen devre dışı bırakma yerine **nesne bazlı (object-level) izolasyon** sağlayarak
daha kontrollü ve güvenli bir yapı sunmaktadır.


## v3.0 – Metrics ve Gözlemlenebilirlik

### Yeni Eklenen Prometheus Metrikleri
v3.0 ile birlikte aşağıdaki storage odaklı metrikler eklenmiştir:

- hostPath nedeniyle reddedilen pod sayısı
- Longhorn dışı PVC kullandığı için reddedilen pod sayısı
- Toplam admission request sayısı
- İzin verilen (allowed) pod sayısı
- Reddedilen (denied) pod sayısı
- Admission webhook gecikme süresi (latency)

Tüm metrikler Prometheus Counter ve Histogram tiplerinde tanımlanmıştır.


## Grafana Dashboard’ları

Grafana üzerinde aşağıdaki paneller oluşturulmuştur:

- Denied Pods – hostPath
- Denied Pods – Non-Longhorn PVC
- Allowed vs Denied Admission Requests (Rate)
- Admission Webhook Latency (p95)
- Admission Request Volume (Rate)

Grafana panellerinde **raw counter değerleri yerine `increase` ve `rate` fonksiyonları kullanılarak**,
pod restart ve rollout işlemlerinden bağımsız, zaman penceresi bazlı analiz sağlanmıştır.



## Test Senaryoları

v3.0 kapsamında aşağıdaki test senaryoları uygulanmıştır:

- hostPath volume kullanan pod → **DENY**
- Ceph storageClass kullanan PVC + pod → **DENY**
- MinIO storageClass kullanan PVC + pod → **DENY**
- Longhorn PVC kullanan pod → **ALLOW**


## Sonuç

v3.0 sürümü ile birlikte Admission Webhook altyapısı:

- Container-level güvenlik kontrollerinin ötesine geçerek storage-aware hale getirilmiş,
- Node filesystem erişimini ve standart dışı storage kullanımını engellemiş,
- Stateful workload’lar için Longhorn tabanlı merkezi bir storage standardı oluşturmuş,
- Tüm kararları metrikler ve dashboard’lar üzerinden ölçülebilir hale getirmiştir.

Bu yapı, Kubernetes ortamlarında **policy-driven ve standardize edilmiş storage güvenliği** yaklaşımının
uygulanabilirliğini göstermektedir.
