# Kubernetes Admission Webhook – v1

## Amaç
Bu sürümün amacı, Kubernetes API Server ile **TLS üzerinden güvenli şekilde haberleşebilen** bir Admission Webhook altyapısı kurmak ve bu altyapının **çalıştığını ve izlenebilir olduğunu** doğrulamaktır.

Bu aşamada webhook, tüm pod oluşturma isteklerine izin vermektedir (`allowed: true`).  
Herhangi bir reddetme (deny) politikası uygulanmamaktadır.


## Yapılan Çalışmalar

### v1.0 – Admission Webhook Altyapısı
- Python (FastAPI) kullanılarak temel bir **Validating Admission Webhook** geliştirildi.
- Webhook, Kubernetes API Server’dan gelen `AdmissionReview` isteklerini alacak şekilde yapılandırıldı.
- HTTPS zorunluluğu için TLS sertifikaları oluşturuldu ve Kubernetes Secret olarak tanımlandı.
- Webhook uygulaması Kubernetes üzerinde **Deployment** ve **Service** olarak çalıştırıldı.
- `ValidatingWebhookConfiguration` ile pod oluşturma istekleri webhook servisine yönlendirildi.
- Test pod’ları ile webhook entegrasyonu başarıyla doğrulandı.



### v1.1 – Metrics ve Gözlemlenebilirlik
- Webhook uygulamasına **Prometheus metrics** entegrasyonu eklendi.
- Admission request sayısı ve gecikme süresi metrikleri tanımlandı.
- Metrics endpoint’i ayrı bir port (9091) üzerinden expose edildi.
- Metrics için ayrı Kubernetes **Service** oluşturuldu.
- Prometheus yapılandırması güncellenerek webhook metrikleri scrape edildi.
- Grafana üzerinde:
  - Admission request sayısı,
  - Request rate,
  - Ortalama webhook gecikmesi,
  - Pod durumları (Running / Pending / Failed)
  panelleri oluşturuldu.
- Kubernetes seviyesinde pod sağlık durumu izlenebilir hale getirildi.



## Sonuç
v1 (v1.0 + v1.1) ile birlikte Admission Webhook altyapısı:

- Kubernetes ile güvenli şekilde entegre edilmiş,
- Çalıştığı testlerle doğrulanmış,
- İzlenebilir ve ölçülebilir hale getirilmiştir.


