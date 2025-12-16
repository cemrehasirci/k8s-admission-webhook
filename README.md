# Kubernetes Admission Webhook – v1

## Amaç
Bu sürümün amacı, Kubernetes API Server ile TLS üzerinden haberleşebilen bir Admission Webhook altyapısı kurmak ve bu iletişimin başarıyla gerçekleştiğini doğrulamaktır.  
Bu aşamada webhook herhangi bir güvenlik politikası uygulamaz ve tüm pod oluşturma isteklerine izin verir.

## Yapılan Çalışmalar
Bu sürüm kapsamında aşağıdaki çalışmalar gerçekleştirilmiştir:

- Python (FastAPI) kullanılarak temel bir Validating Admission Webhook geliştirildi.
- Webhook, Kubernetes API Server’dan gelen AdmissionReview isteklerini alacak şekilde yapılandırıldı.
- HTTPS zorunluluğu için TLS sertifikaları oluşturuldu ve Kubernetes Secret olarak tanımlandı.
- Webhook uygulaması Kubernetes üzerinde Deployment ve Service olarak çalıştırıldı.
- ValidatingWebhookConfiguration tanımı ile pod oluşturma istekleri webhook servisine yönlendirildi.

## Test ve Doğrulama
Webhook’un doğru çalıştığını doğrulamak amacıyla aşağıdaki testler yapılmıştır:

- Test amacıyla kullanılan `webhook-test` pod manifesti ile yeni bir pod oluşturma isteği gönderildi.
- Kubernetes API Server’ın bu isteği webhook servisine ilettiği gözlemlendi.
- Webhook loglarında gelen AdmissionReview nesnesi başarıyla görüntülendi.
- Webhook tarafından `allowed: true` yanıtı dönüldüğü ve pod’un oluşturulduğu doğrulandı.


## Sonuç
Bu sürümde, Admission Webhook’un Kubernetes API Server ile doğru ve güvenli bir şekilde entegre olduğu kanıtlanmıştır.  
Elde edilen bu altyapı, sonraki sürümlerde uygulanacak güvenlik politikaları için sağlam bir temel oluşturmaktadır.
