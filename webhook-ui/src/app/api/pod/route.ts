import { NextResponse } from 'next/server';
import { getK8sClient } from '@/lib/k8s';

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const k8sApi = getK8sClient();

    // Benzersiz bir pod ismi oluştur
    const podName = `test-pod-${Math.floor(Date.now() / 1000)}`;

    const podManifest: any = {
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: {
        name: podName,
        namespace: body.namespace || 'default',
        labels: {
          app: 'webhook-test'
        },
        annotations: {}
      },
      spec: {
        securityContext: {
          runAsNonRoot: body.runAsNonRoot,
        },
        containers: [
          {
            name: 'test-container',
            image: body.image === 'unprivileged' ? 'nginxinc/nginx-unprivileged:latest' : body.image === 'latest' ? 'nginx:latest' : body.image === 'alpine' ? 'nginx:alpine' : body.image,
            securityContext: {
              ...(body.privileged ? { privileged: true } : {}),
              ...(body.allowPrivilegeEscalation ? { allowPrivilegeEscalation: true } : {})
            },
            volumeMounts: [],
            env: []
          }
        ],
        volumes: []
      }
    };

    // runAsUser ayarı (0 ise root)
    if (body.runAsRoot) {
      podManifest.spec.securityContext.runAsUser = 0;
    }

    // Vault Annotation Ekleme (v4)
    if (body.vaultAnnotations) {
      podManifest.metadata.annotations['vault.hashicorp.com/agent-inject'] = 'true';
      podManifest.metadata.annotations['vault.hashicorp.com/role'] = 'app-role';
    }

    // Storage Kuralları (v3)
    if (body.volumeType === 'hostPath') {
      podManifest.spec.volumes.push({
        name: 'test-vol',
        hostPath: { path: '/tmp/test' }
      });
      podManifest.spec.containers[0].volumeMounts.push({
        name: 'test-vol',
        mountPath: '/data'
      });
    } else if (body.volumeType === 'emptyDir') {
      podManifest.spec.volumes.push({
        name: 'test-vol',
        emptyDir: {}
      });
      podManifest.spec.containers[0].volumeMounts.push({
        name: 'test-vol',
        mountPath: '/data'
      });
    } else if (body.volumeType === 'pvc') {
      podManifest.spec.volumes.push({
        name: 'test-vol',
        persistentVolumeClaim: { claimName: body.pvcName || 'test-pvc' }
      });
      podManifest.spec.containers[0].volumeMounts.push({
        name: 'test-vol',
        mountPath: '/data'
      });
    }

    // Native Secret (v4)
    if (body.useNativeSecret) {
      podManifest.spec.containers[0].env.push({
        name: 'SECRET_KEY',
        valueFrom: {
          secretKeyRef: {
            name: 'my-secret',
            key: 'password'
          }
        }
      });
    }

    // Resources (v5)
    if (body.includeResources) {
      podManifest.spec.containers[0].resources = {
        requests: { cpu: '100m', memory: '128Mi' },
        limits: { cpu: '200m', memory: '256Mi' }
      };
    }

    // Boş dizileri temizle ki k8s hata vermesin
    if (podManifest.spec.containers[0].volumeMounts.length === 0) delete podManifest.spec.containers[0].volumeMounts;
    if (podManifest.spec.containers[0].env.length === 0) delete podManifest.spec.containers[0].env;
    if (podManifest.spec.volumes.length === 0) delete podManifest.spec.volumes;
    if (Object.keys(podManifest.metadata.annotations).length === 0) delete podManifest.metadata.annotations;

    try {
      // Pod oluşturma isteği at
      // Modern client-node versiyonlarında obje olarak parametre gönderilir.
      const response = await k8sApi.createNamespacedPod({
        namespace: podManifest.metadata.namespace,
        body: podManifest
      });
      
      return NextResponse.json({ 
        success: true, 
        message: 'Pod başarıyla oluşturuldu (ALLOW)', 
        pod: response 
      });
    } catch (err: any) {
      // Admission Webhook reddettiğinde veya k8s hatası
      const errorBody = err.body;
      return NextResponse.json({ 
        success: false, 
        message: errorBody?.message || err.message || 'Bilinmeyen hata',
        reason: errorBody?.reason || 'DENY'
      }, { status: 400 });
    }

  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
