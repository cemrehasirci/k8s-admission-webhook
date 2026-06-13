import { NextResponse } from 'next/server';
import { getK8sClient } from '@/lib/k8s';

export const dynamic = 'force-dynamic';

export async function GET() {
  const k8sApi = getK8sClient();

  try {
    const pods = await k8sApi.listNamespacedPod({ namespace: 'webhook-system' });
    const webhookPod = pods.items.find(p => 
      p.metadata?.name?.startsWith('pod-security-webhook-') && 
      p.status?.phase === 'Running' &&
      !p.metadata?.deletionTimestamp
    );

    if (!webhookPod || !webhookPod.metadata?.name) {
      return NextResponse.json({ logs: 'Webhook pod bulunamadı. Lütfen webhook-system namespace\'ini ve pod isimlerini kontrol edin.' });
    }

    const podName = webhookPod.metadata.name;
    
    let logsString = "";
    try {
      // Modern signature
      const logsRes = await (k8sApi.readNamespacedPodLog as any)({
        name: podName,
        namespace: 'webhook-system',
        container: 'webhook',
        tailLines: 1000
      });
      logsString = typeof logsRes === 'string' ? logsRes : (logsRes.body || JSON.stringify(logsRes));
    } catch (e) {
      // Fallback for older client-node signatures
      const logsRes = await (k8sApi.readNamespacedPodLog as any)(podName, 'webhook-system', 'webhook', undefined, undefined, false, undefined, undefined, 1000, false);
      logsString = typeof logsRes === 'string' ? logsRes : (logsRes.body || JSON.stringify(logsRes));
    }

    return NextResponse.json({ logs: logsString });
  } catch (err: any) {
    return NextResponse.json({ logs: `Loglar alınırken hata oluştu: ${err.message || 'Bilinmeyen hata'}` });
  }
}
