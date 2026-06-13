import { NextResponse } from 'next/server';
import { getK8sClient } from '@/lib/k8s';

export async function GET(req: Request) {
  try {
    const k8sApi = getK8sClient();

    // Tüm namespacelerdeki podları çek
    const res = await k8sApi.listPodForAllNamespaces();
    // @ts-ignore
    const items = res.items || (res.body && res.body.items) || [];

    const allPods = items.map((p: any) => {
      let exactStatus = p.status?.phase || 'Unknown';
      
      // Kubernetes'in "CrashLoopBackOff" gibi detaylı hata mesajlarını bulmak için:
      if (p.status?.containerStatuses) {
        for (const container of p.status.containerStatuses) {
          if (container.state?.waiting && container.state.waiting.reason) {
            exactStatus = container.state.waiting.reason; // CrashLoopBackOff vb.
            break;
          } else if (container.state?.terminated && container.state.terminated.reason) {
            exactStatus = container.state.terminated.reason; // Error vb.
            break;
          }
        }
      }

      return {
        name: p.metadata?.name || 'Unknown',
        namespace: p.metadata?.namespace || 'Unknown',
        status: exactStatus,
        startTime: p.status?.startTime ? new Date(p.status.startTime).toLocaleString() : 'N/A'
      };
    });

    return NextResponse.json({ pods: allPods });
  } catch (err: any) {
    console.error("Pod getirme hatası:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function DELETE(req: Request) {
  try {
    const { searchParams } = new URL(req.url);
    const name = searchParams.get('name');
    const namespace = searchParams.get('namespace');

    if (!name || !namespace) {
      return NextResponse.json({ error: 'Name ve namespace gereklidir.' }, { status: 400 });
    }

    const k8sApi = getK8sClient();

    // Modern client-node objesi ile istek
    await k8sApi.deleteNamespacedPod({ name, namespace });

    return NextResponse.json({ success: true, message: `Pod ${name} başarıyla silindi.` });
  } catch (err: any) {
    console.error("Silme hatası:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
