import { NextResponse } from 'next/server';
import { getK8sClient } from '@/lib/k8s';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const k8sApi = getK8sClient();
    // Kubernetes'ten tüm namespace'leri çek
    const res = await k8sApi.listNamespace();
    // @ts-ignore
    const items = res.items || (res.body && res.body.items) || [];
    
    // Gelen namespaces listesini temizle ve sadece isimlerini al
    const namespaces = items.map((ns: any) => ns.metadata?.name).filter(Boolean);
    
    return NextResponse.json({ namespaces });
  } catch (err: any) {
    console.error("Namespace getirme hatası:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
