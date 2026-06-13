'use client';
import { useState, useEffect } from 'react';

export interface StatBreakdown {
  [reason: string]: number;
}

export interface DashboardStats {
  total: number;
  success: number;
  security: { total: number; breakdown: StatBreakdown };
  storage: { total: number; breakdown: StatBreakdown };
  resource: { total: number; breakdown: StatBreakdown };
}

const defaultStats: DashboardStats = {
  total: 0,
  success: 0,
  security: { total: 0, breakdown: {} },
  storage: { total: 0, breakdown: {} },
  resource: { total: 0, breakdown: {} }
};

export function useDashboardStats(refreshTrigger?: number) {
  const [stats, setStats] = useState<DashboardStats>(defaultStats);

  const fetchAndParseLogs = async () => {
    try {
      const res = await fetch('/api/logs');
      const data = await res.json();
      const logs = data.logs || '';
      
      // Her seferinde baştan hesapla (Geçmişteki 1000 satırı tarar)
      const newStats: DashboardStats = JSON.parse(JSON.stringify(defaultStats));
      const lines = logs.split('\n');

      lines.forEach((line: string) => {
        // ANSI renk kodlarını temizle
        const cleanLine = line.replace(/\x1b\[[0-9;]*m/g, '').replace(/\[91m/g, '').replace(/\[92m/g, '').replace(/\[0m/g, '');
        
        // BAŞARILI (ALLOW) İstekleri Sayma:
        // Webhook, başarılı istekler için EVENT logu basmıyor, sadece AUDIT logu basıyor.
        if (cleanLine.startsWith('[AUDIT]') && cleanLine.includes('decision=allow')) {
          newStats.total += 1;
          newStats.success += 1;
          return; // Bu satırla işimiz bitti
        }

        // REDDEDİLEN (DENY) İstekleri Sayma:
        // Hata sebeplerini (REASON) alabilmek için EVENT=admission_review satırını kullanıyoruz.
        if (cleanLine.includes('EVENT=admission_review') && cleanLine.includes('DECISION=DENY')) {
          newStats.total += 1;
          
          // POLICY="..." ve REASON="..." ayıkla
          const policyMatch = cleanLine.match(/POLICY=([^ ]+)/);
          const policyRaw = policyMatch ? policyMatch[1] : 'unknown';
          
          let reason = 'Bilinmeyen Red Sebebi';
          const reasonMatch = cleanLine.match(/REASON="([^"]+)"/);
          if (reasonMatch) {
            reason = reasonMatch[1];
          }

          // Policy adına göre kategoriye yerleştir
          let category: 'security' | 'storage' | 'resource' = 'security';
          if (policyRaw === 'resources') category = 'resource';
          else if (policyRaw === 'storage') category = 'storage';
          else if (policyRaw === 'security') category = 'security';
          else {
            // Fallback rules
            const rLow = reason.toLowerCase();
            if (rLow.includes('resource') || rLow.includes('cpu') || rLow.includes('memory')) category = 'resource';
            else if (rLow.includes('volume') || rLow.includes('storage') || rLow.includes('hostpath')) category = 'storage';
          }

          if (reason.length > 55) {
            reason = reason.substring(0, 55) + '...';
          }

          newStats[category].total += 1;
          if (!newStats[category].breakdown[reason]) {
            newStats[category].breakdown[reason] = 0;
          }
          newStats[category].breakdown[reason] += 1;
        }
      });

      setStats(newStats);
    } catch (e) {
      console.error("Dashboard istatistikleri için loglar çekilemedi:", e);
    }
  };

  useEffect(() => {
    fetchAndParseLogs();
  }, [refreshTrigger]);

  // Loglardan okuduğumuz için manuel sıfırlama sadece anlık temizler, sonraki tickte geri gelir.
  const resetStats = () => setStats(defaultStats);

  return { stats, resetStats };
}
