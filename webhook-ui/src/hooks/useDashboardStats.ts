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

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/dashboard/stats');
      if (res.ok) {
        const data = await res.json();
        if (!data.error) {
          setStats(data);
        }
      }
    } catch (e) {
      console.error("Dashboard istatistikleri çekilemedi:", e);
    }
  };

  useEffect(() => {
    fetchStats();
  }, [refreshTrigger]);

  // Artık kalıcı veritabanından okuduğumuz için manuel sıfırlama işlevsizdir,
  // ancak UI'ı bozmamak için fonksiyonu tutuyoruz.
  const resetStats = () => setStats(defaultStats);

  return { stats, resetStats };
}
