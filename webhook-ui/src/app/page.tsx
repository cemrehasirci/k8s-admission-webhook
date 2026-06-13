'use client';

import { useState, useEffect } from 'react';
import styles from './page.module.css';
import { PodConfigForm, PodConfig } from '@/components/PodConfigForm';
import { LogViewer } from '@/components/LogViewer';
import { PodList } from '@/components/PodList';
import { Dashboard } from '@/components/Dashboard';
import { useDashboardStats } from '@/hooks/useDashboardStats';

export default function Home() {
  const [loading, setLoading] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [toast, setToast] = useState<{message: string, type: 'success'|'error'} | null>(null);
  
  const { stats, resetStats } = useDashboardStats(refreshTrigger);

  // Otomatik yenileme (her 5 saniyede bir logları ve dashboard'u günceller)
  useEffect(() => {
    const interval = setInterval(() => {
      setRefreshTrigger(prev => prev + 1);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSubmit = async (config: PodConfig) => {
    setLoading(true);

    try {
      const res = await fetch('/api/pod', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      
      const data = await res.json();
      
      if (res.ok) {
        // Hangi namespace korumalı (webhook var)? Sadece dev ve test
        const isProtected = config.namespace === 'dev' || config.namespace === 'test';
        
        if (!isProtected) {
          // Hangi tehlikeli özelliği seçtiğini bulalım
          let flagReason = "tehlikeli ayarlara";
          if (config.runAsRoot) flagReason = "root (runAsUser: 0) yetkisine";
          else if (config.privileged) flagReason = "Privileged (Ayrıcalıklı) moduna";
          else if (config.allowPrivilegeEscalation) flagReason = "Privilege Escalation'a";
          else if (config.volumeType === 'hostPath') flagReason = "hostPath volume kullanımına";
          else if (!config.runAsNonRoot) flagReason = "Non-Root kuralının atlatılmasına";
          else if (!config.includeResources) flagReason = "limitsiz CPU/Memory kullanımına";

          setToast({ 
            message: `✅ Webhook bu namespace'i kontrol etmediği için ${flagReason} İZİN VERİLDİ. Pod başarılı bir şekilde oluşturuldu!`, 
            type: 'success' 
          });
        } else {
          setToast({ message: '✅ Pod başarıyla oluşturuldu!', type: 'success' });
        }
      } else {
        setToast({ message: `❌ Reddedildi: ${data.message || 'Bilinmeyen Hata'}`, type: 'error' });
      }
      setTimeout(() => setToast(null), 8000); // Kullanıcı uzun mesajı okuyabilsin diye 8 saniye yapıyoruz
      setRefreshTrigger(prev => prev + 1);
    } catch (err: any) {
      setToast({ message: '❌ Sunucu Hatası', type: 'error' });
      setTimeout(() => setToast(null), 4000);
    } finally {
      setLoading(false);
      // Webhook'un log yazmasını 1 saniye bekle ve verileri tekrar tazele
      setTimeout(() => setRefreshTrigger(prev => prev + 1), 1000);
    }
  };

  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    // Check local storage for theme preference
    const savedTheme = localStorage.getItem('theme') as 'dark' | 'light' | null;
    if (savedTheme) {
      setTheme(savedTheme);
      document.documentElement.setAttribute('data-theme', savedTheme);
    }
  }, []);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
  };

  return (
    <div className={styles.mainWrapper}>
      {/* Yukarıdan Gelen Bildirim (Toast) */}
      {toast && (
        <div style={{
          position: 'fixed', top: '20px', left: '50%', transform: 'translateX(-50%)', zIndex: 9999,
          background: toast.type === 'success' ? '#10b981' : '#ef4444', color: '#fff',
          padding: '12px 24px', borderRadius: '8px', fontWeight: 'bold', boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
          animation: 'slideDown 0.3s ease-out'
        }}>
          {toast.message}
        </div>
      )}

      <div className={styles.header}>
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', position: 'relative' }}>
          <h1 className="title" style={{ margin: 0 }}>Pod Security Webhook</h1>
          <button 
            onClick={toggleTheme}
            className="no-invert"
            style={{
              position: 'absolute',
              right: 0,
              background: 'rgba(255, 255, 255, 0.1)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              borderRadius: '50%',
              width: '44px',
              height: '44px',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              fontSize: '1.4rem',
              cursor: 'pointer',
              transition: 'all 0.3s ease',
              boxShadow: '0 4px 15px rgba(0, 0, 0, 0.2)'
            }}
            title="Temayı Değiştir"
          >
            {theme === 'dark' ? '🌙' : '☀️'}
          </button>
        </div>
      </div>

      <div className={styles.dashboardSection}>
        <Dashboard stats={stats} onReset={resetStats} />
      </div>

      <main className={styles.container}>
        <div className={styles.leftCol}>
          <div className="glass-panel" style={{ height: '100%' }}>
            <PodConfigForm onSubmit={handleSubmit} loading={loading} />
          </div>
        </div>
        
        <div className={styles.rightCol} style={{ marginTop: '20px' }}>
          <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
            <h2 style={{ marginBottom: '16px', color: '#f8fafc', fontSize: '1.4rem', fontWeight: 600 }}>Test Sonucu & Loglar</h2>
            
            <div style={{ height: '400px', display: 'flex', flexDirection: 'column' }}>
              <LogViewer refreshTrigger={refreshTrigger} />
            </div>
          </div>
        </div>
      </main>

      {/* Aktif Podlar Bölümü */}
      <div className={styles.podListSection}>
        <PodList refreshTrigger={refreshTrigger} />
      </div>
    </div>
  );
}
