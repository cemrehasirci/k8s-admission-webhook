'use client';
import styles from './Dashboard.module.css';
import { DashboardStats } from '@/hooks/useDashboardStats';

const Gauge = ({ title, value, max, color, breakdown }: { title: string, value: number, max: number, color: string, breakdown?: any }) => {
  const percentage = max > 0 ? (value / max) * 100 : 0;
  
  return (
    <div className={styles.gaugeCard}>
      <div className={styles.gaugeWrapper}>
        <svg viewBox="0 0 100 50" className={styles.svgGauge}>
          {/* Arka plan yarım çember */}
          <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="#334155" strokeWidth="8" strokeLinecap="round" />
          {/* Renkli değer yarım çemberi */}
          <path 
            d="M 10 50 A 40 40 0 0 1 90 50" 
            fill="none" 
            stroke={color} 
            strokeWidth="8" 
            strokeLinecap="round" 
            strokeDasharray="125.6" 
            strokeDashoffset={125.6 - (125.6 * percentage) / 100} 
            style={{ transition: 'stroke-dashoffset 0.5s ease-out' }}
          />
        </svg>
        <div className={styles.gaugeValue} style={{ color }}>{value}</div>
      </div>
      <div className={styles.gaugeTitle}>{title}</div>
      
      {/* Tooltip (Hover olunca açılacak detay tablosu) */}
      {breakdown && Object.keys(breakdown).length > 0 && (
        <div className={styles.tooltip}>
          {Object.entries(breakdown).map(([reason, count]) => (
            <div key={reason} className={styles.tooltipRow}>
              <span className={styles.tooltipReason}>{reason}</span>
              <span className={styles.tooltipCount}>{count as number}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export function Dashboard({ stats, onReset }: { stats: DashboardStats, onReset: () => void }) {
  const max = Math.max(stats.total, 1); // 0'a bölme hatasını engelle

  return (
    <div className={styles.container}>
      <div className={styles.gaugesRow}>
        <Gauge title="TOPLAM İSTEK" value={stats.total} max={stats.total} color="#38bdf8" />
        <Gauge title="BAŞARILI POD" value={stats.success} max={max} color="#4ade80" />
        <Gauge title="SECURITY REDDİ" value={stats.security.total} max={max} color="#f87171" breakdown={stats.security.breakdown} />
        <Gauge title="STORAGE REDDİ" value={stats.storage.total} max={max} color="#fb923c" breakdown={stats.storage.breakdown} />
        <Gauge title="RESOURCE REDDİ" value={stats.resource.total} max={max} color="#facc15" breakdown={stats.resource.breakdown} />
      </div>
      <button onClick={onReset} className={styles.resetBtn}>Sıfırla</button>
    </div>
  );
}
