'use client';
import { useState, useEffect, useRef } from 'react';
import { RefreshCw } from 'lucide-react';
import styles from './LogViewer.module.css';

export function LogViewer({ refreshTrigger }: { refreshTrigger?: number }) {
  const [logs, setLogs] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState<'formatted' | 'json'>('formatted');
  const bottomRef = useRef<HTMLDivElement>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/logs');
      const data = await res.json();
      setLogs(data.logs || 'Bilinmeyen log formatı');
    } catch (e: any) {
      setLogs(`Hata: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [refreshTrigger]);

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, viewMode]);

  const formatLogLine = (line: string, index: number) => {
    if (!line.trim()) return null;
    
    // 1. Terminalden gelen karmaşık ANSI renk kodlarını tamamen temizle
    let cleanLine = line.replace(/\x1b\[[0-9;]*m/g, '');
    
    // 2. HTML karakterlerini güvenli hale getir
    let safeLine = cleanLine.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    
    // JSON modundaysak sadece string'i bas (renklendirme yok)
    if (viewMode === 'json') {
      return <div key={index} style={{ minHeight: '1.2em', opacity: 0.8 }}>{safeLine}</div>;
    }

    // Formatted modu: Temizlenmiş metin üzerinden kendi renklerimizi uygulayalım
    safeLine = safeLine
      .replace(/DECISION=DENY/g, 'DECISION=<span style="color: var(--log-error); font-weight: bold;">DENY</span>')
      .replace(/DECISION=ALLOW_WITH_WARNING/g, 'DECISION=<span style="color: #fde047; font-weight: bold;">ALLOW_WITH_WARNING</span>')
      .replace(/DECISION=ALLOW/g, 'DECISION=<span style="color: var(--log-success); font-weight: bold;">ALLOW</span>')
      .replace(/WARNING EVENT=/g, '<span style="color: #f97316; font-weight: bold;">WARNING</span> EVENT=')
      .replace(/INFO EVENT=/g, '<span style="color: var(--log-info); font-weight: bold;">INFO</span> EVENT=')
      .replace(/INFO:/g, '<span style="color: var(--log-info);">INFO:</span>')
      .replace(/WARNING:/g, '<span style="color: var(--log-warning);">WARNING:</span>')
      .replace(/ERROR:/g, '<span style="color: var(--log-error);">ERROR:</span>')
      .replace(/\[AUDIT\]/g, '<span style="color: var(--log-audit);">[AUDIT]</span>');

    return <div key={index} dangerouslySetInnerHTML={{ __html: safeLine }} style={{ minHeight: '1.2em' }} />;
  };

  const parseLogsToJson = (rawLogs: string) => {
    const lines = rawLogs.split('\n').filter(l => l.trim() !== '');
    const groupedEvents: any[] = [];
    let currentEvent: any = null;

    lines.forEach(line => {
      const cleanLine = line.replace(/\x1b\[[0-9;]*m/g, '').replace(/\[91m/g, '').replace(/\[92m/g, '').replace(/\[0m/g, '');
      
      if (!currentEvent) currentEvent = {};

      if (cleanLine.startsWith('[AUDIT]')) {
        const parts = cleanLine.split('|').map(s => s.trim());
        const msg = parts[0].replace('[AUDIT]', '').trim();
        currentEvent.audit_message = msg;
        if (parts[1]) {
          parts[1].split(' ').forEach(kv => {
            const [k, v] = kv.split('=');
            if (k && v) currentEvent[k] = v;
          });
        }
      } 
      else if (cleanLine.startsWith('INFO:')) {
        const match = cleanLine.match(/INFO:\s+([0-9\.:]+)\s+-\s+"([^"]+)"\s+(\d+)\s+(.*)/);
        if (match) {
          currentEvent.client_ip = match[1];
          currentEvent.http_request = match[2];
          currentEvent.status_code = parseInt(match[3]);
          currentEvent.status_text = match[4];
          
          // HTTP erişim logu genellikle bir isteğin son logudur.
          // Kutucuğu kapatıp listeye ekliyoruz.
          groupedEvents.push(currentEvent);
          currentEvent = null;
        } else {
          currentEvent.raw_info = cleanLine;
        }
      }
      else {
        const eventMatch = cleanLine.match(/^([\d-]+ [\d:,]+) (\w+) (.*)/);
        if (eventMatch) {
          currentEvent.timestamp = eventMatch[1];
          currentEvent.level = eventMatch[2];
          const rest = eventMatch[3];
          const kvRegex = /(\w+)=(?:"([^"]*)"|([^ ]*))/g;
          let kvMatch;
          while ((kvMatch = kvRegex.exec(rest)) !== null) {
            currentEvent[kvMatch[1].toLowerCase()] = kvMatch[2] !== undefined ? kvMatch[2] : kvMatch[3];
          }
        } else {
          // Tamamen bilinmeyen bir satır formatıysa
          if (Object.keys(currentEvent).length === 0) {
            groupedEvents.push({ raw_message: cleanLine });
            currentEvent = null;
          } else {
            currentEvent.extra_data = cleanLine;
          }
        }
      }
    });

    // Döngü bittiğinde elde kalan kapanmamış bir log grubu varsa ekle
    if (currentEvent && Object.keys(currentEvent).length > 0) {
      groupedEvents.push(currentEvent);
    }
    
    // En yeni loglar en üstte görünsün diye ters çeviriyoruz (isteğe bağlı)
    return groupedEvents.reverse();
  };

  return (
    <div className={styles.terminal}>
      <div className={styles.header}>
        <span>pod-security-webhook logs</span>
        <div className={styles.actions}>
          <button 
            className={`${styles.viewToggleBtn} ${viewMode === 'formatted' ? styles.active : ''}`}
            onClick={() => setViewMode('formatted')}
          >
            Formatted
          </button>
          <button 
            className={`${styles.viewToggleBtn} ${viewMode === 'json' ? styles.active : ''}`}
            onClick={() => setViewMode('json')}
          >
            JSON
          </button>
          <button className={styles.btn} onClick={fetchLogs} disabled={loading} title="Logları Yenile">
            {loading ? '...' : <RefreshCw size={14} />}
          </button>
        </div>
      </div>
      <div className={styles.logs}>
        {logs ? (
          viewMode === 'json' ? (
            <div className={styles.jsonContainer}>
              {parseLogsToJson(logs).map((logObj, idx) => (
                <pre key={idx} className={styles.jsonCard}>
                  {JSON.stringify(logObj, null, 2)}
                </pre>
              ))}
            </div>
          ) : (
            logs.split('\n').map((line, i) => formatLogLine(line, i))
          )
        ) : (
          <span className={styles.empty}>Henüz log yok...</span>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
