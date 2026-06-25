'use client';
import { useState, useEffect } from 'react';
import { RefreshCw, Trash2, CheckSquare, XSquare } from 'lucide-react';
import styles from './PodList.module.css';
import { Select } from './FormControls';

interface Pod {
  name: string;
  namespace: string;
  status: string;
  startTime: string;
}

export function PodList({ refreshTrigger }: { refreshTrigger: number }) {
  const [pods, setPods] = useState<Pod[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectionMode, setSelectionMode] = useState(false);
  const [selectedPods, setSelectedPods] = useState<Set<string>>(new Set());
  
  // Yeni Filtre State'leri
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [selectedNsFilter, setSelectedNsFilter] = useState<string>('all');

  const fetchPodsAndNamespaces = async (isManual = false) => {
    if (isManual) setLoading(true);
    try {
      const podRes = await fetch('/api/pods');
      const podData = await podRes.json();
      if (podData.pods) {
        setPods(podData.pods);
      }
    
      const nsRes = await fetch('/api/namespaces');
      const nsData = await nsRes.json();
      if (nsData.namespaces) {
        setNamespaces(nsData.namespaces);
      }
    } catch (e) {
      console.error(e);
    } finally {
      if (isManual) setLoading(false);
    }
  };

  // Otomatik yenilemelerde butonu 'Yenileniyor' yapma
  useEffect(() => {
    const loadPodsAndNamespaces = async () => {
      try {
        const podRes = await fetch('/api/pods');
        const podData = await podRes.json();
        if (podData.pods) {
          setPods(podData.pods);
        }

        const nsRes = await fetch('/api/namespaces');
        const nsData = await nsRes.json();
        if (nsData.namespaces) {
          setNamespaces(nsData.namespaces);
        }
      } catch (e) {
        console.error(e);
      }
    };

    loadPodsAndNamespaces();
  }, [refreshTrigger]);

  const toggleSelectionMode = () => {
    setSelectionMode(!selectionMode);
    setSelectedPods(new Set()); // Mod kapanıp açıldığında seçili olanları temizle
  };

  const togglePodSelection = (id: string) => {
    const newSet = new Set(selectedPods);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setSelectedPods(newSet);
  };

  const handleDeleteSingle = async (name: string, namespace: string) => {
    if (!confirm(`Pod'u silmek istediğinize emin misiniz: ${name}?`)) return;
    
    try {
      setLoading(true);
      await fetch(`/api/pods?name=${name}&namespace=${namespace}`, {
        method: 'DELETE'
      });
      fetchPodsAndNamespaces();
    } catch (e) {
      alert("Silme işlemi başarısız oldu.");
      setLoading(false);
    }
  };

  const handleBulkDelete = async () => {
    if (selectedPods.size === 0) return;
    if (!confirm(`Seçili ${selectedPods.size} pod'u silmek istediğinize emin misiniz?`)) return;
    
    setLoading(true);
    try {
      const promises = Array.from(selectedPods).map(id => {
        const [ns, name] = id.split('/');
        return fetch(`/api/pods?name=${name}&namespace=${ns}`, { method: 'DELETE' });
      });
      
      await Promise.all(promises);
      
      // İşlem bitince seçim modunu kapat ve tabloyu yenile
      setSelectionMode(false);
      setSelectedPods(new Set());
      fetchPodsAndNamespaces();
    } catch (e) {
      alert("Toplu silme sırasında bir hata oluştu.");
      setLoading(false);
    }
  };

  const formatPodTime = (value?: string) => {
    if (!value) return "-";
    const date = new Date(value);
    if (isNaN(date.getTime())) return value;
  
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  };

  // Podları filtrele
  const filteredPods = selectedNsFilter === 'all' 
    ? pods 
    : pods.filter(p => p.namespace === selectedNsFilter);

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.title}>Aktif Podlar (Kubernetes)</div>
        <div className={styles.headerActions}>
          
          <Select 
            wrapperClassName={styles.filterSelectWrapper}
            className={styles.filterSelectOverride}
            options={[{label: 'Tüm Namespaceler', value: 'all'}, ...namespaces.map(ns => ({label: ns, value: ns}))]}
            value={selectedNsFilter}
            onChange={(val) => setSelectedNsFilter(val)}
          />

          {selectionMode && selectedPods.size > 0 && (
            <button className={styles.bulkDeleteBtn} onClick={handleBulkDelete} disabled={loading}>
              <Trash2 size={16} /> Seçilenleri Sil ({selectedPods.size})
            </button>
          )}
          
          <button className={styles.selectBtn} onClick={toggleSelectionMode} disabled={loading}>
            {selectionMode ? (
              <><XSquare size={16} /> İptal</>
            ) : (
              <><CheckSquare size={16} /> Seç</>
            )}
          </button>
          
          <button className={styles.refreshBtn} onClick={() => fetchPodsAndNamespaces(true)} disabled={loading}>
            <RefreshCw size={16} /> {loading ? 'Yenileniyor...' : 'Yenile'}
          </button>
        </div>
      </div>

      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Namespace</th>
              <th>Pod Adı</th>
              <th>Durum</th>
              <th>Başlangıç Zamanı</th>
              <th className={styles.actionCell}>İşlem</th>
            </tr>
          </thead>
          <tbody>
            {filteredPods.length === 0 ? (
              <tr>
                <td colSpan={5} className={styles.empty}>
                  {selectedNsFilter === 'all' 
                    ? 'Şu an çalışan herhangi bir pod bulunmuyor.'
                    : `"${selectedNsFilter}" namespace'inde çalışan pod bulunamadı.`}
                </td>
              </tr>
            ) : (
              filteredPods.map((pod, i) => {
                const podId = `${pod.namespace}/${pod.name}`;
                return (
                  <tr key={i}>
                    <td>{pod.namespace}</td>
                    <td>{pod.name}</td>
                    <td className={
                      pod.status === 'Running' ? styles.statusRunning : 
                      (pod.status === 'CrashLoopBackOff' || pod.status === 'Error' || pod.status === 'InvalidImageName') ? styles.statusCrashLoopBackOff : 
                      styles.statusPending
                    }>
                      {pod.status}
                    </td>
                    <td>{formatPodTime(pod.startTime)}</td>                   
                    <td className={styles.actionCell}>
                      {selectionMode ? (
                        <div className={styles.checkboxContainer}>
                          <input 
                            type="checkbox" 
                            className={styles.checkbox}
                            checked={selectedPods.has(podId)}
                            onChange={() => togglePodSelection(podId)}
                          />
                        </div>
                      ) : (
                        <button 
                          className={styles.deleteBtn}
                          onClick={() => handleDeleteSingle(pod.name, pod.namespace)}
                          title="Pod'u Sil"
                        >
                          <Trash2 size={16} />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
