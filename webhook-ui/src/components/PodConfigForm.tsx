'use client';

import { useState, useEffect } from 'react';
import styles from './PodConfigForm.module.css';
import { Select, Toggle, ComboBox } from './FormControls';

export interface PodConfig {
  namespace: string;
  image: string;
  runAsRoot: boolean;
  runAsNonRoot: boolean;
  privileged: boolean;
  allowPrivilegeEscalation: boolean;
  volumeType: string;
  pvcName: string;
  useNativeSecret: boolean;
  vaultAnnotations: boolean;
  includeResources: boolean;
  cpuRequest: string;
  memoryRequest: string;
  cpuLimit: string;
  memoryLimit: string;
}

interface PodConfigFormProps {
  onSubmit: (config: PodConfig) => void;
  loading: boolean;
}

export function PodConfigForm({ onSubmit, loading }: PodConfigFormProps) {
  const [namespaces, setNamespaces] = useState<{label: string, value: string}[]>([
    {label: 'dev', value: 'dev'},
    {label: 'test', value: 'test'},
    {label: 'default', value: 'default'}
  ]);

  const [config, setConfig] = useState<PodConfig>({
    namespace: 'dev',
    image: 'latest',
    runAsRoot: false,
    runAsNonRoot: true,
    privileged: false,
    allowPrivilegeEscalation: false,
    volumeType: 'none',
    pvcName: 'longhorn-pvc',
    useNativeSecret: false,
    vaultAnnotations: true,
    includeResources: true,
    cpuRequest: '100',
    memoryRequest: '128',
    cpuLimit: '200',
    memoryLimit: '256'
  });

  useEffect(() => {
    // Dinamik olarak Kubernetes'ten tüm namaspace'leri çek
    const fetchNamespaces = async () => {
      try {
        const res = await fetch('/api/namespaces');
        const data = await res.json();
        if (data.namespaces && Array.isArray(data.namespaces)) {
          const nsOptions = data.namespaces.map((ns: string) => ({
            label: ns,
            value: ns
          }));
          setNamespaces(nsOptions);
        }
      } catch (e) {
        console.error("Namespace'ler çekilemedi:", e);
      }
    };
    fetchNamespaces();
  }, []);

  const handleChange = (key: keyof PodConfig, value: any) => {
    setConfig(prev => ({ ...prev, [key]: value }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(config);
  };

  const generateYaml = () => {
    let yaml = `kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: ${config.namespace}
  labels:
    app: webhook-test
spec:
  securityContext:
${config.runAsRoot ? '    runAsUser: 0\n' : ''}${config.runAsNonRoot ? '    runAsNonRoot: true\n' : ''}  containers:
    - name: test-container
      image: ${config.image === 'unprivileged' ? 'nginxinc/nginx-unprivileged:alpine' : config.image === 'latest' ? 'nginx:latest' : config.image === 'alpine' ? 'nginx:alpine' : config.image}`;

    const containerScProps = [];
    if (config.runAsNonRoot) containerScProps.push('        runAsNonRoot: true');
    if (config.privileged) containerScProps.push('        privileged: true');
    if (config.allowPrivilegeEscalation) containerScProps.push('        allowPrivilegeEscalation: true');

    if (containerScProps.length > 0) {
      yaml += `\n      securityContext:\n${containerScProps.join('\n')}`;
    }

    if (config.includeResources) {
      yaml += `\n      resources:
        requests:
          cpu: ${config.cpuRequest}m
          memory: ${config.memoryRequest}Mi
        limits:
          cpu: ${config.cpuLimit}m
          memory: ${config.memoryLimit}Mi`;
    }

    if (config.volumeType !== 'none') {
      yaml += `\n      volumeMounts:\n        - name: test-vol\n          mountPath: /data`;
      yaml += `\n  volumes:\n    - name: test-vol`;
      if (config.volumeType === 'emptyDir') yaml += `\n      emptyDir: {}`;
      if (config.volumeType === 'hostPath') yaml += `\n      hostPath:\n        path: /tmp/test`;
      if (config.volumeType === 'pvc') yaml += `\n      persistentVolumeClaim:\n        claimName: ${config.pvcName}`;
    }

    yaml += `\nEOF`;

    return yaml;
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generateYaml());
    alert("YAML panoya kopyalandı!");
  };

  return (
    <form className={styles.form} onSubmit={handleSubmit}>
      <div className={styles.formLayout}>
        <div className={styles.formFields}>
      <div className={styles.section}>
        <div className={styles.sectionTitle}>Genel Ayarlar</div>
        <Select 
          label="Namespace" 
          options={namespaces} 
          value={config.namespace} 
          onChange={v => handleChange('namespace', v)} 
        />
        <ComboBox 
          label="Image Tag (Seç veya Yaz)" 
          options={[
            {label: 'nginx:latest (Standart)', value: 'latest'}, 
            {label: 'nginx:alpine (Hafif)', value: 'alpine'},
            {label: 'nginx-unprivileged (Non-Root İçin)', value: 'unprivileged'}
          ]} 
          value={config.image} 
          onChange={v => handleChange('image', v)} 
        />
      </div>

      <div className={styles.section}>
        <div className={styles.sectionTitle}>Güvenlik</div>
        <Toggle 
          title="Root Olarak Çalıştır (runAsUser: 0)" 
          active={config.runAsRoot} 
          onChange={v => handleChange('runAsRoot', v)} 
        />
        <Toggle 
          title="runAsNonRoot: true" 
          active={config.runAsNonRoot} 
          onChange={v => handleChange('runAsNonRoot', v)} 
        />
        <Toggle 
          title="Privileged Container" 
          active={config.privileged} 
          onChange={v => handleChange('privileged', v)} 
        />
        <Toggle 
          title="Allow Privilege Escalation" 
          active={config.allowPrivilegeEscalation} 
          onChange={v => handleChange('allowPrivilegeEscalation', v)} 
        />
      </div>

      <div className={styles.section}>
        <div className={styles.sectionTitle}>Depolama & Volumes</div>
        <Select 
          label="Volume Tipi" 
          options={[
            {label: 'Yok', value: 'none'}, 
            {label: 'emptyDir', value: 'emptyDir'}, 
            {label: 'hostPath', value: 'hostPath'}, 
            {label: 'PersistentVolumeClaim (PVC)', value: 'pvc'}
          ]} 
          value={config.volumeType} 
          onChange={v => handleChange('volumeType', v)} 
        />
        {config.volumeType === 'pvc' && (
          <Select 
            label="PVC StorageClass" 
            options={[{label: 'longhorn-pvc', value: 'longhorn-pvc'}, {label: 'standard-pvc', value: 'standard-pvc'}]} 
            value={config.pvcName} 
            onChange={v => handleChange('pvcName', v)} 
          />
        )}
      </div>

      <div className={styles.section}>
        <div className={styles.sectionTitle}>Kaynak Yönetimi</div>
        <Toggle 
          title="CPU & Memory Limits/Requests Ekle" 
          active={config.includeResources} 
          onChange={v => handleChange('includeResources', v)} 
        />
        {config.includeResources && (
          <div className={styles.resourceInputs}>
            <div className={styles.resourceRow}>
              <div className={styles.resourceGroup}>
                <label>CPU Request</label>
                <div className={styles.inputWithUnit}>
                  <input type="number" value={config.cpuRequest} onChange={e => handleChange('cpuRequest', e.target.value)} />
                  <span className={styles.unit}>m</span>
                </div>
              </div>
              <div className={styles.resourceGroup}>
                <label>Memory Request</label>
                <div className={styles.inputWithUnit}>
                  <input type="number" value={config.memoryRequest} onChange={e => handleChange('memoryRequest', e.target.value)} />
                  <span className={styles.unit}>Mi</span>
                </div>
              </div>
            </div>
            <div className={styles.resourceRow}>
              <div className={styles.resourceGroup}>
                <label>CPU Limit</label>
                <div className={styles.inputWithUnit}>
                  <input type="number" value={config.cpuLimit} onChange={e => handleChange('cpuLimit', e.target.value)} />
                  <span className={styles.unit}>m</span>
                </div>
              </div>
              <div className={styles.resourceGroup}>
                <label>Memory Limit</label>
                <div className={styles.inputWithUnit}>
                  <input type="number" value={config.memoryLimit} onChange={e => handleChange('memoryLimit', e.target.value)} />
                  <span className={styles.unit}>Mi</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <button type="submit" className={styles.submitBtn} disabled={loading}>
        {loading ? 'İstek Gönderiliyor...' : 'Pod Oluştur (Test Et)'}
      </button>

        </div>

        <div className={styles.yamlSide}>
          <div className={styles.yamlPreviewContainer}>
            <div className={styles.yamlHeader}>
              <span>YAML Önizleme</span>
              <button type="button" className={styles.copyBtn} onClick={copyToClipboard}>
                Kopyala
              </button>
            </div>
            <pre className={styles.yamlCode}>{generateYaml()}</pre>
          </div>
        </div>
      </div>
    </form>
  );
}
