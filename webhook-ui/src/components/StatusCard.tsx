'use client';
import { CheckCircle, XCircle } from 'lucide-react';
import styles from './StatusCard.module.css';

interface StatusCardProps {
  status: 'idle' | 'success' | 'error';
  message: string;
}

export function StatusCard({ status, message }: StatusCardProps) {
  if (status === 'idle') return null;

  const isSuccess = status === 'success';

  return (
    <div className={`${styles.card} ${isSuccess ? styles.success : styles.error}`}>
      <div className={styles.icon}>
        {isSuccess ? <CheckCircle size={20} /> : <XCircle size={20} />}
      </div>
      <div className={styles.content}>
        <div className={styles.title}>{isSuccess ? 'Admission Allowed' : 'Admission Denied'}</div>
        <div className={styles.message}>{message}</div>
      </div>
    </div>
  );
}
