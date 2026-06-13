'use client';
import { useState, useRef, useEffect } from 'react';
import styles from './FormControls.module.css';

export function Select({ label, options, value, onChange, className, wrapperClassName }: { label?: string, options: {label: string, value: string}[], value: string, onChange: (val: string) => void, className?: string, wrapperClassName?: string }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const selectedOption = options.find(opt => opt.value === value) || options[0];

  return (
    <div className={`${styles.formGroup} ${wrapperClassName || ''}`} ref={dropdownRef}>
      {label && <label className={styles.label}>{label}</label>}
      <div className={styles.customSelectWrapper}>
        <div 
          className={`${styles.select} ${className || ''}`} 
          onClick={() => setIsOpen(!isOpen)}
        >
          <span>{selectedOption ? selectedOption.label : 'Seçiniz...'}</span>
          <span className={styles.chevron} style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0)' }}>▼</span>
        </div>
        
        {isOpen && (
          <div className={styles.optionsMenu}>
            {options.map(opt => (
              <div 
                key={opt.value} 
                className={`${styles.optionItem} ${value === opt.value ? styles.selectedOption : ''}`}
                onClick={() => {
                  onChange(opt.value);
                  setIsOpen(false);
                }}
              >
                {opt.label}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function ComboBox({ label, options, value, onChange, className, wrapperClassName }: { label?: string, options: {label: string, value: string}[], value: string, onChange: (val: string) => void, className?: string, wrapperClassName?: string }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className={`${styles.formGroup} ${wrapperClassName || ''}`} ref={dropdownRef}>
      {label && <label className={styles.label}>{label}</label>}
      <div className={styles.customSelectWrapper}>
        <div className={`${styles.comboBoxInputWrapper} ${className || ''}`}>
          <input 
            type="text" 
            className={styles.comboBoxInput}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onFocus={() => setIsOpen(true)}
            placeholder="İmaj adı yazın veya seçin..."
          />
          <div 
             className={styles.comboBoxChevron} 
             onClick={() => setIsOpen(!isOpen)}
          >
            <span className={styles.chevron} style={{ transform: isOpen ? 'rotate(180deg)' : 'rotate(0)' }}>▼</span>
          </div>
        </div>
        
        {isOpen && (
          <div className={styles.optionsMenu}>
            {options.map(opt => (
              <div 
                key={opt.value} 
                className={styles.optionItem}
                onClick={() => {
                  onChange(opt.value);
                  setIsOpen(false);
                }}
              >
                {opt.label}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function Toggle({ title, description, active, onChange }: { title: string, description?: string, active: boolean, onChange: (val: boolean) => void }) {
  return (
    <div className={styles.toggleContainer} onClick={() => onChange(!active)}>
      <div className={styles.toggleInfo}>
        <span className={styles.toggleTitle}>{title}</span>
        {description && <span className={styles.toggleDesc}>{description}</span>}
      </div>
      <div className={`${styles.switch} ${active ? styles.active : ''}`}>
        <div className={styles.switchHandle} />
      </div>
    </div>
  );
}
