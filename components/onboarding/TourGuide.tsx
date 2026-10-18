'use client';

/**
 * Interactive 5-step onboarding tour (§3.1) — custom React-Portal popovers
 * with a spotlight cut-out overlay, exactly like driver.js but dependency-free
 * and offline-safe. Auto-launches on first login; re-playable from Settings.
 */

import { useEffect, useState, type CSSProperties } from 'react';
import { createPortal } from 'react-dom';

interface TourStep {
  target: string;
  title: string;
  body: string;
}

export const TOUR_STEPS: TourStep[] = [
  {
    target: '#sb-switcher',
    title: 'Step 1 of 5: Mode Switcher',
    body: 'Toggle between Hide, Extract, Scan, and Clean to switch the operational panel. Every mode keeps its own pipeline, and results always stay in this tab.',
  },
  {
    target: '#sb-dropzone',
    title: 'Step 2 of 5: Cover Dropzone',
    body: 'Drag cover images or audio here. StegoBolt instantly computes the SHA-256 hash so you can verify the exact carrier you are working on before and after embedding.',
  },
  {
    target: '#sb-security',
    title: 'Step 3 of 5: Security & Encryption',
    body: 'Configure payload security with encryption, passwords, and advanced stego-algorithms.',
  },
  {
    target: '#sb-backup',
    title: 'Step 4 of 5: Local Vault & PC Backup',
    body: 'History lives in IndexedDB on your machine. Point StegoBolt at a folder on your hard drive (C:\\Users\\you\\Documents\\StegoVault or /Users/…) for direct PC backups you fully own.',
  },
  {
    target: '#sb-hexbtn',
    title: 'Step 5 of 5: Hex Inspector',
    body: 'Open the footer console to reveal the low-level byte drawer: hexadecimal dumps and the LSB binary view of whatever file you just processed. Volatile RAM — flushed on lock.',
  },
];

const POPOVER_W = 330;
const POPOVER_EST_H = 196;

export function TourGuide({ active, onDone }: { active: boolean; onDone: () => void }) {
  const [step, setStep] = useState(0);
  const [rect, setRect] = useState<DOMRect | null>(null);

  useEffect(() => {
    if (active) setStep(0);
  }, [active]);

  useEffect(() => {
    if (!active || typeof document === 'undefined') return;
    const cur = TOUR_STEPS[step];
    let tries = 0;
    let raf = 0;
    const measure = () => {
      const el = document.querySelector(cur.target);
      if (el) {
        setRect(el.getBoundingClientRect());
        return true;
      }
      return false;
    };
    const poll = () => {
      if (!measure() && tries++ < 24) raf = window.setTimeout(poll, 120);
    };
    poll();
    const onMove = () => measure();
    window.addEventListener('resize', onMove);
    window.addEventListener('scroll', onMove, true);
    return () => {
      window.removeEventListener('resize', onMove);
      window.removeEventListener('scroll', onMove, true);
      window.clearTimeout(raf);
    };
  }, [active, step]);

  if (!active || typeof document === 'undefined') return null;

  const s = TOUR_STEPS[step];
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const last = step === TOUR_STEPS.length - 1;

  let popStyle: CSSProperties;
  if (rect) {
    const left = Math.max(12, Math.min(vw - POPOVER_W - 12, rect.left + rect.width / 2 - POPOVER_W / 2));
    const below = rect.bottom + POPOVER_EST_H + 26 < vh;
    const top = below ? rect.bottom + 14 : Math.max(12, rect.top - POPOVER_EST_H - 14);
    popStyle = { position: 'fixed', top, left, width: POPOVER_W };
  } else {
    popStyle = { position: 'fixed', top: vh / 2 - POPOVER_EST_H / 2, left: vw / 2 - POPOVER_W / 2, width: POPOVER_W };
  }

  const highlight = rect && {
    position: 'fixed' as const,
    top: rect.top - 8,
    left: rect.left - 8,
    width: rect.width + 16,
    height: rect.height + 16,
    borderRadius: 14,
    boxShadow:
      '0 0 0 9999px rgba(2,5,9,0.78), 0 0 0 2px rgba(34,197,94,0.9), 0 0 34px rgba(34,197,94,0.35)',
  };

  return createPortal(
    <div className="z-[80]">
      {/* click-catcher so the app can't be operated mid-step */}
      <div className="fixed inset-0" onClick={(e) => e.stopPropagation()} />
      {highlight && <div aria-hidden className="pointer-events-none fixed transition-all duration-300" style={highlight} />}
      <div style={popStyle} className="pointer-events-auto fixed animate-popin rounded-xl border border-brand/50 bg-[#0d1219] p-4 shadow-[0_0_0_1px_rgba(34,197,94,0.25),0_24px_70px_rgba(0,0,0,0.65)]">
        <h3 className="text-[13.5px] font-bold text-slate-100">{s.title}</h3>
        <p className="mt-1.5 text-[12px] leading-relaxed text-slate-400">{s.body}</p>
        <div className="mt-4 flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            {TOUR_STEPS.map((_, i) => (
              <span
                key={i}
                className={`h-1.5 rounded-full transition-all ${
                  i === step ? 'w-4 bg-brand' : i < step ? 'w-1.5 bg-brand/50' : 'w-1.5 bg-[#2a3444]'
                }`}
              />
            ))}
            <span className="ml-1.5 text-[10px] font-medium text-slate-500">{step + 1} of {TOUR_STEPS.length}</span>
          </div>
          <div className="flex items-center gap-1.5">
            {step > 0 && (
              <button onClick={() => setStep((v) => v - 1)} className="btn-ghost !px-2 !py-1 text-[11px]">
                Back
              </button>
            )}
            <button onClick={onDone} className="btn-ghost !px-2 !py-1 text-[11px]">
              Skip
            </button>
            <button
              onClick={() => (last ? onDone() : setStep((v) => v + 1))}
              className="btn-green !px-4 !py-1.5 !text-[11px] normal-case tracking-normal"
            >
              {last ? 'Finish' : 'Next'}
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}
