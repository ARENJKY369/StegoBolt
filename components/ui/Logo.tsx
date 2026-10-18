'use client';

/**
 * StegoBolt brand mark — a hand-built SVG: a security shield carrying a
 * lightning bolt (the "Bolt") knocked out in negative space, with two pixel
 * squares trailing from its tip (the hidden LSB payload). Vector-crisp at
 * every size, matches the app's emerald identity, zero external assets.
 */

import { useId } from 'react';
import { FAVICON_SVG, FAVICON_URL } from '@/lib/brand';

export function LogoMark({ size = 26, className = '' }: { size?: number; className?: string }) {
  const uid = useId().replace(/[^a-zA-Z0-9_-]/g, '');
  const grad = `sbg-${uid}`;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      role="img"
      aria-label="StegoBolt logo"
      className={className}
    >
      <defs>
        <linearGradient id={grad} x1="6.5" y1="5.5" x2="33.5" y2="37" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#4ade80" />
          <stop offset="0.55" stopColor="#22c55e" />
          <stop offset="1" stopColor="#15803d" />
        </linearGradient>
      </defs>
      {/* shield */}
      <path
        d="M20 5.5 L33.5 10.4 L33.5 21.2 C33.5 28.2 28.5 33.6 20 37.1 C11.5 33.6 6.5 28.2 6.5 21.2 L6.5 10.4 Z"
        fill={`url(#${grad})`}
        stroke="#86efac"
        strokeOpacity="0.35"
        strokeWidth="0.9"
        strokeLinejoin="round"
      />
      {/* bolt (negative space) */}
      <path
        d="M23.4 12 L14.6 23.4 L19.2 23.4 L17.6 30.6 L26.4 19.2 L21.8 19.2 Z"
        fill="#0a0e13"
      />
      {/* hidden pixel bits trailing from the strike */}
      <rect x="27" y="21.4" width="2.5" height="2.5" rx="0.6" fill="#ffffff" opacity="0.92" />
      <rect x="29.6" y="25" width="1.7" height="1.7" rx="0.45" fill="#ffffff" opacity="0.5" />
    </svg>
  );
}

/** Full horizontal lockup: mark + wordmark. */
export function Logo({ size = 26 }: { size?: number }) {
  return (
    <span className="flex items-center gap-2">
      <LogoMark size={size} />
      <span className="text-[16.5px] font-bold tracking-tight text-slate-100">StegoBolt</span>
    </span>
  );
}

/** Re-exported for convenience — canonical source lives in lib/brand.ts */
export { FAVICON_SVG, FAVICON_URL };
