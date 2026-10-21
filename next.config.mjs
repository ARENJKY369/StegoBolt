/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  // Popup isolation — nothing to gain from cross-origin window.opener access.
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  // Note: no X-Frame-Options / frame-ancestors — StegoBolt has no backend session
  // to ride through frames by design, and it must stay embeddable in local
  // tooling / preview windows.
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "form-action 'none'",
      // Next.js ships inline bootstrap scripts and (in dev) eval'd bundles.
      // 'unsafe-inline'/'unsafe-eval' are scoped to same-origin code only —
      // no external script origins are permitted.
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' blob: data:",
      "media-src 'self' blob:",
      "font-src 'self' data:",
      // LSB work runs in an inline Blob Web Worker.
      "worker-src 'self' blob:",
      // User data only goes to the explicitly configured Java engine: local
      // development ports or an HTTPS deployment, plus the HMR websocket.
      "connect-src 'self' ws: http://localhost:* http://127.0.0.1:* https:",
      "frame-src 'self'",
    ].join('; '),
  },
];

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};

export default nextConfig;
