import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
    './lib/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        ink: '#0a0e13',
        panel: '#10151c',
        panel2: '#151b24',
        panel3: '#1a222d',
        hair: '#222b38',
        hair2: '#2c3646',
        brand: {
          DEFAULT: '#22c55e',
          dim: '#16a34a',
          glow: 'rgba(34,197,94,0.35)',
        },
      },
      fontFamily: {
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          '"Liberation Mono"',
          'monospace',
        ],
      },
      boxShadow: {
        card: '0 10px 30px rgba(0,0,0,0.35)',
        glow: '0 0 0 1px rgba(34,197,94,0.65), 0 0 24px rgba(34,197,94,0.28)',
      },
      keyframes: {
        fadein: {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        popin: {
          '0%': { opacity: '0', transform: 'scale(0.97)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        blink: {
          '0%,100%': { opacity: '1' },
          '50%': { opacity: '0.25' },
        },
      },
      animation: {
        fadein: 'fadein 0.18s ease-out both',
        popin: 'popin 0.16s ease-out both',
        blink: 'blink 1.4s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};

export default config;
