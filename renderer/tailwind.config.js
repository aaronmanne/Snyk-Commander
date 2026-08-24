/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Solarized Dark color scheme
        bg: {
          primary: '#002b36',    // base03
          secondary: '#073642',  // base02
          tertiary: '#0d4552',   // slightly lighter than base02
        },
        border: {
          DEFAULT: '#586e75',    // base01
          light: '#657b83',      // base00
        },
        accent: {
          purple: '#6c71c4',     // violet
          'purple-light': '#8b90d4',
          'purple-dim': '#4c51a4',
          green: '#859900',      // green
          'green-dim': '#586e00',
          blue: '#268bd2',       // blue
          cyan: '#2aa198',       // cyan
          yellow: '#b58900',     // yellow
          orange: '#cb4b16',     // orange
          red: '#dc322f',        // red
          magenta: '#d33682',    // magenta
        },
        severity: {
          critical: '#dc322f',   // red
          high: '#cb4b16',       // orange
          medium: '#b58900',     // yellow
          low: '#586e75',        // base01
        },
        text: {
          primary: '#fdf6e3',    // base3
          secondary: '#93a1a1',  // base1
          muted: '#839496',      // base0
        }
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 2s linear infinite',
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
