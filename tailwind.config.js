/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        primary: '#a855f7',
        secondary: '#6366f1',
        accent: '#00ff88',
        dark: {
          100: '#1a1a2e',
          200: '#16213e',
          300: '#0a0e17',
        },
      },
    },
  },
  plugins: [],
};
