import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The bridge serves dist/ in the demo. In `npm run dev`, proxy the stream to it
// so the dev server and the built console behave identically.
export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': { target: 'http://127.0.0.1:8765', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', emptyOutDir: true },
});
