import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/scenario': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/detection': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/attribution': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/attack': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/traceback': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/logs': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/behavior': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/traffic': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/dashboard': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: resolve(__dirname, '../xiaoxueqi/static/spa'),
    emptyOutDir: true,
  },
})
