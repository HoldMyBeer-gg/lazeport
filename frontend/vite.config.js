import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import deferCss from './vite-plugin-defer-css.js'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), deferCss()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/auth': 'http://127.0.0.1:8000',
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/echarts')) return 'echarts'
          if (id.includes('node_modules/vue') || id.includes('node_modules/vue-router') || id.includes('node_modules/@vue')) return 'vue'
          if (id.includes('node_modules/vue-i18n')) return 'vue-i18n'
        },
      },
    },
    chunkSizeWarningLimit: 600,
  },
})
