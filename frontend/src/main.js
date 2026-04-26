import { createApp } from 'vue'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-sans/700.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import '@fontsource/ibm-plex-mono/600.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/600.css'
import './style.css'
import App from './App.vue'
import router from './router'
import i18n, { initLocale } from './i18n'

// initLocale() must resolve before mount() so no component ever renders
// with missing translation keys. Wrapped in an async IIFE because the
// Vite build target (es2020) does not support top-level await.
;(async () => {
  const app = createApp(App).use(router).use(i18n)
  await initLocale()
  app.mount('#app')
})()
