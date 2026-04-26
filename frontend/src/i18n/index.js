import { createI18n } from 'vue-i18n'
import en from './locales/en.json'

const STORAGE_KEY = 'laze-locale'

export const LOCALES = [
  { id: 'en', label: 'English', dir: 'ltr' },
  { id: 'de', label: 'Deutsch', dir: 'ltr' },
  { id: 'he', label: 'עברית', dir: 'rtl' },
  { id: 'es-419', label: 'Español (Latinoamérica)', dir: 'ltr' },
  { id: 'zh-CN', label: '简体中文', dir: 'ltr' },
]

function savedLocale() {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v && LOCALES.some(l => l.id === v)) return v
  } catch { /* ignore */ }
  return 'en'
}

// en is always available (static import); others are loaded on demand.
const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: { en },
})

const _loaded = new Set(['en'])

// Dynamic imports keyed by locale id. Vite statically analyses these at build
// time and emits each locale JSON as its own chunk.
const _loaders = {
  'de':    () => import('./locales/de.json'),
  'he':    () => import('./locales/he.json'),
  'es-419': () => import('./locales/es-419.json'),
  'zh-CN': () => import('./locales/zh-CN.json'),
}

async function _loadLocaleMessages(id) {
  if (_loaded.has(id)) return
  const loader = _loaders[id]
  if (!loader) return
  const messages = await loader()
  i18n.global.setLocaleMessage(id, messages.default)
  _loaded.add(id)
}

function _applyDOM(id) {
  const loc = LOCALES.find(l => l.id === id)
  if (!loc) return
  document.documentElement.lang = id
  document.documentElement.dir = loc.dir
}

/**
 * Switch locale atomically: messages are fully loaded before the locale ref
 * is updated, so no component ever renders with missing translations.
 */
export async function setLocale(id) {
  if (!LOCALES.some(l => l.id === id)) return
  await _loadLocaleMessages(id)
  i18n.global.locale.value = id
  try { localStorage.setItem(STORAGE_KEY, id) } catch { /* ignore */ }
  _applyDOM(id)
}

/**
 * Must be awaited in main.js before app.mount(). Loads the user's saved locale
 * before the first render so no component ever sees missing translation keys.
 */
export async function initLocale() {
  const id = savedLocale()
  await _loadLocaleMessages(id)
  i18n.global.locale.value = id
  _applyDOM(id)
}

export default i18n
