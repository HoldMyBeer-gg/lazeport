import { reactive } from 'vue'
import { request } from '../services/api'

const THEMES = [
  { id: 'system', labelKey: 'themes.system', swatch: 'linear-gradient(135deg, #06060b 50%, #ffffff 50%)' },
  { id: 'terminal', labelKey: 'themes.terminal', swatch: 'linear-gradient(135deg, #06060b 70%, #00ffa3 100%)' },
  { id: 'light', labelKey: 'themes.light', swatch: '#ffffff' },
  { id: 'dark', labelKey: 'themes.dark', swatch: '#002b36' },
  { id: 'ghost', labelKey: 'themes.ghost', swatch: 'linear-gradient(135deg, #0c0c0c 70%, #fb7185 100%)' },
]

const state = reactive({
  current: localStorage.getItem('lazeport_theme') || 'terminal',
})

// Track the media query for OS preference
let _mql = null

function _getSystemTheme() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function _resolveTheme(theme) {
  return theme === 'system' ? _getSystemTheme() : theme
}

function applyTheme(theme) {
  state.current = theme
  localStorage.setItem('lazeport_theme', theme)
  // Apply the resolved theme to the DOM
  document.documentElement.setAttribute('data-theme', _resolveTheme(theme))
  _syncSystemListener()
}

function _syncSystemListener() {
  // If "system" is active, listen for OS changes; otherwise, remove the listener
  if (state.current === 'system') {
    if (!_mql) {
      _mql = window.matchMedia('(prefers-color-scheme: dark)')
      _mql._handler = () => {
        if (state.current === 'system') {
          document.documentElement.setAttribute('data-theme', _getSystemTheme())
        }
      }
      _mql.addEventListener('change', _mql._handler)
    }
  } else {
    if (_mql) {
      _mql.removeEventListener('change', _mql._handler)
      _mql = null
    }
  }
}

async function setTheme(theme) {
  applyTheme(theme)
  try {
    await request('/api/admin/profile', {
      method: 'PUT',
      body: JSON.stringify({ theme }),
    })
  } catch {
    // Best-effort persist; localStorage already saved
  }
}

async function loadTheme() {
  // Apply cached theme immediately to prevent flash
  applyTheme(state.current)
  try {
    const data = await request('/api/admin/profile')
    if (data.theme && data.theme !== state.current) {
      applyTheme(data.theme)
    }
  } catch {
    // Stick with localStorage value
  }
}

export { THEMES, state, applyTheme, setTheme, loadTheme }
