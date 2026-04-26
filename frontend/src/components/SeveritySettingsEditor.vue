<script setup>
import { onMounted, ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { marked } from 'marked'
import { request } from '../services/api'
import { setStatus } from '../stores/status'
import Modal from './Modal.vue'

const { t } = useI18n()


const props = defineProps({
  orgId: {
    type: String,
    required: true,
  },
  show: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['close'])

// Severity levels in order
const SEVERITY_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Informational']

// Form state
const criteria = ref({})
const originalCriteria = ref({})
const loading = ref(true)
const saving = ref(false)
const errors = ref({})
const expandedLevel = ref(null)

// Editor state
const unsavedChanges = computed(() => {
  return JSON.stringify(criteria.value) !== JSON.stringify(originalCriteria.value)
})

// Load severity criteria from API
async function loadCriteria() {
  loading.value = true
  errors.value = {}
  try {
    if (!props.orgId) {
      console.error('No orgId provided to SeveritySettingsEditor')
      loading.value = false
      return
    }

    const response = await request(`/api/orgs/${props.orgId}/severity-settings`)

    criteria.value = response.severity_criteria || {}

    originalCriteria.value = JSON.parse(JSON.stringify(response.severity_criteria || {}))
  } catch (e) {
    console.error('Failed to load severity criteria:', e)
    setStatus(t('severity.loadFailed') + ': ' + (e.message || 'Unknown error'), 'error')
  } finally {
    loading.value = false
  }
}

// Validate criteria
function validateCriteria() {
  errors.value = {}
  let valid = true

  // Check all 5 levels exist
  const missing = SEVERITY_LEVELS.filter(l => !criteria.value[l])
  if (missing.length > 0) {
    setStatus(t('severity.validation.allLevelsRequired'), 'error')
    valid = false
  }

  // Check no extra levels
  const extra = Object.keys(criteria.value).filter(k => !SEVERITY_LEVELS.includes(k))
  if (extra.length > 0) {
    errors.value = { ...errors.value, extra: t('severity.validation.invalidLevels', { levels: extra.join(', ') }) }
    valid = false
  }

  // Check each definition
  for (const level of SEVERITY_LEVELS) {
    const def = criteria.value[level]
    if (!def) continue

    if (typeof def !== 'string') {
      errors.value[level] = t('severity.validation.mustBeString')
      valid = false
    } else if (def.trim().length === 0) {
      errors.value[level] = t('severity.validation.cannotBeEmpty')
      valid = false
    } else if (def.length > 2000) {
      errors.value[level] = t('severity.validation.maxLength', { max: 2000 })
      valid = false
    }
  }

  return valid
}

// Save criteria
async function saveCriteria() {
  if (!validateCriteria()) return

  saving.value = true
  try {
    await request(`/api/orgs/${props.orgId}/severity-settings`, {
      method: 'PUT',
      body: JSON.stringify({ severity_criteria: criteria.value }),
    })
    originalCriteria.value = JSON.parse(JSON.stringify(criteria.value))
    expandedLevel.value = null
    setStatus(t('severity.saved'), 'success')
  } catch (e) {
    setStatus(e.message || t('severity.saveFailed'), 'error')
    console.error(e)
  } finally {
    saving.value = false
  }
}

// Cancel editing
function cancelEdit() {
  criteria.value = JSON.parse(JSON.stringify(originalCriteria.value))
  errors.value = {}
  expandedLevel.value = null
  emit('close')
}

// Generate preview document with markdown rendered and styled
function generatePreviewDoc(text) {
  if (!text) return ''
  try {
    const html = marked(text, { breaks: true, gfm: true })
    // Escape backticks and special chars for safe srcdoc injection
    const safe = html.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$')
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; margin: 12px; font-size: 13px; }
    h1, h2, h3, h4, h5, h6 { margin: 12px 0 6px 0; }
    h1 { font-size: 18px; }
    h2 { font-size: 16px; }
    h3 { font-size: 14px; }
    p { margin: 6px 0; }
    ul, ol { margin: 6px 0; padding-left: 20px; }
    li { margin: 3px 0; }
    code { background: #f5f5f5; padding: 2px 4px; border-radius: 2px; font-family: monospace; font-size: 12px; }
    pre { background: #f5f5f5; padding: 8px; border-radius: 4px; overflow-x: auto; }
    pre code { background: none; padding: 0; }
    blockquote { margin: 8px 0; padding-left: 12px; border-left: 3px solid #ddd; color: #666; }
    a { color: #0066cc; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>${safe}</body>
</html>`
  } catch (e) {
    console.error('Failed to generate preview:', e)
    return `<!DOCTYPE html><html><body style="padding: 12px; color: #999;">Error rendering preview</body></html>`
  }
}

onMounted(() => {
  if (props.show) {
    loadCriteria()
  }
})

watch(() => props.orgId, () => {
  if (props.show) {
    loadCriteria()
  }
}, { immediate: false })

watch(() => props.show, (newVal) => {
  if (newVal) {
    loadCriteria()
  }
}, { immediate: false })
</script>

<template>
  <Modal :show="props.show" @close="emit('close')" :title="t('severity.title')" :extra-wide="true">
    <div class="severity-settings-editor">
      <!-- Loading state -->
      <div v-if="loading" class="loading-spinner">
        {{ t('common.loading') }}
      </div>

    <!-- Content -->
    <div v-else>
      <!-- Header -->
      <div class="settings-header">
        <h3>{{ t('severity.title') }}</h3>
        <p class="description">{{ t('severity.description') }}</p>
      </div>

      <!-- Expandable cards per severity level -->
      <div class="criteria-section">
        <div v-for="level in SEVERITY_LEVELS" :key="level" :class="['severity-card', level.toLowerCase(), { expanded: expandedLevel === level }]">
          <!-- Card header (always visible) -->
          <div class="card-header" @click="expandedLevel = expandedLevel === level ? null : level">
            <div class="card-title">
              <span class="toggle-icon">{{ expandedLevel === level ? '▼' : '▶' }}</span>
              <h4>{{ level }}</h4>
            </div>
            <div class="card-summary">{{ criteria[level] ? criteria[level].substring(0, 60) + (criteria[level].length > 60 ? '...' : '') : '—' }}</div>
          </div>

          <!-- Card content (expanded view with split pane) -->
          <div v-if="expandedLevel === level" class="card-content">
            <div class="split-pane">
              <!-- Left: Editor -->
              <div class="pane-left">
                <div class="pane-label">{{ t('severity.editor') }}</div>
                <textarea
                  v-model="criteria[level]"
                  :placeholder="t('severity.definitionPlaceholder')"
                  rows="8"
                  maxlength="2000"
                  :class="{ error: errors[level] }"
                  class="editor-textarea"
                />
                <div v-if="errors[level]" class="error-message">{{ errors[level] }}</div>
                <div class="char-count">
                  {{ (criteria[level] || '').length }} / 2000
                </div>
              </div>

              <!-- Right: Preview -->
              <div class="pane-right">
                <div class="preview-label">{{ t('severity.preview') }}</div>
                <iframe
                  v-if="criteria[level]"
                  :srcdoc="generatePreviewDoc(criteria[level])"
                  class="preview-iframe"
                  title="Preview"
                />
                <div v-else class="no-definition">{{ t('severity.noDefinition') }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Validation errors -->
        <div v-if="errors.extra" class="validation-error">
          {{ errors.extra }}
        </div>

        <!-- Action buttons -->
        <div class="button-group">
          <button class="btn btn-primary" @click="saveCriteria" :disabled="!unsavedChanges || saving">
            {{ saving ? t('common.saving') : t('severity.save') }}
          </button>
          <button class="btn btn-secondary" @click="cancelEdit" :disabled="saving">
            {{ t('severity.cancel') }}
          </button>
        </div>
      </div>
    </div>
    </div>
  </Modal>
</template>

<style scoped>
.severity-settings-editor {
  padding: 20px 0;
}

.settings-header {
  margin-bottom: 30px;
}

.settings-header h3 {
  margin: 0 0 10px 0;
  font-size: 18px;
  font-weight: 600;
}

.description {
  margin: 0;
  color: var(--text-secondary);
  font-size: 14px;
}

.loading-spinner {
  text-align: center;
  padding: 40px;
  color: var(--text-secondary);
}

/* Expandable Cards */
.criteria-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 20px;
}

.severity-card {
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
  background: var(--bg-card);
}

.severity-card.critical {
  border-color: var(--sev-critical-bg);
}

.severity-card.high {
  border-color: var(--sev-high-bg);
}

.severity-card.medium {
  border-color: var(--sev-medium-bg);
}

.severity-card.low {
  border-color: var(--sev-low-bg);
}

.severity-card.informational {
  border-color: var(--sev-info-bg);
}

.card-header {
  padding: 14px;
  cursor: pointer;
  user-select: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  transition: background 0.2s;
}

.card-header:hover {
  opacity: 0.8;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
}

.toggle-icon {
  font-size: 12px;
  color: var(--text-secondary);
  width: 16px;
  text-align: center;
}

.card-title h4 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}

.card-summary {
  font-size: 13px;
  color: var(--text-secondary);
  flex: 1;
  text-align: right;
  max-width: 300px;
}

.card-content {
  padding: 0 14px 14px 14px;
  border-top: 1px solid var(--border);
}

/* Split Pane */
.split-pane {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  min-height: 350px;
  margin-top: 1em;
}

.pane-left,
.pane-right {
  display: flex;
  flex-direction: column;
}

.editor-textarea {
  padding: 10px;
  border: 1px solid var(--border-focus);
  border-radius: 4px;
  background: var(--bg-input);
  color: var(--text-primary);
  font-family: monospace;
  font-size: 12px;
  resize: vertical;
  flex: 1;
}

.editor-textarea:focus {
  outline: none;
  border-color: var(--border-focus);
  box-shadow: 0 0 0 2px var(--border-focus)22;
}

.editor-textarea.error {
  border-color: var(--danger);
}

.error-message {
  font-size: 12px;
  color: var(--danger);
  margin-top: 4px;
}

.char-count {
  font-size: 11px;
  color: var(--text-muted);
  text-align: right;
  margin-top: 4px;
}

.pane-right {
  border-left: 1px solid var(--border);
  padding-left: 20px;
}

.pane-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: 8px;
}

.preview-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: 8px;
}

.preview-iframe {
  width: 100%;
  height: 100%;
  border: 1px solid var(--border);
  border-radius: 4px;
}

.no-definition {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--text-secondary);
  font-size: 13px;
}

/* Buttons */
.button-group {
  display: flex;
  gap: 10px;
  margin-top: 20px;
}

.btn {
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-primary {
  background: var(--color-accent);
  color: white;
}

.btn-primary:hover:not(:disabled) {
  opacity: 0.9;
}

.btn-secondary {
  background: var(--bg-card);
  color: var(--text-primary);
  border: 1px solid var(--border);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--border);
}

.validation-error {
  padding: 10px;
  background: var(--danger)22;
  border: 1px solid var(--danger);
  border-radius: 4px;
  color: var(--danger);
  font-size: 13px;
  margin-bottom: 15px;
}

/* Responsive */
@media (max-width: 1024px) {
  .split-pane {
    grid-template-columns: 1fr;
    gap: 15px;
    min-height: auto;
  }

  .pane-right {
    border-left: none;
    border-top: 1px solid var(--border);
    padding-left: 0;
    padding-top: 15px;
  }
}
</style>
