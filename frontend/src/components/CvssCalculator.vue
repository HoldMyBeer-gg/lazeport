<template>
  <Modal :show="show" @close="$emit('close')" :title="t('cvss.title')" wide>
    <div class="cvss-calculator">
      <!-- Score Display -->
      <div class="score-display">
        <div class="score-badge" :class="severityClass">
          {{ t('cvss.score') }}: {{ baseScore }} 
          <span class="severity-label">{{ severityLabel }}</span>
        </div>
        <div class="vector-string">
          {{ t('cvss.vector') }}: {{ vectorString }}
          <button 
            v-if="vectorString !== 'CVSS:3.1/'" 
            @click="copyVector" 
            class="copy-btn"
            :aria-label="t('cvss.copyVector')"
          >
            📋
          </button>
        </div>
      </div>

      <!-- Exploitability Metrics -->
      <div class="metric-group">
        <h3>{{ t('cvss.exploitability') }}</h3>
        
        <div class="metric-row">
          <label>{{ t('cvss.attackVector') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.AV.options" 
              :key="option.value"
              @click="setMetric('AV', option.value)"
              :class="{ active: metrics.AV.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>

        <div class="metric-row">
          <label>{{ t('cvss.attackComplexity') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.AC.options" 
              :key="option.value"
              @click="setMetric('AC', option.value)"
              :class="{ active: metrics.AC.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>

        <div class="metric-row">
          <label>{{ t('cvss.privilegesRequired') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.PR.options" 
              :key="option.value"
              @click="setMetric('PR', option.value)"
              :class="{ active: metrics.PR.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>

        <div class="metric-row">
          <label>{{ t('cvss.userInteraction') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.UI.options" 
              :key="option.value"
              @click="setMetric('UI', option.value)"
              :class="{ active: metrics.UI.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>
      </div>

      <!-- Scope -->
      <div class="metric-group">
        <h3>{{ t('cvss.scope') }}</h3>
        
        <div class="metric-row">
          <label>{{ t('cvss.scopeLabel') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.S.options" 
              :key="option.value"
              @click="setMetric('S', option.value)"
              :class="{ active: metrics.S.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>
      </div>

      <!-- Impact Metrics -->
      <div class="metric-group">
        <h3>{{ t('cvss.impact') }}</h3>
        
        <div class="metric-row">
          <label>{{ t('cvss.confidentiality') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.C.options" 
              :key="option.value"
              @click="setMetric('C', option.value)"
              :class="{ active: metrics.C.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>

        <div class="metric-row">
          <label>{{ t('cvss.integrity') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.I.options" 
              :key="option.value"
              @click="setMetric('I', option.value)"
              :class="{ active: metrics.I.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>

        <div class="metric-row">
          <label>{{ t('cvss.availability') }}</label>
          <div class="metric-buttons">
            <button 
              v-for="option in metrics.A.options" 
              :key="option.value"
              @click="setMetric('A', option.value)"
              :class="{ active: metrics.A.selected === option.value }"
              :title="option.description"
            >
              {{ option.label }}
            </button>
          </div>
        </div>
      </div>

      <!-- Actions -->
      <div class="modal-actions">
        <button @click="clear" class="btn-secondary">{{ t('cvss.clear') }}</button>
        <button @click="apply" class="btn-primary" :disabled="!isComplete">
          {{ t('cvss.apply') }}
        </button>
      </div>
    </div>
  </Modal>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Modal from './Modal.vue'

const { t } = useI18n()

const props = defineProps({
  show: Boolean,
  initialVector: String
})

const emit = defineEmits(['close', 'apply'])

// CVSS v3.1 Metrics with options
const metrics = ref({
  AV: {
    selected: null,
    options: [
      { value: 'N', label: 'N', description: 'Network - Remotely exploitable' },
      { value: 'A', label: 'A', description: 'Adjacent - Adjacent network access' },
      { value: 'L', label: 'L', description: 'Local - Local access required' },
      { value: 'P', label: 'P', description: 'Physical - Physical access required' }
    ]
  },
  AC: {
    selected: null,
    options: [
      { value: 'L', label: 'Low', description: 'No special conditions' },
      { value: 'H', label: 'High', description: 'Special conditions required' }
    ]
  },
  PR: {
    selected: null,
    options: [
      { value: 'N', label: 'None', description: 'No privileges required' },
      { value: 'L', label: 'Low', description: 'Basic user privileges' },
      { value: 'H', label: 'High', description: 'Admin privileges required' }
    ]
  },
  UI: {
    selected: null,
    options: [
      { value: 'N', label: 'None', description: 'No user interaction' },
      { value: 'R', label: 'Required', description: 'User interaction required' }
    ]
  },
  S: {
    selected: null,
    options: [
      { value: 'U', label: 'Unchanged', description: 'Scope unchanged' },
      { value: 'C', label: 'Changed', description: 'Scope changed' }
    ]
  },
  C: {
    selected: null,
    options: [
      { value: 'N', label: 'None', description: 'No confidentiality impact' },
      { value: 'L', label: 'Low', description: 'Limited confidentiality impact' },
      { value: 'H', label: 'High', description: 'Total confidentiality compromise' }
    ]
  },
  I: {
    selected: null,
    options: [
      { value: 'N', label: 'None', description: 'No integrity impact' },
      { value: 'L', label: 'Low', description: 'Limited integrity impact' },
      { value: 'H', label: 'High', description: 'Total integrity compromise' }
    ]
  },
  A: {
    selected: null,
    options: [
      { value: 'N', label: 'None', description: 'No availability impact' },
      { value: 'L', label: 'Low', description: 'Reduced availability' },
      { value: 'H', label: 'High', description: 'Total availability loss' }
    ]
  }
})

// CVSS v3.1 Base Score Calculation (official formula)
function calculateBaseScore() {
  const av = metrics.value.AV.selected
  const ac = metrics.value.AC.selected
  const pr = metrics.value.PR.selected
  const ui = metrics.value.UI.selected
  const s = metrics.value.S.selected
  const c = metrics.value.C.selected
  const i = metrics.value.I.selected
  const a = metrics.value.A.selected

  if (!av || !ac || !pr || !ui || !s || !c || !i || !a) {
    return null
  }

  // Numeric values for each metric
  const avValues = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
  const acValues = { L: 0.77, H: 0.44 }
  const prValues = {
    N: { U: 0.85, C: 0.85 },
    L: { U: 0.62, C: 0.68 },
    H: { U: 0.27, C: 0.50 }
  }
  const uiValues = { N: 0.85, R: 0.62 }
  const ciaValues = { N: 0, L: 0.22, H: 0.56 }

  // Get PR value based on scope
  const prValue = prValues[pr][s]

  // Impact Sub-Score (ISS)
  const iss = 1 - ((1 - ciaValues[c]) * (1 - ciaValues[i]) * (1 - ciaValues[a]))

  // Impact
  let impact
  if (s === 'U') {
    impact = 6.42 * iss
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  }

  // Exploitability
  const exploitability = 8.22 * avValues[av] * acValues[ac] * prValue * uiValues[ui]

  // Base Score
  let score
  if (impact <= 0) {
    score = 0
  } else if (s === 'U') {
    score = Math.min(impact + exploitability, 10)
  } else {
    score = Math.min(1.08 * (impact + exploitability), 10)
  }

  // Round up to 1 decimal
  return Math.ceil(score * 10) / 10
}

const baseScore = computed(() => {
  const score = calculateBaseScore()
  return score !== null ? score.toFixed(1) : '-'
})

const severityLabel = computed(() => {
  const score = calculateBaseScore()
  if (score === null) return ''
  if (score === 0) return 'None'
  if (score <= 3.9) return 'Low'
  if (score <= 6.9) return 'Medium'
  if (score <= 8.9) return 'High'
  return 'Critical'
})

const severityClass = computed(() => {
  const label = severityLabel.value.toLowerCase()
  return `severity-${label}`
})

const vectorString = computed(() => {
  const parts = []
  for (const [key, metric] of Object.entries(metrics.value)) {
    if (metric.selected) {
      parts.push(`${key}:${metric.selected}`)
    }
  }
  return parts.length === 8 ? `CVSS:3.1/${parts.join('/')}` : 'CVSS:3.1/'
})

const isComplete = computed(() => {
  return Object.values(metrics.value).every(m => m.selected !== null)
})

function setMetric(key, value) {
  metrics.value[key].selected = value
}

function clear() {
  for (const metric of Object.values(metrics.value)) {
    metric.selected = null
  }
}

async function copyVector() {
  try {
    await navigator.clipboard.writeText(vectorString.value)
    // Temporarily show feedback
    const btn = document.activeElement
    if (btn) {
      btn.textContent = '✓'
      setTimeout(() => {
        btn.textContent = '📋'
      }, 1500)
    }
  } catch (err) {
    console.error('Failed to copy:', err)
    // Fallback for older browsers or when clipboard API fails
    const textArea = document.createElement('textarea')
    textArea.value = vectorString.value
    textArea.style.position = 'fixed'
    textArea.style.left = '-999999px'
    document.body.appendChild(textArea)
    textArea.select()
    try {
      document.execCommand('copy')
      const btn = document.activeElement?.previousElementSibling
      if (btn && btn.classList.contains('copy-btn')) {
        btn.textContent = '✓'
        setTimeout(() => {
          btn.textContent = '📋'
        }, 1500)
      }
    } catch (fallbackErr) {
      console.error('Fallback copy failed:', fallbackErr)
      alert('Failed to copy to clipboard. Please copy manually.')
    } finally {
      document.body.removeChild(textArea)
    }
  }
}

function apply() {
  if (!isComplete.value) return
  
  const formattedValue = `${baseScore.value} (${vectorString.value})`
  emit('apply', formattedValue)
  emit('close')
}

// Parse initial vector if provided
watch(() => props.initialVector, (vector) => {
  if (!vector || !props.show) return
  
  // Parse CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
  const match = vector.match(/CVSS:3\.1\/(.+)/)
  if (!match) return
  
  const parts = match[1].split('/')
  for (const part of parts) {
    const [key, value] = part.split(':')
    if (metrics.value[key]) {
      metrics.value[key].selected = value
    }
  }
}, { immediate: true })

// Reset when modal opens fresh
watch(() => props.show, (show) => {
  if (show && !props.initialVector) {
    clear()
  }
})
</script>

<style scoped>
.cvss-calculator {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.score-display {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.score-badge {
  font-size: 1.25rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.severity-label {
  font-size: 0.875rem;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-weight: 500;
}

.severity-critical .severity-label { background: var(--sev-critical-bg); color: var(--sev-critical-text); }
.severity-high .severity-label { background: var(--sev-high-bg); color: var(--sev-high-text); }
.severity-medium .severity-label { background: var(--sev-medium-bg); color: var(--sev-medium-text); }
.severity-low .severity-label { background: var(--sev-low-bg); color: var(--sev-low-text); }
.severity-none .severity-label { background: var(--sev-info-bg); color: var(--sev-info-text); }

.vector-string {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.875rem;
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 0.5rem;
  word-break: break-all;
}

.copy-btn {
  background: none;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.25rem 0.5rem;
  cursor: pointer;
  font-size: 0.875rem;
  flex-shrink: 0;
}

.copy-btn:hover {
  background: var(--surface);
}

.metric-group {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.metric-group h3 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}

.metric-row {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.metric-row label {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text);
}

.metric-buttons {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.metric-buttons button {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 1rem;
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text);
  transition: all 0.2s;
  min-width: 60px;
}

.metric-buttons button:hover {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
}

.metric-buttons button.active {
  background: var(--accent);
  color: white;
  border-color: var(--accent);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border);
}

.btn-secondary {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 1.5rem;
  cursor: pointer;
  font-weight: 500;
  color: var(--text);
}

.btn-secondary:hover {
  background: var(--bg);
}

.btn-primary {
  background: var(--accent);
  border: none;
  border-radius: 6px;
  padding: 0.5rem 1.5rem;
  cursor: pointer;
  font-weight: 500;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: var(--accent-hover);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

@media (max-width: 768px) {
  .metric-buttons button {
    flex: 1;
    min-width: 0;
  }
}
</style>
