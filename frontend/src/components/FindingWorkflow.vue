<!-- FindingWorkflow.vue - Modal workflow for processing Burp findings (session mode: survives navigation) -->
<script setup>
import { ref, computed, watch, onUnmounted, inject } from 'vue'
import { useI18n } from 'vue-i18n'
import Modal from './Modal.vue'
import { request } from '../services/api'
import { startBurpImportProcessing, resetAndEnqueueBurpImport } from '../services/burpImportProcessor'

const { t } = useI18n()
const orgLlmSettings = inject('orgLlmSettings', ref({}))

// Live clock for elapsed time display when generating
const now = ref(Date.now())
let elapsedInterval = null

const props = defineProps({
  sessionId: { type: String, default: null },
  reportId: { type: String, default: null },
  tasks: { type: Array, default: () => [] },
  fileName: { type: String, default: '' },
  show: { type: Boolean, default: false }
})

const emit = defineEmits(['close', 'finished'])

// Session mode: has sessionId + reportId
const sessionMode = computed(() => Boolean(props.sessionId && props.reportId))
const tasksList = ref([])
const isEnqueuing = ref(false)
const isCancelling = ref(false)
let pollInterval = null

watch(
  () => [props.tasks, props.show],
  ([tasks, show]) => {
    if (Array.isArray(tasks)) tasksList.value = tasks
    if (show && sessionMode.value) {
      startPolling()
    } else {
      stopPolling()
    }
  },
  { immediate: true }
)

function startElapsedTick() {
  if (elapsedInterval) return
  elapsedInterval = setInterval(() => { now.value = Date.now() }, 1000)
}
function stopElapsedTick() {
  if (elapsedInterval) {
    clearInterval(elapsedInterval)
    elapsedInterval = null
  }
}

function formatElapsed(ms) {
  if (!ms || ms < 0) return '0s'
  const s = Math.floor(ms / 1000)
  const m = Math.floor(s / 60)
  const secs = s % 60
  if (m > 0) return `${m}:${String(secs).padStart(2, '0')}`
  return `${s}s`
}

function startPolling() {
  stopPolling()
  pollInterval = setInterval(refreshTasks, 2000)
}

function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval)
    pollInterval = null
  }
}

onUnmounted(stopPolling)

async function refreshTasks() {
  if (!props.reportId) return
  try {
    const data = await request(`/api/admin/reports/${props.reportId}/import-queue`)
    const sess = data.sessions?.find((s) => s.session_id === props.sessionId)
    if (sess?.tasks) {
      tasksList.value = sess.tasks
      // Stop polling once no tasks are actively generating
      const hasGenerating = sess.tasks.some((tk) => tk.status === 'generating')
      if (!hasGenerating) {
        stopPolling()
      }
    }
  } catch {}
}

const pendingTasks = computed(() => {
  return tasksList.value
    .map((tk, i) => ({ ...tk, index: tk.index ?? i }))
    .filter((tk) => tk.status === 'pending' || tk.status === 'failed')
})
const cancellableCount = computed(() => pendingTasks.value.length)
const completedTasks = computed(() => {
  return tasksList.value
    .map((tk, i) => ({ ...tk, index: tk.index ?? i }))
    .filter((tk) => tk.status === 'completed')
})
const skippedTasks = computed(() => {
  return tasksList.value
    .map((tk, i) => ({ ...tk, index: tk.index ?? i }))
    .filter((tk) => tk.status === 'skipped')
})
const completedCount = computed(() => completedTasks.value.length)
const skippedCount = computed(() => skippedTasks.value.length)
const generatingCount = computed(
  () => tasksList.value.filter((tk) => tk.status === 'generating').length
)
const allDone = computed(
  () => pendingTasks.value.length === 0 && generatingCount.value === 0 && tasksList.value.length > 0
)

const generatingPosition = computed(() => {
  // Count how many tasks have been processed (completed + skipped) + currently generating
  // This gives accurate "X of Y" even when tasks fail and retry
  const processedCount = tasksList.value.filter(
    (tk) => tk.status === 'completed' || tk.status === 'skipped' || tk.status === 'generating'
  ).length
  return processedCount
})

const elapsedMs = computed(() => {
  const generating = tasksList.value.filter((tk) => tk.status === 'generating')
  if (generating.length === 0) return 0
  const timestamps = generating.map((tk) => tk.generating_since).filter((v) => v && v > 0)
  if (timestamps.length === 0) return 0
  return now.value - Math.min(...timestamps)
})

const generatingProgressText = computed(() => {
  if (generatingCount.value === 0) return null
  const total = tasksList.value.length
  return t('findingWorkflow.generatingProgress', {
    current: generatingPosition.value || 1,
    total,
    elapsed: formatElapsed(elapsedMs.value)
  })
})

watch(
  () => generatingCount.value,
  (n) => {
    if (n > 0) startElapsedTick()
    else stopElapsedTick()
  },
  { immediate: true }
)
onUnmounted(stopElapsedTick)

async function generateTask(task) {
  if (!props.sessionId || !props.reportId) return
  await startBurpImportProcessing({
    sessionId: props.sessionId,
    reportId: props.reportId,
    taskIndices: [task.index],
    llmSettings: orgLlmSettings.value,
  })
  startPolling()
  await refreshTasks()
}

async function generateAll() {
  if (!props.sessionId || !props.reportId || pendingTasks.value.length === 0) return
  isEnqueuing.value = true
  try {
    await startBurpImportProcessing({
      sessionId: props.sessionId,
      reportId: props.reportId,
      taskIndices: pendingTasks.value.map((tk) => tk.index),
      llmSettings: orgLlmSettings.value,
    })
    startPolling()
    await refreshTasks()
  } finally {
    isEnqueuing.value = false
  }
}

async function skipTask(task) {
  if (!props.sessionId) return
  await request(
    `/api/admin/import-sessions/${props.sessionId}/tasks/${task.index}`,
    {
      method: 'PATCH',
      body: JSON.stringify({ status: 'skipped' })
    }
  )
  await refreshTasks()
}

async function unskipTask(task) {
  if (!props.sessionId) return
  await request(
    `/api/admin/import-sessions/${props.sessionId}/tasks/${task.index}`,
    {
      method: 'PATCH',
      body: JSON.stringify({ status: 'pending' })
    }
  )
  await refreshTasks()
}

async function regenerateTask(task) {
  if (!props.sessionId || !props.reportId) return
  await resetAndEnqueueBurpImport({
    sessionId: props.sessionId,
    reportId: props.reportId,
    taskIndices: [task.index],
    llmSettings: orgLlmSettings.value,
  })
  startPolling()
  await refreshTasks()
}

async function unskipAll() {
  if (!props.sessionId || skippedTasks.value.length === 0) return
  for (const task of skippedTasks.value) {
    await request(
      `/api/admin/import-sessions/${props.sessionId}/tasks/${task.index}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status: 'pending' })
      }
    )
  }
  await refreshTasks()
}

async function regenerateAll() {
  if (!props.sessionId || !props.reportId || completedTasks.value.length === 0) return
  await resetAndEnqueueBurpImport({
    sessionId: props.sessionId,
    reportId: props.reportId,
    taskIndices: completedTasks.value.map((tk) => tk.index),
    llmSettings: orgLlmSettings.value,
  })
  startPolling()
  await refreshTasks()
}

async function cancelPendingTasks() {
  if (!props.sessionId || cancellableCount.value === 0) return
  isCancelling.value = true
  try {
    await request(`/api/admin/import-sessions/${props.sessionId}/cancel-pending`, {
      method: 'POST',
    })
    await refreshTasks()
    const hasGenerating = tasksList.value.some((tk) => tk.status === 'generating')
    const hasCancellable = tasksList.value.some((tk) => tk.status === 'pending' || tk.status === 'failed')
    if (!hasGenerating && !hasCancellable) {
      closeModal()
    }
  } finally {
    isCancelling.value = false
  }
}

function closeModal() {
  stopPolling()
  emit('close')
}

function finishWorkflow() {
  stopPolling()
  emit('finished')
}

function getTaskTooltip(task) {
  const f = task.finding
  if (!f) return ''
  
  const parts = []
  
  // Title (full, untruncated)
  if (f.name) parts.push(f.name)
  
  // Severity
  if (f.severity) parts.push(`Severity: ${f.severity}`)
  
  // Location info (SARIF vs Burp)
  if (f.locations && Array.isArray(f.locations)) {
    // SARIF format (merged) - show count and first few locations
    if (f.tool) parts.push(`Tool: ${f.tool}`)
    if (f.ruleId) parts.push(`Rule: ${f.ruleId}`)
    const count = f.locations.length
    if (count > 0) {
      parts.push(`Affected Files: ${count}`)
      // Show first 3 locations
      const preview = f.locations.slice(0, 3)
      preview.forEach(loc => {
        const line = loc.line ? `:${loc.line}` : ''
        parts.push(`  • ${loc.file}${line}`)
      })
      if (count > 3) parts.push(`  ... and ${count - 3} more`)
    }
  } else if (f.location) {
    // SARIF format (single occurrence - legacy)
    let loc = f.location
    if (f.lineNumber) loc += `:${f.lineNumber}`
    parts.push(`Location: ${loc}`)
    if (f.tool) parts.push(`Tool: ${f.tool}`)
    if (f.ruleId) parts.push(`Rule: ${f.ruleId}`)
  } else if (f.host || f.path) {
    // Burp format
    if (f.host) parts.push(`Host: ${f.host}`)
    if (f.path) parts.push(`Path: ${f.path}`)
    if (f.confidence) parts.push(`Confidence: ${f.confidence}`)
  }
  
  // Description preview (first 150 chars)
  if (f.description) {
    const desc = f.description.substring(0, 150)
    parts.push(desc + (f.description.length > 150 ? '...' : ''))
  } else if (f.issueDetail) {
    // Strip HTML and get preview
    const stripped = f.issueDetail.replace(/<[^>]*>/g, '').substring(0, 150)
    parts.push(stripped + (f.issueDetail.length > 150 ? '...' : ''))
  }
  
  return parts.join('\n')
}
</script>

<template>
  <Modal
    v-if="show && sessionMode && tasksList.length > 0"
    @close="closeModal"
    :title="$t('findingWorkflow.modalTitle')"
    size="large"
    :close-on-backdrop="generatingCount === 0"
  >
    <div class="workflow-container">
    <p v-if="fileName" class="muted" style="margin-bottom:12px">
      {{ fileName }} - {{ $t('findingWorkflow.generationRunsOnServer') }}
    </p>

      <div class="progress-header">
        <div class="progress-pills">
          <span class="pill pill-completed" v-if="completedCount">{{ $t('findingWorkflow.generated', { count: completedCount }) }}</span>
          <span class="pill pill-generating" v-if="generatingCount">{{ $t('findingWorkflow.generating', { count: generatingCount }) }}</span>
          <span class="pill pill-skipped" v-if="skippedCount">{{ $t('findingWorkflow.skipped', { count: skippedCount }) }}</span>
          <span class="pill pill-pending" v-if="pendingTasks.length">{{ $t('findingWorkflow.pending', { count: pendingTasks.length }) }}</span>
        </div>
        <p v-if="generatingProgressText" class="generating-progress muted">
          {{ generatingProgressText }}
        </p>
      </div>

      <div class="task-list">
        <div
          v-for="task in tasksList"
          :key="task.index"
          class="task-row"
          :class="task.status"
          :title="getTaskTooltip(task)"
        >
          <div class="task-main">
            <span class="task-title">{{ task.finding?.name || $t('findingWorkflow.unnamed') }}</span>
            <span :class="['task-status', task.status]">{{ task.status }}</span>
          </div>
          <!-- Pending / Failed: Generate + Skip -->
          <div v-if="task.status === 'pending' || task.status === 'failed'" class="task-actions">
            <button class="primary small" @click="generateTask(task)" :disabled="task.status === 'generating'">
              {{ task.status === 'generating' ? $t('findingWorkflow.generatingLabel') : $t('findingWorkflow.generate') }}
            </button>
            <button class="secondary small" @click="skipTask(task)">{{ $t('findingWorkflow.skip') }}</button>
          </div>
          <!-- Generating: spinner label -->
          <div v-else-if="task.status === 'generating'" class="task-actions">
            <span class="task-generating-label">{{ $t('findingWorkflow.generatingLabel') }}</span>
          </div>
          <!-- Completed: Regenerate -->
          <div v-else-if="task.status === 'completed'" class="task-actions">
            <button class="ghost small" @click="regenerateTask(task)" :title="$t('findingWorkflow.regenerateTitle')">{{ $t('findingWorkflow.regenerate') }}</button>
          </div>
          <!-- Skipped: Unskip -->
          <div v-else-if="task.status === 'skipped'" class="task-actions">
            <button class="ghost small" @click="unskipTask(task)" :title="$t('findingWorkflow.unskipTitle')">{{ $t('findingWorkflow.unskip') }}</button>
          </div>
        </div>
      </div>

      <div class="workflow-actions">
        <button
          v-if="cancellableCount > 0"
          @click="cancelPendingTasks"
          class="secondary"
          :disabled="isCancelling"
        >
          {{ $t('common.cancel') }} ({{ cancellableCount }})
        </button>
        <button
          v-if="pendingTasks.length > 0"
          @click="generateAll"
          class="primary"
          :disabled="isEnqueuing"
        >
          {{ $t('findingWorkflow.generateAll', { count: pendingTasks.length }) }}
        </button>
        <button
          v-if="skippedCount > 0"
          @click="unskipAll"
          class="secondary"
          :title="$t('findingWorkflow.unskipAllTitle')"
        >
          {{ $t('findingWorkflow.unskipAll', { count: skippedCount }) }}
        </button>
        <button
          v-if="completedCount > 0 && pendingTasks.length === 0"
          @click="regenerateAll"
          class="secondary"
          :title="$t('findingWorkflow.regenerateAllTitle')"
        >
          {{ $t('findingWorkflow.regenerateAll', { count: completedCount }) }}
        </button>
        <button v-if="allDone" @click="finishWorkflow" class="primary">
          {{ $t('findingWorkflow.viewGeneratedFindings') }}
        </button>
        <button @click="closeModal" class="secondary">{{ $t('common.close') }}</button>
      </div>
    </div>
  </Modal>
</template>

<style scoped>
.workflow-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.progress-header {
  text-align: center;
}

.progress-pills {
  display: flex;
  gap: 8px;
  justify-content: center;
  flex-wrap: wrap;
}

.generating-progress {
  margin: 8px 0 0;
  font-size: 13px;
}

.pill {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.pill-completed {
  background: rgba(34, 197, 94, 0.12);
  color: #16a34a;
}

.pill-generating {
  background: rgba(13, 148, 136, 0.12);
  color: var(--primary);
}

.pill-skipped {
  background: rgba(107, 114, 128, 0.12);
  color: var(--text-muted);
}

.pill-pending {
  background: rgba(245, 158, 11, 0.12);
  color: #d97706;
}

.task-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 360px;
  overflow-y: auto;
}

.task-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-meta);
  transition: all 0.2s;
  cursor: help;
}

.task-row:hover {
  border-color: var(--primary);
  background: var(--bg-card);
}

.task-row.completed {
  opacity: 0.65;
}

.task-row.skipped {
  opacity: 0.55;
  border-style: dashed;
}

.task-row.completed:hover,
.task-row.skipped:hover {
  opacity: 1;
}

.task-main {
  flex: 1;
  min-width: 0;
}

.task-title {
  font-weight: 500;
  color: var(--text-primary);
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.task-status {
  font-size: 12px;
  color: var(--text-muted);
  text-transform: capitalize;
}

.task-status.completed {
  color: #22c55e;
}

.task-status.failed {
  color: #ef4444;
}

.task-status.skipped {
  color: #9ca3af;
}

.task-status.generating {
  color: var(--primary);
}

.task-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
  align-items: center;
}

.task-generating-label {
  font-size: 13px;
  color: var(--primary);
  font-weight: 500;
  animation: pulse-text 1.5s ease-in-out infinite;
}

@keyframes pulse-text {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

button.small {
  padding: 6px 12px;
  font-size: 13px;
}

button.ghost {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.15s;
}

button.ghost:hover {
  background: var(--bg-hover-solid);
  color: var(--text-primary);
  border-color: var(--text-muted);
}

button.ghost.small {
  padding: 4px 10px;
  font-size: 12px;
}

.workflow-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  flex-wrap: wrap;
  padding-top: 8px;
}
</style>
