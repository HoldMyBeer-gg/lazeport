<!-- TaskBar.vue — terminal-style fixed bottom bar for Celery-backed generation tasks -->
<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps({
  tasks: {
    type: Array,
    default: () => []
  }
})

const emit = defineEmits(['taskClick', 'taskCancel', 'taskDismiss', 'dismissAll'])

const expanded = ref(false)

// ── Computed ─────────────────────────────────────────────────────────────────

const runningTasks = computed(() =>
  props.tasks.filter(t => t.status === 'pending' || t.status === 'running')
)

const doneTasks = computed(() =>
  props.tasks.filter(t => t.status === 'completed' || t.status === 'failed' ||
                          t.status === 'cancelled' || t.status === 'stale')
)

// The most active task shown inline when bar is collapsed
const primaryTask = computed(() => {
  if (runningTasks.value.length > 0) {
    return runningTasks.value.reduce((best, t) =>
      t.current_step > best.current_step ? t : best
    )
  }
  return doneTasks.value[0] || null
})

const hasDismissable = computed(() => doneTasks.value.length > 0)

// No auto-expand — user controls the bar. The collapsed strip shows
// the primary task's status at a glance; expand is always manual.

// ── Helpers ───────────────────────────────────────────────────────────────────

function taskPrefix(task) {
  switch (task.task_type) {
    case 'generate_finding':   return t('taskBar.prefixGen')
    case 'regenerate_finding': return t('taskBar.prefixReg')
    case 'generate_summaries': return t('taskBar.prefixSum')
    case 'vision_extraction':  return t('taskBar.prefixImg')
    case 'import_finding':     return t('taskBar.prefixImp')
    case 'validate_guidance':  return t('taskBar.prefixVal')
    default:                   return '[???]'
  }
}

function taskStatusClass(task) {
  switch (task.status) {
    case 'running':
    case 'pending':   return 'status-running'
    case 'completed': return 'status-done'
    case 'failed':    return 'status-error'
    case 'stale':     return 'status-stale'
    default:          return 'status-done'
  }
}

function progressPct(task) {
  if (!task.total_steps || task.total_steps === 0) return 0
  return Math.min(100, Math.round((task.current_step / task.total_steps) * 100))
}

function lastProgressMsg(task) {
  try {
    const log = Array.isArray(task.progress_log)
      ? task.progress_log
      : JSON.parse(task.progress_log || '[]')
    return log[log.length - 1] || ''
  } catch {
    return ''
  }
}

function elapsedSeconds(task) {
  if (!task.started_at) return null
  const start = new Date(task.started_at).getTime()
  const end = task.finished_at ? new Date(task.finished_at).getTime() : Date.now()
  return ((end - start) / 1000).toFixed(1)
}

function isActionable(task) {
  return task.status === 'completed' || task.status === 'failed'
}

function isReviewTask(task) {
  return task.task_type === 'regenerate_finding' ||
         task.task_type === 'generate_summaries'
}

function actionLabel(task) {
  if (task.status === 'failed') return null
  return isReviewTask(task) ? t('taskBar.review') : t('taskBar.view')
}

function progressAriaText(task) {
  return t('taskBar.ariaProgress', {
    current: task.current_step || 0,
    total: task.total_steps || 0,
    msg: lastProgressMsg(task) || ''
  })
}

function toggleExpanded() {
  expanded.value = !expanded.value
}

function onTaskClick(task) {
  emit('taskClick', task)
}

function onTaskCancel(task) {
  emit('taskCancel', task)
}

function onTaskDismiss(task) {
  emit('taskDismiss', task)
}

function onDismissAll() {
  emit('dismissAll')
}
</script>

<template>
  <div
    v-if="tasks.length > 0"
    class="task-bar"
    :class="{ 'task-bar--expanded': expanded }"
    role="log"
    aria-live="polite"
    :aria-label="t('taskBar.ariaLabel')"
  >
    <!-- ── Collapsed strip ── -->
    <div
      class="task-bar__strip"
      role="button"
      tabindex="0"
      :aria-expanded="expanded"
      :aria-label="expanded ? t('taskBar.collapse') : t('taskBar.expand')"
      @click="toggleExpanded"
      @keydown.enter.prevent="toggleExpanded"
      @keydown.space.prevent="toggleExpanded"
    >
      <!-- Left: summary when collapsed, title when expanded -->
      <span class="task-bar__strip-label">
        <template v-if="!expanded && primaryTask">
          <span class="task-bar__prefix" :class="taskStatusClass(primaryTask)">
            {{ taskPrefix(primaryTask) }}
          </span>
          <span class="task-bar__inline-title">{{ primaryTask.title }}</span>
          <template v-if="primaryTask.status === 'running' || primaryTask.status === 'pending'">
            <span class="task-bar__inline-progress">
              {{ primaryTask.current_step }}/{{ primaryTask.total_steps }}
            </span>
            <span class="task-bar__inline-msg">{{ lastProgressMsg(primaryTask) }}</span>
          </template>
          <template v-else>
            <span class="task-bar__inline-status" :class="taskStatusClass(primaryTask)">
              {{ primaryTask.status === 'completed' ? '✓' : primaryTask.status === 'failed' ? '✗' : '○' }}
            </span>
          </template>
        </template>
        <template v-else-if="expanded">
          <span class="task-bar__title">{{ t('taskBar.title') }}</span>
          <span class="task-bar__summary">
            <template v-if="runningTasks.length > 0">
              {{ t('taskBar.running', { count: runningTasks.length }) }}
            </template>
            <template v-if="runningTasks.length > 0 && doneTasks.length > 0"> · </template>
            <template v-if="doneTasks.length > 0">
              {{ t('taskBar.done', { count: doneTasks.length }) }}
            </template>
          </span>
        </template>
      </span>

      <!-- Clear all button (expanded only, when terminal tasks exist) -->
      <button
        v-if="expanded && hasDismissable"
        class="task-bar__clear-all-btn"
        type="button"
        :aria-label="t('taskBar.clearAll')"
        @click.stop="onDismissAll"
      >
        {{ t('taskBar.clearAll') }}
      </button>

      <!-- Right: expand/collapse chevron -->
      <span class="task-bar__chevron" aria-hidden="true">
        {{ expanded ? '▼' : '▲' }}
      </span>
    </div>

    <!-- ── Expanded task list ── -->
    <div v-if="expanded" class="task-bar__list">
      <div
        v-for="task in tasks"
        :key="task.id"
        class="task-bar__row"
        :class="taskStatusClass(task)"
        :role="isActionable(task) ? 'button' : 'listitem'"
        :tabindex="isActionable(task) ? 0 : -1"
        :aria-label="isActionable(task) ? `${task.title} — ${actionLabel(task)}` : task.title"
        @click="isActionable(task) && onTaskClick(task)"
        @keydown.enter.prevent="isActionable(task) && onTaskClick(task)"
        @keydown.space.prevent="isActionable(task) && onTaskClick(task)"
      >
        <!-- Left column: prefix badge + title -->
        <div class="task-bar__row-left">
          <span class="task-bar__prefix" :class="taskStatusClass(task)">
            {{ taskPrefix(task) }}
          </span>
          <span class="task-bar__row-title">{{ task.title }}</span>
        </div>

        <!-- Center: progress bar + current message -->
        <div class="task-bar__row-center">
          <div
            v-if="task.total_steps > 0"
            class="task-bar__progress-track"
            role="progressbar"
            :aria-valuenow="task.current_step"
            :aria-valuemax="task.total_steps"
            :aria-valuetext="progressAriaText(task)"
          >
            <div
              class="task-bar__progress-fill"
              :class="{
                'task-bar__progress-fill--pulse': task.status === 'running',
                'task-bar__progress-fill--done': task.status === 'completed',
                'task-bar__progress-fill--error': task.status === 'failed',
              }"
              :style="{ width: progressPct(task) + '%' }"
            />
          </div>
          <div class="task-bar__row-msg">
            <template v-if="task.status === 'completed'">
              <span class="status-done">✓ {{ lastProgressMsg(task) || t('taskBar.done', { count: 1 }).replace(' 1', '') }}</span>
            </template>
            <template v-else-if="task.status === 'failed'">
              <span class="status-error">✗ {{ task.error || t('taskBar.error') }}</span>
            </template>
            <template v-else-if="task.status === 'stale'">
              <span class="status-stale">⚠ {{ t('taskBar.stale') }}</span>
            </template>
            <template v-else>
              <span class="task-bar__repaint">→ {{ lastProgressMsg(task) }}</span>
            </template>
          </div>
        </div>

        <!-- Right column: step counter + elapsed + actions -->
        <div class="task-bar__row-right">
          <span
            v-if="task.total_steps > 0 && (task.status === 'running' || task.status === 'pending')"
            class="task-bar__steps"
          >
            {{ t('taskBar.stepOf', { current: task.current_step, total: task.total_steps }) }}
          </span>
          <span v-if="elapsedSeconds(task)" class="task-bar__elapsed">
            {{ elapsedSeconds(task) }}s
          </span>

          <!-- Action button: View / Review -->
          <button
            v-if="task.status === 'completed' && actionLabel(task)"
            class="task-bar__action-btn"
            type="button"
            @click.stop="onTaskClick(task)"
          >
            {{ actionLabel(task) }} →
          </button>

          <!-- Cancel button for running tasks -->
          <button
            v-if="task.status === 'running' || task.status === 'pending'"
            class="task-bar__cancel-btn"
            type="button"
            :aria-label="t('taskBar.cancel')"
            @click.stop="onTaskCancel(task)"
          >
            ✕
          </button>

          <!-- Dismiss button for terminal tasks -->
          <button
            v-if="task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled' || task.status === 'stale'"
            class="task-bar__cancel-btn"
            type="button"
            :aria-label="t('taskBar.dismiss')"
            @click.stop="onTaskDismiss(task)"
          >
            ✕
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* ── Root bar ─────────────────────────────────────────────────────────────── */
.task-bar {
  position: fixed;
  bottom: 0;
  inset-inline-start: 0;
  inset-inline-end: 0;
  z-index: 1000;
  font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
  font-size: 0.75rem;
  background: var(--color-bg-secondary, #1a1a1a);
  border-top: 1px solid var(--color-border, #333);
  color: var(--color-text, #ccc);
  padding-bottom: env(safe-area-inset-bottom);
  transition: max-height 0.2s ease;
}

/* ── Collapsed strip ─────────────────────────────────────────────────────── */
.task-bar__strip {
  display: flex;
  align-items: center;
  height: 40px;
  padding-inline: 1rem;
  cursor: pointer;
  user-select: none;
  gap: 0.5rem;
  border-top: 1px solid var(--color-border, #333);
}

.task-bar__strip:focus-visible {
  outline: 2px solid var(--color-accent, #268bd2);
  outline-offset: -2px;
}

.task-bar__strip-label {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  overflow: hidden;
}

.task-bar__title {
  font-weight: 600;
  color: var(--color-text, #ccc);
  letter-spacing: 0.05em;
  text-transform: uppercase;
  font-size: 0.7rem;
}

.task-bar__summary {
  color: var(--color-text-muted, #666);
  font-size: 0.7rem;
}

.task-bar__inline-title {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 30ch;
  color: var(--color-text, #ccc);
}

.task-bar__inline-progress {
  color: var(--color-text-muted, #666);
  white-space: nowrap;
  flex-shrink: 0;
}

.task-bar__inline-msg {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--color-text-muted, #666);
  font-style: italic;
}

.task-bar__inline-status {
  flex-shrink: 0;
}

.task-bar__clear-all-btn {
  background: transparent;
  border: 1px solid var(--color-text-muted, #666);
  color: var(--color-text-muted, #666);
  font-family: inherit;
  font-size: 0.65rem;
  padding: 1px 6px;
  border-radius: 2px;
  cursor: pointer;
  white-space: nowrap;
  flex-shrink: 0;
  transition: color 0.15s, border-color 0.15s;
}

.task-bar__clear-all-btn:hover {
  color: var(--color-text, #ccc);
  border-color: var(--color-text, #ccc);
}

.task-bar__clear-all-btn:focus-visible {
  outline: 2px solid var(--color-accent, #268bd2);
  outline-offset: 2px;
}

.task-bar__chevron {
  flex-shrink: 0;
  color: var(--color-text-muted, #666);
  font-size: 0.65rem;
}

/* ── Expanded list ───────────────────────────────────────────────────────── */
.task-bar__list {
  max-height: min(240px, 50vh);
  overflow-y: auto;
  overscroll-behavior: contain;
}

/* ── Task row ────────────────────────────────────────────────────────────── */
.task-bar__row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  min-height: 44px;   /* 44px min touch target */
  padding: 0.4rem 1rem;
  border-top: 1px solid var(--color-border-subtle, #2a2a2a);
  transition: background 0.1s;
}

.task-bar__row[role="button"] {
  cursor: pointer;
}

.task-bar__row[role="button"]:hover {
  background: var(--color-bg-hover, rgba(255,255,255,0.04));
}

.task-bar__row[role="button"]:focus-visible {
  outline: 2px solid var(--color-accent, #268bd2);
  outline-offset: -2px;
}

/* ── Row sections ────────────────────────────────────────────────────────── */
.task-bar__row-left {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-shrink: 0;
  min-width: 0;
  width: 22ch;
}

.task-bar__row-title {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--color-text, #ccc);
  font-size: 0.72rem;
}

.task-bar__row-center {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.task-bar__row-msg {
  font-size: 0.7rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--color-text-muted, #666);
}

.task-bar__repaint {
  font-style: italic;
  color: var(--color-text-muted, #666);
}

.task-bar__row-right {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-shrink: 0;
}

.task-bar__steps {
  color: var(--color-text-muted, #666);
  white-space: nowrap;
  font-size: 0.7rem;
}

.task-bar__elapsed {
  color: var(--color-text-muted, #666);
  font-size: 0.7rem;
  white-space: nowrap;
}

/* ── Prefix badge ────────────────────────────────────────────────────────── */
.task-bar__prefix {
  font-size: 0.65rem;
  font-weight: 700;
  padding: 1px 3px;
  border-radius: 2px;
  letter-spacing: 0.04em;
  flex-shrink: 0;
  background: transparent;
  border: 1px solid currentColor;
  white-space: nowrap;
}

/* ── Progress bar ────────────────────────────────────────────────────────── */
.task-bar__progress-track {
  height: 4px;
  background: var(--color-bg-tertiary, #2a2a2a);
  border-radius: 2px;
  overflow: hidden;
}

.task-bar__progress-fill {
  height: 100%;
  border-radius: 2px;
  background: var(--color-accent, #268bd2);
  transition: width 0.4s ease;
}

.task-bar__progress-fill--pulse {
  background: var(--color-info, #2aa198);
  animation: bar-pulse 1.5s ease-in-out infinite;
}

.task-bar__progress-fill--done {
  background: var(--color-success, #859900);
}

.task-bar__progress-fill--error {
  background: var(--color-error, #dc322f);
}

@keyframes bar-pulse {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.6; }
}

/* ── Action / cancel buttons ────────────────────────────────────────────── */
.task-bar__action-btn {
  background: transparent;
  border: 1px solid var(--color-success, #859900);
  color: var(--color-success, #859900);
  font-family: inherit;
  font-size: 0.7rem;
  padding: 2px 6px;
  border-radius: 2px;
  cursor: pointer;
  white-space: nowrap;
  transition: background 0.15s;
}

.task-bar__action-btn:hover {
  background: var(--color-success, #859900);
  color: var(--color-bg, #fff);
}

.task-bar__action-btn:focus-visible {
  outline: 2px solid var(--color-success, #859900);
  outline-offset: 2px;
}

.task-bar__cancel-btn {
  background: transparent;
  border: none;
  color: var(--color-text-muted, #666);
  font-family: inherit;
  font-size: 0.75rem;
  padding: 2px 4px;
  cursor: pointer;
  border-radius: 2px;
  transition: color 0.15s;
  line-height: 1;
}

.task-bar__cancel-btn:hover {
  color: var(--color-error, #dc322f);
}

.task-bar__cancel-btn:focus-visible {
  outline: 2px solid var(--color-error, #dc322f);
  outline-offset: 2px;
}

/* ── Status colors (Solarized palette) ───────────────────────────────────── */
.status-running { color: var(--color-info, #2aa198); }
.status-done    { color: var(--color-success, #859900); }
.status-error   { color: var(--color-error, #dc322f); }
.status-stale   { color: var(--color-warning, #b58900); }

/* ── Scrollbar ───────────────────────────────────────────────────────────── */
.task-bar__list::-webkit-scrollbar {
  width: 4px;
}
.task-bar__list::-webkit-scrollbar-track {
  background: transparent;
}
.task-bar__list::-webkit-scrollbar-thumb {
  background: var(--color-border, #333);
  border-radius: 2px;
}
</style>
