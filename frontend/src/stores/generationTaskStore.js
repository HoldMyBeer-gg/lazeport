/**
 * generationTaskStore.js
 *
 * Polls /api/tasks every 2s when any task is active, 10s when all done.
 * DB is the source of truth — no sessionStorage. First poll on startPolling()
 * immediately restores all active tasks after a page refresh or navigation.
 *
 * Session isolation: terminal tasks are only shown if this session previously
 * saw them as active (pending/running). This prevents orphaned failed/cancelled
 * tasks from a previous Celery worker restart from filling the TaskBar on load.
 *
 * Usage:
 *   startPolling()      — call in DashboardLayout onMounted
 *   stopPolling()       — call in DashboardLayout onUnmounted
 *   getGenerationTasks() — reactive list of tasks
 *   hasRunningTasks()   — true if any task is pending/running
 *   registerCompletionCallback(taskId, fn) — fired once when task completes
 *   unregisterCompletionCallback(taskId)
 *   acknowledgeTask(id) — remove from local list (persists across polls via dismissed set)
 *   cancelTask(id)      — DELETE /api/tasks/{id}
 */
import { reactive, ref } from 'vue'

const tasks = reactive([])
const isPolling = ref(false)
let pollTimer = null
let idleCount = 0  // polls since all tasks finished
const IDLE_STOP_POLLS = 30  // stop after 30 idle polls (10s each = 5 min idle)

// Terminal tasks dismissed by the user this session — never re-add them
const dismissedIds = new Set()

// Tasks we have seen as active (pending/running) in this session.
// A terminal task is only shown if it was active at some point this session
// — this prevents failed/stale tasks from a previous worker restart from
// appearing on every page load.
const seenActiveTaskIds = new Set()

const completionCallbacks = new Map()  // taskId → fn(task)

// ── Internal helpers ─────────────────────────────────────────────────────────

function _isActive(t) {
  return t.status === 'pending' || t.status === 'running'
}

function _isFinal(t) {
  return t.status === 'completed' || t.status === 'failed' || t.status === 'cancelled' || t.status === 'stale'
}

function _merge(fresh) {
  // Add or update tasks; track which went from active → final for callbacks
  for (const ft of fresh) {
    if (dismissedIds.has(ft.id)) continue  // user dismissed — never re-add

    const idx = tasks.findIndex(t => t.id === ft.id)
    if (idx === -1) {
      // New task not yet in our list.
      // Active tasks: always show (handles page-refresh during a running task).
      // Terminal tasks: only show if we saw this task as active this session —
      // prevents orphaned failed/cancelled tasks from a previous Celery restart
      // from appearing on every page load.
      // Stale tasks always shown — they need user attention (stuck worker).
      // Other terminal tasks only shown if seen as active this session.
      if (_isFinal(ft) && ft.status !== 'stale' && !seenActiveTaskIds.has(ft.id)) continue
      tasks.push({ ...ft })
      if (_isActive(ft)) seenActiveTaskIds.add(ft.id)
    } else {
      const was = tasks[idx]
      const wasActive = _isActive(was)
      if (wasActive) seenActiveTaskIds.add(ft.id)
      Object.assign(tasks[idx], ft)
      if (wasActive && _isFinal(ft)) {
        _fireCompletion(ft.id)
      }
    }
  }
}

async function _fireCompletion(taskId) {
  const cb = completionCallbacks.get(taskId)
  if (!cb) return
  try {
    // Fetch full task (includes result_json) before firing callback
    const r = await fetch(`/api/tasks/${taskId}`)
    if (r.ok) {
      const fullTask = await r.json()
      cb(fullTask)
    } else {
      const cached = tasks.find(t => t.id === taskId)
      if (cached) cb(cached)
    }
  } catch (_) {
    const cached = tasks.find(t => t.id === taskId)
    if (cached) cb(cached)
  }
}

async function _poll() {
  try {
    const r = await fetch('/api/tasks')
    if (!r.ok) return
    const data = await r.json()
    _merge(data.tasks || [])
  } catch (_) {
    // Network error — continue polling silently
  }
}

function _schedule() {
  if (!isPolling.value) return
  const anyActive = tasks.some(_isActive)
  if (anyActive) {
    idleCount = 0
    pollTimer = setTimeout(_tick, 2000)
  } else {
    idleCount++
    if (idleCount >= IDLE_STOP_POLLS) {
      tasks.splice(0)
      isPolling.value = false
      return
    }
    pollTimer = setTimeout(_tick, 10000)
  }
}

async function _tick() {
  pollTimer = null
  await _poll()
  _schedule()
}

// ── Public API ────────────────────────────────────────────────────────────────

export function startPolling() {
  if (isPolling.value) return
  isPolling.value = true
  idleCount = 0
  _tick()
}

/**
 * Force an immediate poll and reset to fast-poll mode. Call after enqueueing
 * a task so the TaskBar appears instantly instead of waiting for the next
 * scheduled tick (which could be up to 10s away in idle mode).
 */
export async function nudge() {
  idleCount = 0
  // Cancel any pending slow-poll timer
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
  if (!isPolling.value) {
    isPolling.value = true
  }
  // Poll now, then resume fast schedule
  await _poll()
  _schedule()
}

export function stopPolling() {
  isPolling.value = false
  if (pollTimer) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
}

export function getGenerationTasks() {
  return tasks
}

export function hasRunningTasks() {
  return tasks.some(_isActive)
}

export function hasTasks() {
  return tasks.length > 0
}

export function registerCompletionCallback(taskId, fn) {
  completionCallbacks.set(taskId, fn)
}

export function unregisterCompletionCallback(taskId) {
  completionCallbacks.delete(taskId)
}

/**
 * Pre-register task IDs as "seen active" so they are shown in the TaskBar
 * even if polling first encounters them in a terminal state. Call this
 * immediately after enqueuing tasks, before any poll can race.
 */
export function trackTaskIds(ids) {
  for (const id of ids) {
    seenActiveTaskIds.add(id)
  }
}

export function acknowledgeTask(id) {
  dismissedIds.add(id)
  const idx = tasks.findIndex(t => t.id === id)
  if (idx !== -1) tasks.splice(idx, 1)
  completionCallbacks.delete(id)
}

export async function cancelTask(id) {
  try {
    await fetch(`/api/tasks/${id}`, { method: 'DELETE' })
    const idx = tasks.findIndex(t => t.id === id)
    if (idx !== -1) tasks[idx].status = 'cancelled'
  } catch (_) {}
}
