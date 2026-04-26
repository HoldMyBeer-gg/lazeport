import { reactive } from 'vue'
import i18n from '../i18n'

const STORAGE_KEY = 'lazeport-background-tasks'
const STORAGE_VERSION = 2  // Increment to force clear old storage format

/**
 * Global store for AI (and other long-running) tasks that continue when the user
 * navigates away. Tasks persist here (and in sessionStorage) so the UI can show
 * progress after refresh and when the user returns to the relevant page.
 */
const tasks = reactive([])
let nextId = 1

function persist() {
  try {
    const payload = {
      version: STORAGE_VERSION,
      tasks: tasks.map((t) => ({
        id: t.id,
        reportId: t.reportId,
        type: t.type,
        title: t.title,
        status: t.status,
        error: t.error,
        startedAt: t.startedAt,
        finishedAt: t.finishedAt ?? null,
      }))
    }
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload))
  } catch (_) {}
}

function rehydrate() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return
    const payload = JSON.parse(raw)
    
    // Version mismatch or old format - clear and start fresh
    if (!payload.version || payload.version !== STORAGE_VERSION) {
      sessionStorage.removeItem(STORAGE_KEY)
      return
    }
    
    const storedTasks = payload.tasks || []
    if (!Array.isArray(storedTasks) || storedTasks.length === 0) return
    
    const now = Date.now()
    let maxNum = 0
    for (const p of storedTasks) {
      const num = parseInt(String(p.id).replace(/^bg-/, ''), 10)
      if (!isNaN(num)) maxNum = Math.max(maxNum, num)
      // On page refresh, only restore running tasks
      // Completed/error tasks are just notifications and shouldn't persist across reloads
      if (p.status !== 'running') continue
      tasks.push({
        id: p.id,
        reportId: p.reportId ?? null,
        type: p.type ?? 'info',
        title: p.title ?? i18n.global.t('common.processing'),
        status: p.status ?? 'running',
        error: p.error ?? null,
        startedAt: p.startedAt ?? now,
        finishedAt: p.finishedAt ?? null,
      })
    }
    nextId = maxNum + 1
    // Clean up sessionStorage if we skipped any finished tasks
    if (tasks.length !== storedTasks.length) {
      persist()
    }
  } catch (_) {}
}

rehydrate()

export function addBackgroundTask({ reportId, type, title, data = null }) {
  const id = `bg-${nextId++}`
  const task = {
    id,
    reportId: reportId || null,
    type, // 'summaries' | 'finding' | 'master-docx' | etc.
    title: title || i18n.global.t('common.processing'),
    status: 'running',
    error: null,
    startedAt: Date.now(),
    data: data || null,  // Store additional data (e.g., generated content for review)
  }
  tasks.push(task)
  persist()
  return id
}

/** Default dismiss delay for non-actionable tasks (ms). */
const DEFAULT_DISMISS_MS = 3000
/** Longer delay for actionable tasks (finding, summaries) so user has time to click. */
const ACTIONABLE_DISMISS_MS = 20 * 1000

export function finishBackgroundTask(id, { error = null, title = null, data = null, dismissAfterMs } = {}) {
  const task = tasks.find((t) => t.id === id)
  if (task) {
    task.status = error ? 'error' : 'completed'
    task.error = error || null
    if (title) task.title = title
    if (data) task.data = data  // Store completion data (e.g., generated content)
    task.finishedAt = Date.now()
    persist()
    const delay =
      dismissAfterMs ??
      (task.reportId && task.type === 'finding' ? ACTIONABLE_DISMISS_MS : DEFAULT_DISMISS_MS)
    setTimeout(() => {
      const i = tasks.indexOf(task)
      if (i !== -1) tasks.splice(i, 1)
      persist()
    }, delay)
  }
}

export function getBackgroundTask(id) {
  return tasks.find((t) => t.id === id)
}

export function getBackgroundTasks() {
  return tasks
}

export function isReportTaskRunning(reportId, type = null) {
  return tasks.some(
    (t) => t.reportId === reportId && t.status === 'running' && (type == null || t.type === type)
  )
}

export function hasAnyRunningTasks() {
  return tasks.some((t) => t.status === 'running')
}

export const backgroundTasks = tasks
