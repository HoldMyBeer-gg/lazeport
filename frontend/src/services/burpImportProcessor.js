/**
 * Generic import processor for security scan findings (Burp, SARIF, etc.)
 * Tasks run on the backend (Celery) and survive page refresh.
 *
 * LLM settings are passed in from the calling component (which injects
 * orgLlmSettings via Vue provide/inject). No localStorage access.
 */
import { request } from './api'

/**
 * Enqueue security scan import tasks for server-side processing.
 *
 * @param {Object} opts
 * @param {string} opts.sessionId
 * @param {string} opts.reportId
 * @param {number[]} opts.taskIndices - indices to process (pending or failed)
 * @param {Object} [opts.llmSettings] - org LLM settings from injected ref
 */
export async function startBurpImportProcessing({ sessionId, reportId, taskIndices, llmSettings }) {
  if (!taskIndices || taskIndices.length === 0) return
  const s = llmSettings || {}
  await request('/api/admin/burp-import/enqueue', {
    method: 'POST',
    body: JSON.stringify({
      session_id: sessionId,
      task_indices: taskIndices,
      llm_provider: s.provider || null,
      llm_model: s.model || null,
      llm_base_url: s.base_url || null,
      llm_timeout: s.timeout || null,
      sampling_params: s.sampling_params || null,
    })
  })
}

/**
 * LOW-3: Atomically reset tasks to pending and enqueue (avoids reset-then-enqueue race).
 */
export async function resetAndEnqueueBurpImport({ sessionId, reportId, taskIndices, llmSettings }) {
  if (!taskIndices || taskIndices.length === 0) return
  const s = llmSettings || {}
  await request(`/api/admin/import-sessions/${sessionId}/reset-and-enqueue`, {
    method: 'POST',
    body: JSON.stringify({
      task_indices: taskIndices,
      llm_provider: s.provider || null,
      llm_model: s.model || null,
      llm_base_url: s.base_url || null,
      llm_timeout: s.timeout || null,
      sampling_params: s.sampling_params || null,
    })
  })
}
