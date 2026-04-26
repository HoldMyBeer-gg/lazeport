import { addCsrfHeader } from '../utils/csrf'

const apiBase = import.meta.env.VITE_API_BASE || ''

export async function request(path, options = {}) {
  // Prepare headers with CSRF token for state-changing requests
  const method = (options.method || 'GET').toUpperCase()
  const stateChangingMethods = ['POST', 'PUT', 'DELETE', 'PATCH']
  
  // Don't set Content-Type for FormData (browser sets it with boundary)
  const isFormData = options.body instanceof FormData
  let headers = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(options.headers || {})
  }
  
  // Add CSRF token for state-changing methods
  if (stateChangingMethods.includes(method)) {
    headers = await addCsrfHeader(headers)
  }

  const res = await fetch(`${apiBase}${path}`, {
    credentials: 'include',
    headers,
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    // Handle structured detail (rate limit, LLM errors with i18n code)
    if (err.detail && typeof err.detail === 'object') {
      const message = err.detail.message || 'Request failed'
      const secondsRemaining = err.detail.seconds_remaining
      if (secondsRemaining !== undefined) {
        const e = new Error('rate_limit')
        e.code = 'rate_limit'
        e.secondsRemaining = secondsRemaining
        throw e
      }
      const e = new Error(message)
      if (err.detail.code) e.code = err.detail.code
      throw e
    }
    throw new Error(err.detail || res.statusText)
  }
  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return res.json()
  }
  return res.text()
}

export async function getSessionUser() {
  try {
    return await request('/api/me')
  } catch {
    return null
  }
}

export async function loginLocal(username, password) {
  return request('/auth/login/local', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
}

export async function loginUser(email, password) {
  return request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
}

export async function acceptInvite(token, password, name = '') {
  return request('/auth/invite/accept', {
    method: 'POST',
    body: JSON.stringify({ token, password, name }),
  })
}

export async function logout() {
  return request('/auth/logout', { method: 'POST' })
}
