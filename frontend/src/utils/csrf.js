/**
 * CSRF Token Utilities
 *
 * Implements client-side CSRF protection using Double Submit Cookie pattern.
 * The server sets an HttpOnly cookie and returns the token in the response body.
 * We fetch the token from GET /auth/csrf and send it in the X-CSRF-Token header.
 */

let cachedToken = null

/**
 * Get CSRF token (cached). Fetches from /auth/csrf if not yet loaded.
 * @returns {Promise<string|null>} CSRF token or null
 */
export async function getCsrfToken() {
  if (cachedToken) return cachedToken
  try {
    const base = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE) || ''
    const res = await fetch(`${base}/auth/csrf`, { credentials: 'include' })
    if (res.ok) {
      const data = await res.json()
      cachedToken = data.token || null
      return cachedToken
    }
  } catch (_) {}
  return null
}

/**
 * Get CSRF token synchronously (returns cached value only; may be null before first fetch)
 * @returns {string|null}
 */
export function getCsrfTokenSync() {
  return cachedToken
}

/**
 * Add CSRF token to request headers (async; fetches token if needed)
 * @param {Headers|Object} headers - Headers object or plain object
 * @returns {Promise<Headers|Object>} Headers with CSRF token added
 */
export async function addCsrfHeader(headers = {}) {
  const token = await getCsrfToken()
  const out = headers instanceof Headers ? headers : { ...headers }
  if (token) {
    if (out instanceof Headers) {
      out.set('X-CSRF-Token', token)
    } else {
      out['X-CSRF-Token'] = token
    }
  }
  return out
}

/**
 * Fetch wrapper that automatically adds CSRF token
 * @param {string} url - URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} Fetch response
 */
export async function fetchWithCsrf(url, options = {}) {
  // Only add CSRF token for state-changing methods
  const method = (options.method || 'GET').toUpperCase()
  const stateChangingMethods = ['POST', 'PUT', 'DELETE', 'PATCH']
  
  if (stateChangingMethods.includes(method)) {
    options.headers = await addCsrfHeader(options.headers || {})
  }

  return fetch(url, options)
}
