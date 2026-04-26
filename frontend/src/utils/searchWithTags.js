/**
 * Parse a search string that may contain @tag tokens.
 * Use for unified search + tag filter (e.g. "login @owasp" filters by text "login" and tag "owasp").
 * Reusable across Reports, Applications, Teams, or any page with a search box and tag filter.
 *
 * @param {string} input - Raw search input (e.g. "login @owasp" or "API @PCI DSS")
 * @returns {{ query: string, tag: string }} - query: text to search (no @token); tag: last @token value or ""
 */
export function parseSearchWithTags(input) {
  if (typeof input !== 'string') return { query: '', tag: '' }
  const s = input.trim()
  if (!s) return { query: '', tag: '' }
  // Match @token (token = one or more word chars, spaces, periods - tag name style). Global.
  const atRegex = /@([a-zA-Z0-9 .]+?)(?=\s*@|$)/g
  const tags = []
  let m
  while ((m = atRegex.exec(s)) !== null) {
    tags.push(m[1].trim())
  }
  const tag = tags.length ? tags[tags.length - 1] : ''
  const query = s.replace(/@[a-zA-Z0-9 .]+?(?=\s*@|$)/g, '').replace(/\s+/g, ' ').trim()
  return { query, tag }
}

/**
 * Build display string from query + tag (inverse of parseSearchWithTags for syncing input display).
 * @param {string} query
 * @param {string} tag
 * @returns {string}
 */
export function formatSearchWithTag(query, tag) {
  const q = (query || '').trim()
  const t = (tag || '').trim()
  if (!t) return q
  return q ? `${q} @${t}` : `@${t}`
}
