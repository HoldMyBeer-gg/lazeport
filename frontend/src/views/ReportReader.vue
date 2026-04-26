<script setup>
/**
 * ReportReader – A clean, reader-optimized view of report findings.
 *
 * Designed to trigger browser Reader View (Chrome, Vivaldi, Firefox, Safari)
 * by using proper semantic HTML: <article>, <section>, <h1>–<h3>, <p>, <dl>.
 *
 * Accessibility: WCAG 2.1 AA compliant structure with proper landmarks,
 * heading hierarchy, and descriptive text.
 */
import { onMounted, ref, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request } from '../services/api'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const reportId = route.params.id

const report = ref(null)
const clientName = ref('')
const applicationName = ref('')
const findings = ref([])
const loading = ref(true)
const error = ref('')

/* ── Section ordering and classification ── */
const META_KEYS = ['Severity', 'CVSS v3.1', 'CWE', 'CVE', 'OWASP', 'Affected Roles', 'Confidence']
const PROSE_KEYS = [
  'Vulnerability Summary', 'Summary', 'Justification', 'Rationale',
  'Root Cause', 'Details', 'Remediation', 'Additional Notes', 'References'
]
const SKIP_KEYS = new Set([...META_KEYS, ...PROSE_KEYS, 'Finding Title', 'Title', 'title', 'severity'])

function parseContent(jsonStr) {
  try { return JSON.parse(jsonStr || '{}') } catch { return {} }
}

/* ── Markdown renderer: heading levels remapped to avoid h1–h3 conflicts ── */
function renderMarkdown(text) {
  if (!text || !String(text).trim()) return ''
  let html = marked(String(text), { breaks: true, gfm: true })
  html = html
    .replace(/<(\/?)h1(\s|>)/gi, '<$1h5$2')
    .replace(/<(\/?)h2(\s|>)/gi, '<$1h6$2')
    .replace(/<(\/?)h3(\s|>)/gi, '<$1h6$2')
  return DOMPurify.sanitize(html)
}

function getMetaEntries(data) {
  const entries = []
  for (const key of META_KEYS) {
    const val = String(data[key] ?? '').trim()
    if (val) entries.push({ key, val })
  }
  return entries
}

function getProseEntries(data) {
  const entries = []
  for (const key of PROSE_KEYS) {
    const val = String(data[key] ?? '').trim()
    if (val) entries.push({ key, val })
  }
  for (const [key, val] of Object.entries(data)) {
    if (!SKIP_KEYS.has(key) && !META_KEYS.includes(key) && val != null && String(val).trim()) {
      entries.push({ key, val: String(val).trim() })
    }
  }
  return entries
}

/* ── Hyperlink CWE, CVE, OWASP, CVSS in meta and prose ── */
const OWASP_2021 = {
  '1': 'A01_2021-Broken_Access_Control', '2': 'A02_2021-Cryptographic_Failures', '3': 'A03_2021-Injection',
  '4': 'A04_2021-Insecure_Design', '5': 'A05_2021-Security_Misconfiguration', '6': 'A06_2021-Vulnerable_and_Outdated_Components',
  '7': 'A07_2021-Identification_and_Authentication_Failures', '8': 'A08_2021-Software_and_Data_Integrity_Failures',
  '9': 'A09_2021-Security_Logging_and_Monitoring_Failures', '10': 'A10_2021-Server-Side_Request_Forgery_%28SSRF%29',
}
const OWASP_2017 = {
  '1': 'A1_2017-Injection', '2': 'A2_2017-Broken_Authentication', '3': 'A3_2017-Sensitive_Data_Exposure',
  '4': 'A4_2017-XML_External_Entities_%28XXE%29', '5': 'A5_2017-Broken_Access_Control', '6': 'A6_2017-Security_Misconfiguration',
  '7': 'A7_2017-Cross-Site_Scripting_%28XSS%29', '8': 'A8_2017-Insecure_Deserialization',
  '9': 'A9_2017-Using_Components_with_Known_Vulnerabilities', '10': 'A10_2017-Insufficient_Logging%26Monitoring',
}
function cweToUrl(id) { return `https://cwe.mitre.org/data/definitions/${id}.html` }
function cveToUrl(id) { return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}` }
function owaspToUrl(num, year) {
  const n = String(parseInt(num, 10))
  if (year === '2017' && OWASP_2017[n]) return `https://owasp.org/www-project-top-ten/2017/${OWASP_2017[n]}`
  if ((!year || year === '2021') && OWASP_2021[n]) return `https://owasp.org/Top10/${OWASP_2021[n]}/`
  return 'https://owasp.org/Top10/'
}
function cvssVectorToUrl(vector) {
  const v = vector.startsWith('CVSS:3') ? vector : `CVSS:3.1/${vector}`
  return `https://www.first.org/cvss/calculator/3.1#${v}`
}
function hyperlinkMetaParts(key, val) {
  const text = String(val || '')
  if (!text.trim()) return [{ text: '' }]
  if (key === 'CWE') {
    const m = text.match(/CWE-(\d+)/i)
    if (m && /^\d+$/.test(m[1])) return [{ text, href: cweToUrl(m[1]) }]
  }
  if (key === 'CVE') {
    const m = text.match(/CVE-\d{4}-\d{4,7}/i)
    if (m) return [{ text, href: cveToUrl(m[0]) }]
  }
  if (key === 'OWASP') {
    const m = text.match(/A(\d{1,2})(?::?(20\d{2}))?/i)
    if (m) return [{ text, href: owaspToUrl(m[1], m[2]) }]
  }
  if (key === 'CVSS v3.1') {
    const fullVector = text.match(/CVSS:3\.\d\/(?:[A-Z]+:[A-Z]+\/?)+/i)?.[0]
    const shorthandVector = text.match(/AV:[A-Z]\/AC:[A-Z]\/PR:[A-Z]\/UI:[A-Z]\/S:[A-Z]\/C:[A-Z]\/I:[A-Z]\/A:[A-Z]/i)?.[0]
    const vector = fullVector || shorthandVector
    if (vector) {
      const url = cvssVectorToUrl(vector)
      const idx = text.indexOf(vector)
      if (idx >= 0) {
        const parts = []
        if (idx > 0) parts.push({ text: text.slice(0, idx) })
        parts.push({ text: vector, href: url })
        if (idx + vector.length < text.length) parts.push({ text: text.slice(idx + vector.length) })
        return parts
      }
      return [{ text, href: url }]
    }
  }
  return [{ text }]
}
const IDENTIFIER_RE = /(CVE-\d{4}-\d{4,7}|CWE-\d{1,5}|A\d{1,2}(?::20\d{2})?|CVSS:3\.\d\/(?:[A-Z]+:[A-Z]+\/?)+|AV:[A-Z]\/AC:[A-Z]\/PR:[A-Z]\/UI:[A-Z]\/S:[A-Z]\/C:[A-Z]\/I:[A-Z]\/A:[A-Z])/gi
function linkifyProse(text) {
  if (!text || !String(text).trim()) return []
  const str = String(text)
  const parts = []
  let last = 0
  let m
  const re = new RegExp(IDENTIFIER_RE.source, 'gi')
  while ((m = re.exec(str)) !== null) {
    if (m.index > last) parts.push({ text: str.slice(last, m.index) })
    const token = m[0]
    let href = null
    if (/^CVE-/i.test(token)) href = cveToUrl(token)
    else if (/^CWE-/i.test(token)) href = cweToUrl(token.replace(/\D/g, ''))
    else if (/^A\d/i.test(token)) {
      const ym = token.match(/A(\d{1,2})(?::(20\d{2}))?/i)
      if (ym) href = owaspToUrl(ym[1], ym[2])
    } else if (/^CVSS:3|^AV:[A-Z]/i.test(token)) href = cvssVectorToUrl(token)
    parts.push(href ? { text: token, href } : { text: token })
    last = m.index + token.length
  }
  if (last < str.length) parts.push({ text: str.slice(last) })
  return parts.length ? parts : [{ text: str }]
}

/* ── Severity labels for display ── */
function severityLabel(sev) {
  const key = `reportReader.severity${sev.charAt(0).toUpperCase() + sev.slice(1)}`
  return t(key)
}

/* ── Severity sorting ── */
const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }

function severity(finding) {
  try {
    const c = parseContent(finding.content_json)
    let sev = (c.Severity || c.severity || '').toLowerCase().trim()
    if (sev === 'information') sev = 'informational'
    return sev
  } catch { return '' }
}

const sortedFindings = computed(() => {
  return [...findings.value].sort((a, b) => {
    const sevA = severity(a) || 'informational'
    const sevB = severity(b) || 'informational'
    return (severityOrder[sevA] ?? 999) - (severityOrder[sevB] ?? 999)
  })
})

/* ── Severity statistics ── */
const severityStats = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  for (const f of findings.value) {
    const sev = severity(f) || 'informational'
    if (sev in counts) counts[sev]++
  }
  return Object.entries(counts).filter(([, v]) => v > 0)
})

/* ── Data loading ── */
async function loadData() {
  loading.value = true
  error.value = ''
  try {
    const [reportData, findingsData] = await Promise.all([
      request(`/api/admin/reports/${reportId}`),
      request(`/api/admin/findings?report_id=${reportId}`),
    ])
    report.value = reportData
    
    // Filter out False Positive findings from reader view
    findings.value = findingsData.filter(f => {
      const content = parseContent(f.content_json)
      const confidence = (content.Confidence || '').trim()
      return confidence !== 'False Positive'
    })
    // Resolve client + application names
    try {
      const [clientsData, appsData] = await Promise.all([
        request('/api/admin/clients'),
        request('/api/admin/applications'),
      ])
      if (reportData?.client_id) {
        const match = clientsData.find(t => t.id === reportData.client_id)
        clientName.value = match?.name || ''
      }
      if (reportData?.application_id) {
        const match = appsData.find(a => a.id === reportData.application_id)
        applicationName.value = match?.name || ''
      }
    } catch { /* optional */ }
  } catch (e) {
    error.value = e.message || t('reportReader.failedToLoadReport')
  } finally {
    loading.value = false
  }
}

/* ── Dynamic page title for Reader View ── */
function updatePageTitle() {
  if (report.value?.name) {
    document.title = t('reportReader.reportTitleFormat', { name: report.value.name })
  }
}

/* ── Print support ── */
function printReport() {
  window.print()
}

function goBack() {
  router.push(`/dashboard/reports/${reportId}/findings`)
}

onMounted(async () => {
  await loadData()
  updatePageTitle()
})
</script>

<template>
  <div v-if="loading" class="reader-loading" role="status" aria-live="polite">
    <p>{{ $t('reportReader.loadingReport') }}</p>
  </div>

  <div v-else-if="error" class="reader-error" role="alert">
    <h1>{{ $t('reportReader.errorLoadingReport') }}</h1>
    <p>{{ error }}</p>
    <button @click="goBack">{{ $t('reportReader.backToReport') }}</button>
  </div>

  <article v-else class="reader-article" aria-labelledby="reader-title">
    <!-- Toolbar (hidden from Reader View by using nav element) -->
    <nav class="reader-toolbar no-print" aria-label="Reader view controls">
      <button @click="goBack" class="reader-back" :aria-label="$t('reportReader.backToEditorAriaLabel')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
        {{ $t('reportReader.backToEditor') }}
      </button>
      <button @click="printReport" class="reader-print" :aria-label="$t('reportReader.printAriaLabel')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
        {{ $t('reportReader.print') }}
      </button>
    </nav>

    <!-- Report header -->
    <header class="reader-header">
      <h1 id="reader-title">{{ report?.name || $t('reportReader.securityAssessmentReport') }}</h1>
      <p class="reader-subtitle" v-if="applicationName || clientName">
        <span v-if="applicationName"><strong>{{ applicationName }}</strong></span>
        <span v-if="applicationName && clientName"> · </span>
        <span v-if="clientName">{{ $t('reportReader.clientLabel') }} <strong>{{ clientName }}</strong></span>
      </p>
      <p class="reader-meta">
        {{ sortedFindings.length === 1 ? $t('reportReader.findingsIdentified', { count: sortedFindings.length }) : $t('reportReader.findingsIdentifiedPlural', { count: sortedFindings.length }) }}
        <span v-if="severityStats.length"> -
          <span v-for="([sev, count], i) in severityStats" :key="sev">
            {{ count }} {{ severityLabel(sev) }}<span v-if="i < severityStats.length - 1">, </span>
          </span>
        </span>
      </p>
    </header>

    <!-- Executive Summary -->
    <section v-if="report?.summary_executive" class="reader-section" aria-labelledby="reader-exec-heading">
      <h2 id="reader-exec-heading">{{ $t('reportReader.executiveSummary') }}</h2>
      <p>{{ report.summary_executive }}</p>
    </section>

    <!-- Technical Summary -->
    <section v-if="report?.summary_technical" class="reader-section" aria-labelledby="reader-tech-heading">
      <h2 id="reader-tech-heading">{{ $t('reportReader.technicalSummary') }}</h2>
      <p>{{ report.summary_technical }}</p>
    </section>

    <!-- Recommendations -->
    <section v-if="report?.summary_recommendations" class="reader-section" aria-labelledby="reader-rec-heading">
      <h2 id="reader-rec-heading">{{ $t('reportReader.recommendations') }}</h2>
      <p>{{ report.summary_recommendations }}</p>
    </section>

    <!-- Findings -->
    <section class="reader-section" aria-labelledby="reader-findings-heading">
      <h2 id="reader-findings-heading">{{ $t('reportReader.detailedFindings') }}</h2>

      <p v-if="!sortedFindings.length" class="reader-empty">
        {{ $t('reportReader.noFindingsYet') }}
      </p>

      <article
        v-for="(finding, idx) in sortedFindings"
        :key="finding.id"
        class="reader-finding"
        :aria-labelledby="`finding-title-${finding.id}`"
      >
        <h3 :id="`finding-title-${finding.id}`">
          <span class="reader-finding-num">{{ idx + 1 }}.</span>
          {{ finding.title || $t('reportReader.untitledFinding') }}
        </h3>

        <!-- Metadata as definition list (CWE, CVE, OWASP, CVSS hyperlinked) -->
        <dl v-if="getMetaEntries(parseContent(finding.content_json)).length" class="reader-dl">
          <template v-for="m in getMetaEntries(parseContent(finding.content_json))" :key="m.key">
            <dt>{{ m.key }}</dt>
            <dd :class="m.key === 'Severity' ? `sev-${m.val.toLowerCase()}` : ''">
              <template v-for="(part, pidx) in hyperlinkMetaParts(m.key, m.val)" :key="pidx">
                <a v-if="part.href" :href="part.href" target="_blank" rel="noopener noreferrer">{{ part.text }}</a>
                <span v-else>{{ part.text }}</span>
              </template>
            </dd>
          </template>
        </dl>

        <!-- Prose sections (CVE/CWE/OWASP/CVSS in text hyperlinked) -->
        <section
          v-for="s in getProseEntries(parseContent(finding.content_json))"
          :key="s.key"
          class="reader-prose-section"
        >
          <h4>{{ s.key }}</h4>
          <p>
            <template v-for="(part, pidx) in linkifyProse(s.val)" :key="pidx">
              <a v-if="part.href" :href="part.href" target="_blank" rel="noopener noreferrer">{{ part.text }}</a>
              <span v-else>{{ part.text }}</span>
            </template>
          </p>
        </section>

        <!-- Validation Guidance (separate DB field, not in content_json) -->
        <section
          v-if="finding.validation_guidance && finding.validation_guidance.trim()"
          class="reader-prose-section"
          :aria-label="$t('reportReader.validationGuidance')"
        >
          <h4>{{ $t('reportReader.validationGuidance') }}</h4>
          <div class="markdown-prose" v-html="renderMarkdown(finding.validation_guidance)"></div>
        </section>

        <p v-if="!getProseEntries(parseContent(finding.content_json)).length && !getMetaEntries(parseContent(finding.content_json)).length && !finding.validation_guidance?.trim()" class="reader-empty">
          {{ $t('reportReader.noStructuredContent') }}
        </p>
      </article>
    </section>

    <!-- Footer -->
    <footer class="reader-footer no-print">
      <p>
        {{ $t('reportReader.generatedBy') }}
        <a href="#" @click.prevent="goBack">{{ $t('reportReader.returnToEditor') }}</a>.
      </p>
    </footer>
  </article>
</template>

<style scoped>
.reader-loading,
.reader-error {
  padding: 2rem;
  text-align: center;
}

.reader-error h1 {
  font-size: 1.25rem;
  margin-bottom: 0.5rem;
}

.reader-error button {
  margin-top: 1rem;
}

.reader-article {
  max-width: 48rem;
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
  font-family: var(--font-sans, system-ui, sans-serif);
  font-size: 1rem;
  line-height: 1.6;
  color: var(--text-primary, #1a1a1a);
}

.reader-toolbar {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 2rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--border, #e5e7eb);
}

.reader-back,
.reader-print {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
  background: var(--bg-input, #f3f4f6);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-primary);
  cursor: pointer;
}

.reader-back:hover,
.reader-print:hover {
  background: var(--bg-hover-solid, #e5e7eb);
}

.reader-header {
  margin-bottom: 2rem;
}

.reader-article h1 {
  font-size: 1.75rem;
  font-weight: 700;
  margin: 0 0 0.5rem;
  line-height: 1.3;
}

.reader-subtitle {
  font-size: 1rem;
  color: var(--text-secondary, #4b5563);
  margin: 0 0 0.25rem;
}

.reader-meta {
  font-size: 0.875rem;
  color: var(--text-muted, #6b7280);
  margin: 0;
}

.reader-section {
  margin-bottom: 2.5rem;
}

.reader-section h2 {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 1rem;
  padding-bottom: 0.25rem;
  border-bottom: 1px solid var(--border);
}

.reader-section h2 + p {
  margin: 0;
}

.reader-section p {
  margin: 0 0 1rem;
}

.reader-section p:last-child {
  margin-bottom: 0;
}

.reader-finding {
  margin-bottom: 2.5rem;
  padding-bottom: 2rem;
  border-bottom: 1px solid var(--border);
}

.reader-finding:last-child {
  border-bottom: none;
}

.reader-finding h3 {
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0 0 0.75rem;
  line-height: 1.4;
}

.reader-finding-num {
  margin-right: 0.25rem;
  color: var(--text-muted);
}

.reader-dl {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.25rem 1.5rem;
  margin: 0 0 1.25rem;
  font-size: 0.875rem;
}

.reader-dl dt {
  font-weight: 600;
  color: var(--text-secondary);
  margin: 0;
}

.reader-dl dd {
  margin: 0;
}

.reader-dl dd.sev-critical {
  color: var(--sev-critical-text);
  font-weight: 600;
}

.reader-dl dd.sev-high {
  color: var(--sev-high-text);
  font-weight: 600;
}

.reader-dl dd.sev-medium {
  color: var(--sev-medium-text);
  font-weight: 600;
}

.reader-dl dd.sev-low {
  color: var(--sev-low-text);
  font-weight: 600;
}

.reader-dl dd.sev-informational {
  color: var(--sev-info-text);
}

.reader-prose-section {
  margin-bottom: 1.25rem;
}

.reader-prose-section h4 {
  font-size: 0.9375rem;
  font-weight: 600;
  margin: 0 0 0.35rem;
  color: var(--text-secondary);
}

.reader-prose-section p {
  margin: 0;
  font-size: 0.9375rem;
}

.reader-empty {
  color: var(--text-muted);
  font-style: italic;
  margin: 0;
}

.reader-footer {
  margin-top: 3rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
  font-size: 0.875rem;
  color: var(--text-muted);
}

.reader-footer a {
  color: var(--color-link, var(--primary, #0d9488));
  text-decoration: underline;
}

.reader-footer a:hover {
  text-decoration: none;
}

@media print {
  .no-print {
    display: none !important;
  }

  .reader-article {
    padding: 0;
    max-width: none;
  }

  .reader-toolbar {
    display: none;
  }

  .reader-finding {
    break-inside: avoid;
    page-break-inside: avoid;
  }
}
</style>
