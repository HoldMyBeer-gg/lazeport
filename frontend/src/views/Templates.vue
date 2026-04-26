<script setup>
import { onMounted, ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { marked } from 'marked'
import { request, getSessionUser } from '../services/api'
import { addCsrfHeader } from '../utils/csrf'
import { setStatus } from '../stores/status'
import { showConfirm } from '../composables/useConfirm'
import Modal from '../components/Modal.vue'

const { t } = useI18n()
const tab = ref('finding')

/* ── Finding Templates ── */
const templates = ref([])
const showModal = ref(false)
const modalTitle = ref('')
const editingId = ref(null)
const formName = ref('')
const formContent = ref('')
const currentUserId = ref(null)
const isOrgAdmin = ref(false)
const canCreateTemplates = ref(false)

/* ── Live preview parser (mirrors backend template_parse.py) ── */
function headingsFromMarkdown(text) {
  const keys = []
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed.startsWith('#')) {
      const heading = trimmed.replace(/^#+\s*/, '').trim()
      if (heading) keys.push(heading)
    }
  }
  return keys
}

function headingsFromHtml(text) {
  const keys = []
  const seen = new Set()
  // h1–h4
  for (const m of text.matchAll(/<h([1-4])[^>]*>([^<]+)<\/h\1>/gi)) {
    const title = m[2].trim()
    if (title && !seen.has(title)) { keys.push(title); seen.add(title) }
  }
  // <b> and <strong>
  for (const m of text.matchAll(/<(?:b|strong)[^>]*>([^<]+)<\/(?:b|strong)>/gi)) {
    const title = m[1].trim()
    if (title && !seen.has(title)) { keys.push(title); seen.add(title) }
  }
  return keys
}

function extractSectionKeys(template) {
  const t = (template || '').trim()
  if (!t) return ['Summary', 'Details', 'Remediation', 'References']
  const looksHtml = t.includes('<') && (t.includes('</') || /<h/i.test(t) || /<b>/i.test(t) || /<strong>/i.test(t))
  const keys = looksHtml ? headingsFromHtml(t) : headingsFromMarkdown(t)
  return keys.length ? keys : ['Summary', 'Details', 'Remediation', 'References']
}

function extractTableRows(template) {
  const t = (template || '').trim()
  if (!t || !/<table/i.test(t)) return []
  const tableMatch = t.match(/<table[^>]*>([\s\S]*?)<\/table>/i)
  if (!tableMatch) return []
  const tableBody = tableMatch[1]
  const labels = []
  for (const tr of tableBody.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const tdMatch = tr[1].match(/<td[^>]*>([\s\S]*?)<\/td>/i)
    if (tdMatch) {
      const label = tdMatch[1].replace(/<[^>]+>/g, '').trim()
      if (label) labels.push(label)
    }
  }
  return labels
}

const META_KEYS = new Set(['Severity', 'CVSS v3.1', 'CWE', 'CVE', 'OWASP', 'Affected Roles'])

const previewSections = computed(() => {
  const keys = extractSectionKeys(formContent.value)
  const tableRows = extractTableRows(formContent.value)
  const meta = []
  const prose = []

  // Collect meta from table rows
  for (const row of tableRows) {
    if (!meta.find(m => m.label === row)) {
      meta.push({ label: row, value: sampleMetaValue(row) })
    }
  }

  // Sections: classify as meta or prose
  for (const key of keys) {
    if (META_KEYS.has(key)) {
      if (!meta.find(m => m.label === key)) {
        meta.push({ label: key, value: sampleMetaValue(key) })
      }
    } else {
      prose.push({ title: key, body: sampleProseValue(key) })
    }
  }

  return { meta, prose }
})

/** Full HTML document for live preview, rendering markdown and supporting both HTML/CSS. */
const previewDoc = computed(() => {
  const raw = (formContent.value || '').trim()
  if (!raw) return ''

  try {
    // Check if content looks like HTML or markdown
    const looksHtml = raw.includes('<') && (raw.includes('</') || /<h/i.test(raw) || /<b>/i.test(raw) || /<strong>/i.test(raw))
    const html = looksHtml ? raw : marked(raw, { breaks: true, gfm: true })

    // Escape backticks and special chars for safe srcdoc injection
    const safe = html.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$')
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; margin: 12px; font-size: 13px; } h1, h2, h3, h4, h5, h6 { margin: 12px 0 6px 0; } h1 { font-size: 18px; } h2 { font-size: 16px; } h3 { font-size: 14px; } p { margin: 6px 0; } ul, ol { margin: 6px 0; padding-left: 20px; } li { margin: 3px 0; } code { background: #f5f5f5; padding: 2px 4px; border-radius: 2px; font-family: monospace; font-size: 12px; } pre { background: #f5f5f5; padding: 8px; border-radius: 4px; overflow-x: auto; } pre code { background: none; padding: 0; } blockquote { margin: 8px 0; padding-left: 12px; border-left: 3px solid #ddd; color: #666; } a { color: #0066cc; text-decoration: none; } a:hover { text-decoration: underline; }</style></head><body>${safe}</body></html>`
  } catch (e) {
    // Fallback to raw HTML if markdown parsing fails
    const safe = raw.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$')
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body>${safe}</body></html>`
  }
})

function sampleMetaValue(label) {
  const samples = {
    'Severity': 'High',
    'CVSS v3.1': '7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)',
    'CWE': 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    'CVE': 'CVE-2024-12345',
    'OWASP': 'A03:2021 – Injection',
    'Affected Roles': 'All Users',
  }
  return samples[label] || '—'
}

function sampleProseValue(title) {
  const samples = {
    'Vulnerability Summary': 'The application is vulnerable to reflected cross-site scripting (XSS) in the search parameter, allowing an attacker to execute arbitrary JavaScript in the context of a victim\'s browser session.',
    'Summary': 'A critical vulnerability was identified that could allow unauthorized access to sensitive data.',
    'Justification': 'This finding is rated High severity because it can be exploited remotely without authentication and impacts the confidentiality of user data.',
    'Rationale': 'The lack of input validation on user-supplied data allows injection of malicious payloads.',
    'Root Cause': 'User input is reflected in the response without proper output encoding or sanitization.',
    'Details': 'During testing, the parameter "q" on /search was found to reflect user input directly into the HTML response without encoding.',
    'Remediation': 'Implement context-aware output encoding for all user-supplied data. Use a Content Security Policy (CSP) header to mitigate the impact of XSS.',
    'Additional Notes': 'This issue was confirmed on both the staging and production environments.',
    'References': 'OWASP XSS Prevention Cheat Sheet\nhttps://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html',
  }
  return samples[title] || 'Sample content for this section would appear here based on AI-generated analysis of the vulnerability.'
}

async function loadTemplates() {
  templates.value = await request('/api/admin/finding-templates')
}

function openAdd() {
  editingId.value = null
  formName.value = ''
  formContent.value = ''
  modalTitle.value = t('templates.newFindingTemplate')
  showModal.value = true
}

function openEdit(tpl) {
  editingId.value = tpl.id
  formName.value = tpl.name
  formContent.value = tpl.content
  modalTitle.value = t('templates.editFindingTemplate')
  showModal.value = true
}

async function saveTemplate() {
  try {
    const body = JSON.stringify({ name: formName.value, content: formContent.value })
    if (editingId.value) {
      setStatus(t('templates.updatingTemplate'), 'info')
      await request(`/api/admin/finding-templates/${editingId.value}`, { method: 'PUT', body })
    } else {
      setStatus(t('templates.creatingTemplate'), 'info')
      await request('/api/admin/finding-templates', { method: 'POST', body })
    }
    showModal.value = false
    await loadTemplates()
    setStatus(t('templates.templateSaved'), 'success')
  } catch (e) {
    setStatus(e.message || t('templates.saveFailed'), 'error')
  }
}

async function deleteTemplate(id) {
  const ok = await showConfirm({ message: t('templates.deleteTemplateConfirm'), danger: true })
  if (!ok) return
  setStatus(t('templates.deletingTemplate'), 'info')
  await request(`/api/admin/finding-templates/${id}`, { method: 'DELETE' })
  await loadTemplates()
  setStatus(t('templates.templateDeleted'), 'success')
}

/* ── Master DOCX ── */
const masterList = ref([])

function formatTokens(tokens) {
  if (!tokens || tokens.length === 0) return ''
  return tokens.map(t => '{{ ' + t + ' }}').join(', ')
}

async function loadMasterList() {
  masterList.value = await request('/api/master-templates')
}

async function uploadMaster(e) {
  const file = e.target.files?.[0]
  if (!file) return
  setStatus(t('templates.uploadingMaster'), 'info')
  const fd = new FormData()
  fd.append('file', file)
  
  const headers = await addCsrfHeader({})
  
  await fetch(`${import.meta.env.VITE_API_BASE || ''}/api/admin/master-templates/upload`, {
    method: 'POST',
    credentials: 'include',
    headers,
    body: fd,
  })
  e.target.value = ''
  await loadMasterList()
  setStatus(t('templates.masterUploaded'), 'success')
}

async function downloadMaster(name) {
  setStatus(t('templates.downloading'), 'info')
  try {
    const res = await fetch(`${import.meta.env.VITE_API_BASE || ''}/api/admin/master-templates/${name}/download`, {
      method: 'GET',
      credentials: 'include',
    })
    if (!res.ok) throw new Error('Download failed')
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${name}.docx`
    a.click()
    URL.revokeObjectURL(a.href)
    setStatus(t('templates.downloaded'), 'success')
  } catch (e) {
    setStatus(e.message || t('templates.downloadFailed'), 'error')
  }
}

async function deleteMaster(name) {
  const ok = await showConfirm({ message: t('templates.deleteMasterConfirm'), danger: true })
  if (!ok) return
  setStatus(t('templates.deletingMaster'), 'info')
  await request(`/api/admin/master-templates/${name}`, { method: 'DELETE' })
  await loadMasterList()
  setStatus(t('templates.masterDeleted'), 'success')
}

/* ── Master template tokens ── */
const tokenMap = ref({})

async function loadTokens(name) {
  try {
    const data = await request(`/api/admin/master-templates/${name}/tokens`)
    tokenMap.value[name] = data.tokens || []
  } catch {
    tokenMap.value[name] = []
  }
}

async function checkUserRole() {
  try {
    const user = await getSessionUser()
    currentUserId.value = user.id
    
    if (user.role === 'admin') {
      isOrgAdmin.value = true
      canCreateTemplates.value = true
      return
    }
    
    // Check organization role from user session
    if (user.org_role) {
      isOrgAdmin.value = ['org_admin', 'org_owner'].includes(user.org_role)
      canCreateTemplates.value = user.org_role !== 'readonly'
    } else {
      canCreateTemplates.value = false
    }
  } catch (err) {
    isOrgAdmin.value = false
    canCreateTemplates.value = false
  }
}

function canDeleteTemplate(template) {
  // User can delete if they created it OR they're an org admin
  return template.created_by === currentUserId.value || isOrgAdmin.value
}

const canEditCurrentTemplate = computed(() => {
  if (!editingId.value) return canCreateTemplates.value // Creating new template requires consultant+
  const currentTemplate = templates.value.find(t => t.id === editingId.value)
  if (!currentTemplate) return false
  return canDeleteTemplate(currentTemplate)
})

onMounted(async () => {
  await checkUserRole()
  await Promise.all([loadTemplates(), loadMasterList()])
  for (const name of masterList.value) {
    loadTokens(name)
  }
})
</script>

<template>
  <div class="org-hero">
    <div class="org-title">
      <p class="kicker">{{ $t('templates.title') }}</p>
      <h1>{{ $t('templates.heading') }}</h1>
      <p class="subtitle">{{ $t('templates.subtitle') }}</p>
    </div>
  </div>

  <div class="tabs" role="tablist">
    <button :class="['tab', tab === 'finding' && 'active']" @click="tab = 'finding'" role="tab" :aria-selected="tab === 'finding'" :aria-label="$t('templates.findingTabAriaLabel')">{{ $t('templates.findingTab') }}</button>
    <button :class="['tab', tab === 'master' && 'active']" @click="tab = 'master'" role="tab" :aria-selected="tab === 'master'" :aria-label="$t('templates.masterTabAriaLabel')">{{ $t('templates.masterTab') }}</button>
  </div>

  <!-- Finding Templates -->
  <div v-if="tab === 'finding'" class="card">
    <div class="topbar" style="margin-bottom:12px">
      <span class="section-header" style="border:none;margin:0;padding:0">{{ $t('templates.sectionTemplates') }}</span>
      <button v-if="canCreateTemplates" @click="openAdd" :aria-label="$t('templates.addTemplateAriaLabel')">{{ $t('templates.addTemplate') }}</button>
    </div>
    <div class="table-wrapper" v-if="templates.length">
      <table class="table">
      <thead>
        <tr>
          <th>{{ $t('common.name') }}</th>
          <th style="width:180px">{{ $t('templates.actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="tpl in templates" :key="tpl.id" class="clickable" @click="openEdit(tpl)">
          <td>{{ tpl.name }}</td>
          <td @click.stop>
            <div class="actions">
              <button v-if="canDeleteTemplate(tpl)" class="secondary" @click="openEdit(tpl)">{{ $t('common.edit') }}</button>
              <button v-if="canDeleteTemplate(tpl)" class="danger" @click="deleteTemplate(tpl.id)">{{ $t('common.delete') }}</button>
            </div>
          </td>
        </tr>
      </tbody>
      </table>
    </div>
    <p v-else class="muted">{{ $t('templates.noFindingTemplates') }}</p>
  </div>

  <!-- Master DOCX -->
  <div v-if="tab === 'master'" class="card">
    <div class="topbar" style="margin-bottom:12px">
      <span class="section-header" style="border:none;margin:0;padding:0">{{ $t('templates.masterDocxFiles') }}</span>
      <label v-if="isOrgAdmin" style="margin:0;text-transform:none">
        <input type="file" accept=".docx" @change="uploadMaster" style="display:none" />
        <span class="upload-btn" style="display:inline-block;padding:9px 16px;border-radius:8px;background: var(--btn-primary-bg, #0d9488);color:#fff;font-size:13px;font-weight:600;cursor:pointer">{{ $t('templates.uploadDocx') }}</span>
      </label>
    </div>
    <table class="table" v-if="masterList.length">
      <thead>
        <tr>
          <th>{{ $t('templates.file') }}</th>
          <th>{{ $t('templates.tokens') }}</th>
          <th style="width:220px">{{ $t('templates.actions') }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="name in masterList" :key="name">
          <td>{{ name }}.docx</td>
          <td>
            <span v-if="tokenMap[name]" class="muted">{{ formatTokens(tokenMap[name]) || $t('templates.tokensNone') }}</span>
          </td>
          <td>
            <div class="actions">
              <button class="secondary" @click="downloadMaster(name)">{{ $t('templates.download') }}</button>
              <button v-if="isOrgAdmin" class="danger" @click="deleteMaster(name)">{{ $t('common.delete') }}</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else class="muted">{{ $t('templates.noMasterDocx') }}</p>
  </div>

  <!-- Modal for adding/editing finding templates -->
  <Modal v-if="showModal" :title="modalTitle" extraWide @close="showModal = false">
    <div class="tpl-editor-grid">
      <!-- Left: editor -->
      <div class="tpl-editor-pane">
        <div>
          <label for="template-name" class="tpl-editor-label">{{ $t('common.name') }}</label>
          <input id="template-name" v-model="formName" :placeholder="$t('templates.namePlaceholder')" :aria-label="$t('templates.templateNameAriaLabel')" :readonly="editingId && !canEditCurrentTemplate" />
        </div>
        <div class="tpl-content-field">
          <label for="template-content" class="tpl-editor-label">{{ $t('templates.templateContentLabel') }}</label>
          <textarea id="template-content" v-model="formContent" rows="20" :placeholder="$t('templates.contentPlaceholder')" :aria-label="$t('templates.templateContentAriaLabel')" :readonly="editingId && !canEditCurrentTemplate"></textarea>
        </div>
        <div class="actions" style="justify-content:flex-end">
          <button class="secondary" @click="showModal = false" :aria-label="$t('templates.cancelEditingAriaLabel')">{{ $t('common.cancel') }}</button>
          <button v-if="!editingId || canEditCurrentTemplate" @click="saveTemplate" :disabled="!formName.trim()" :aria-label="$t('templates.saveTemplateAriaLabel')">{{ $t('common.save') }}</button>
        </div>
      </div>

      <!-- Right: live preview (renders template HTML/CSS in iframe so edits are visible) -->
      <div class="tpl-preview-pane">
        <div class="tpl-preview-label">{{ $t('templates.livePreview') }}</div>
        <div class="tpl-preview-scroll">
          <iframe
            v-if="previewDoc"
            :srcdoc="previewDoc"
            class="tpl-preview-iframe"
            title="Template preview"
          />
          <div v-else class="tpl-preview-empty">
            <p>{{ $t('templates.previewEmpty') }}</p>
            <p class="tpl-hint">{{ $t('templates.previewHintHeadings') }}</p>
            <p class="tpl-hint">{{ $t('templates.previewHintTable') }}</p>
          </div>
        </div>
      </div>
    </div>
  </Modal>
</template>

<style scoped>
.tpl-editor-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  min-height: 420px;
}
.tpl-editor-pane {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.tpl-content-field {
  flex: 1;
  display: flex;
  flex-direction: column;
}
.tpl-content-field textarea {
  flex: 1;
  min-height: 200px;
  resize: vertical;
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
  font-size: 12.5px;
  line-height: 1.5;
  tab-size: 2;
}
.tpl-preview-pane {
  display: flex;
  flex-direction: column;
  gap: 8px;
  border-left: 1px solid var(--border);
  padding-left: 24px;
}
/* Labels: sufficient contrast for accessibility (WCAG) */
.tpl-editor-label,
.tpl-preview-label {
  color: var(--text, var(--text-primary));
}
.tpl-editor-pane .tpl-editor-label {
  display: block;
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 4px;
}
.tpl-preview-label {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.tpl-preview-scroll {
  flex: 1;
  overflow-y: auto;
  max-height: 520px;
  padding-right: 8px;
}
.tpl-preview-iframe {
  display: block;
  width: 100%;
  min-height: 480px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--background);
}
.tpl-preview-empty {
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.7;
  padding: 12px 0;
}
.tpl-preview-empty p {
  margin: 0 0 10px;
}
.tpl-hint {
  font-size: 12px;
  color: var(--text-faint);
}
.tpl-hint code {
  background: var(--bg-input);
  padding: 1px 5px;
  border-radius: 4px;
  font-size: 11.5px;
}

@media (max-width: 768px) {
  .tpl-editor-grid {
    grid-template-columns: 1fr;
  }
  .tpl-preview-pane {
    border-left: none;
    border-top: 1px solid var(--border);
    padding-left: 0;
    padding-top: 16px;
  }
}
</style>
