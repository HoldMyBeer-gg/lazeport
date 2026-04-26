<script setup>
import { onMounted, ref, computed, inject } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request, getSessionUser } from '../services/api'
import { setStatus } from '../stores/status'
import { showConfirm } from '../composables/useConfirm'
import { LOCALES, setLocale } from '../i18n'
import Modal from '../components/Modal.vue'
import SeveritySettingsEditor from '../components/SeveritySettingsEditor.vue'

const route = useRoute()
const router = useRouter()
const { t, locale } = useI18n()

const selectedLocale = ref(locale.value)

/* ── Tabs ── */
const TABS = [
  { id: 'profile', labelKey: 'settings.profileTab', icon: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z' },
  { id: 'api-keys', labelKey: 'settings.apiKeysTab', icon: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4' },
  { id: 'security', labelKey: 'settings.securityTab', icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' },
]
const ORG_TABS = [
  { id: 'members', labelKey: 'settings.membersTab', icon: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75' },
  { id: 'llm', labelKey: 'settings.llmTab', icon: 'M12 2a2 2 0 012 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 017 7h1a1 1 0 110 2h-1.07A7.001 7.001 0 0113 22h-2a7.001 7.001 0 01-6.93-6H3a1 1 0 110-2h1a7 7 0 017-7h1V5.73A2.002 2.002 0 0112 2z' },
  { id: 'sso', labelKey: 'settings.ssoTab', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
  { id: 'email', labelKey: 'settings.emailTab', icon: 'M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2zm16 2l-8 5-8-5' },
  { id: 'security', labelKey: 'settings.securityTab', icon: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' },
  { id: 'validation', labelKey: 'settings.validationTab', icon: 'M9 11l3 3L22 4M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11' },
  { id: 'audit', labelKey: 'settings.auditTab', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4' },
]

const VALID_TAB_IDS = new Set([...TABS, ...ORG_TABS].map(t => t.id))

function isValidTab(id) {
  return VALID_TAB_IDS.has(id)
}

const activeTab = ref(isValidTab(route.query.tab) ? route.query.tab : 'profile')
const isOrgAdmin = ref(false)
const userOrgRole = ref('readonly')

/* ── Severity Settings Modal ── */
const showSeverityModal = ref(false)

const allTabs = computed(() => {
  if (isOrgAdmin.value) {
    const personalTabs = TABS.filter(t => t.id !== 'security')
    return [...personalTabs, ...ORG_TABS]
  }
  return TABS
})

function setTab(tab) {
  if (!isValidTab(tab)) return
  activeTab.value = tab
  router.replace({ query: { ...route.query, tab } })
}

/* ── Profile ── */
const profile = ref({
  name: '',
  user_email: '',
  email: '',
  phone: '',
  title: '',
  company_name: '',
  department_name: '',
  default_master_template: 'master',
  default_finding_template: '',
  openai_api_key_configured: false,
  ai_key_provider: '',
  configured_providers: [],
})
const masterTemplates = ref([])
const findingTemplates = ref([])
const openaiApiKeyInput = ref('')
const openaiApiKeyFieldTouched = ref(false)
const savingAiKey = ref(false)

/* ── AI Provider Key config ── */
const AI_PROVIDERS = [
  { id: 'openai', keyLabelKey: 'settings.apiKeys.aiProviderKeyLabels.openai', placeholderKey: 'settings.apiKeys.aiProviderPlaceholders.openai' },
  { id: 'anthropic', keyLabelKey: 'settings.apiKeys.aiProviderKeyLabels.anthropic', placeholderKey: 'settings.apiKeys.aiProviderPlaceholders.anthropic' },
  { id: 'gemini', keyLabelKey: 'settings.apiKeys.aiProviderKeyLabels.gemini', placeholderKey: 'settings.apiKeys.aiProviderPlaceholders.gemini' },
  { id: 'groq', keyLabelKey: 'settings.apiKeys.aiProviderKeyLabels.groq', placeholderKey: 'settings.apiKeys.aiProviderPlaceholders.groq' },
  { id: 'together', keyLabelKey: 'settings.apiKeys.aiProviderKeyLabels.together', placeholderKey: 'settings.apiKeys.pasteApiKeyPlaceholder' },
  { id: 'deepseek', keyLabelKey: 'settings.apiKeys.aiProviderKeyLabels.deepseek', placeholderKey: 'settings.apiKeys.aiProviderPlaceholders.deepseek' },
  { id: 'mistral', keyLabelKey: 'settings.apiKeys.aiProviderKeyLabels.mistral', placeholderKey: 'settings.apiKeys.pasteApiKeyPlaceholder' },
]
const selectedAiProvider = ref('openai')

const activeAiProvider = computed(() => {
  const p = AI_PROVIDERS.find(pr => pr.id === selectedAiProvider.value) || AI_PROVIDERS[0]
  return {
    ...p,
    keyLabel: t(p.keyLabelKey),
    placeholder: t(p.placeholderKey),
  }
})
const isKeyConfiguredForSelected = computed(() => {
  return profile.value.configured_providers.includes(selectedAiProvider.value)
})

async function loadProfile() {
  const user = await getSessionUser()
  if (user) {
    profile.value.user_email = user.email || ''
    profile.value.name = user.name || ''
  }
  const data = await request('/api/admin/profile')
  profile.value.email = data.email || ''
  profile.value.phone = data.phone || ''
  profile.value.title = data.title || ''
  profile.value.company_name = data.company_name || ''
  profile.value.department_name = data.department_name || ''
  profile.value.default_master_template = data.default_master_template || 'master'
  profile.value.default_finding_template = data.default_finding_template || ''
  profile.value.openai_api_key_configured = !!data.openai_api_key_configured
  profile.value.ai_key_provider = data.ai_key_provider || ''
  profile.value.configured_providers = data.configured_providers || []
  if (data.ai_key_provider) {
    selectedAiProvider.value = data.ai_key_provider
  }
  try {
    masterTemplates.value = await request('/api/master-templates')
  } catch { masterTemplates.value = [] }
  try {
    findingTemplates.value = await request('/api/admin/finding-templates')
  } catch { findingTemplates.value = [] }
}

async function saveProfile() {
  setStatus(t('settings.profile.savingProfile'), 'info')
  const body = {
    name: profile.value.name,
    email: profile.value.email,
    phone: profile.value.phone,
    title: profile.value.title,
    company_name: profile.value.company_name,
    department_name: profile.value.department_name,
    default_master_template: profile.value.default_master_template,
    default_finding_template: profile.value.default_finding_template,
  }
  await request('/api/admin/profile', { method: 'PUT', body: JSON.stringify(body) })
  await setLocale(selectedLocale.value)
  setStatus(t('settings.profile.profileSaved'), 'success')
}

async function saveAiKey() {
  if (!openaiApiKeyFieldTouched.value) return
  savingAiKey.value = true
  setStatus(t('settings.apiKeys.savingAiKey'), 'info')
  try {
    const keyValue = openaiApiKeyInput.value.trim()
    const providerValue = keyValue ? selectedAiProvider.value : ''
    const body = { openai_api_key: keyValue || '', ai_key_provider: providerValue }
    await request('/api/admin/profile', { method: 'PUT', body: JSON.stringify(body) })
    // Reload profile to get updated configured_providers list
    await loadProfile()
    openaiApiKeyInput.value = ''
    openaiApiKeyFieldTouched.value = false
    setStatus(t('settings.apiKeys.aiKeySaved'), 'success')
  } catch (e) {
    setStatus(t('settings.apiKeys.failedToSaveAiKey'), 'error')
  } finally {
    savingAiKey.value = false
  }
}

/* ── API Keys ── */
const apiKeys = ref([])
const newKeyName = ref('')
const createdKey = ref(null)

async function loadKeys() {
  try { apiKeys.value = await request('/api/me/keys') }
  catch { apiKeys.value = [] }
}

async function createKey() {
  if (!newKeyName.value.trim()) return
  try {
    const res = await request('/api/me/keys', {
      method: 'POST',
      body: JSON.stringify({ name: newKeyName.value }),
    })
    createdKey.value = res.key
    newKeyName.value = ''
    await loadKeys()
  } catch { setStatus(t('settings.apiKeys.failedToCreateApiKey'), 'error') }
}

async function copyKey() {
  if (!createdKey.value) return
  await navigator.clipboard.writeText(createdKey.value)
  setStatus(t('settings.apiKeys.apiKeyCopied'), 'success')
}

async function revokeKey(id) {
  const ok = await showConfirm({ message: t('settings.apiKeys.revokeConfirm'), danger: true })
  if (!ok) return
  try {
    await request(`/api/me/keys/${id}`, { method: 'DELETE' })
    await loadKeys()
    setStatus(t('settings.apiKeys.apiKeyRevoked'), 'success')
  } catch { setStatus(t('settings.apiKeys.failedToRevokeApiKey'), 'error') }
}

/* ── 2FA ── */
const twofa = ref({ enabled: false, configured_at: null })
const show2FAEnrollModal = ref(false)
const show2FABackupCodesModal = ref(false)
const show2FAPasswordModal = ref(false)
const twofa2FAAction = ref('') // 'disable' or 'regenerate'
const twofaPassword = ref('')
const twofaQRCode = ref('')
const twofaSecret = ref('')
const twofaCode = ref('')
const twofaBackupCodes = ref([])
const twofaBackupCodesSaved = ref(false)
const showSecretKey = ref(false)

async function load2FAStatus() {
  try {
    const user = await getSessionUser()
    if (user) {
      twofa.value.enabled = user.twofa_enabled || false
      twofa.value.configured_at = user.twofa_configured_at || null
    }
  } catch (e) {
    console.error('Failed to load 2FA status', e)
  }
}

async function start2FAEnrollment() {
  try {
    const response = await request('/auth/2fa/enroll', { method: 'POST' })
    twofaQRCode.value = response.qr_code
    twofaSecret.value = response.secret
    twofaCode.value = ''
    show2FAEnrollModal.value = true
  } catch (e) {
    setStatus(t('twofa.errorEnrollmentFailed'), 'error')
  }
}

async function verify2FAEnrollment() {
  try {
    const response = await request('/auth/2fa/verify-enrollment', {
      method: 'POST',
      body: JSON.stringify({ code: twofaCode.value })
    })
    
    twofaBackupCodes.value = response.backup_codes
    show2FAEnrollModal.value = false
    show2FABackupCodesModal.value = true
    twofaBackupCodesSaved.value = false
  } catch (e) {
    setStatus(t('twofa.setupInvalidCode'), 'error')
  }
}

async function complete2FAEnrollment() {
  if (!twofaBackupCodesSaved.value) {
    setStatus(t('twofa.backupCodesConfirmCheckbox'), 'error')
    return
  }
  
  try {
    await request('/auth/2fa/complete-enrollment', { method: 'POST' })
    setStatus(t('twofa.notificationSetupSuccess'), 'success')
    window.location.href = '/login'
  } catch (e) {
    setStatus(t('twofa.errorEnrollmentFailed'), 'error')
  }
}

async function open2FAPasswordModal(action) {
  if (action === 'disable') {
    const ok = await showConfirm({
      message: t('twofa.disableConfirmMessage'),
      danger: true,
      title: t('twofa.disableConfirmTitle')
    })
    if (!ok) return
  }
  
  twofa2FAAction.value = action
  twofaPassword.value = ''
  show2FAPasswordModal.value = true
}

async function confirm2FAPassword() {
  if (!twofaPassword.value) return
  
  if (twofa2FAAction.value === 'disable') {
    await disable2FA()
  } else if (twofa2FAAction.value === 'regenerate') {
    await regenerate2FABackupCodes()
  }
}

async function disable2FA() {
  try {
    await request('/auth/2fa/disable', {
      method: 'POST',
      body: JSON.stringify({ password: twofaPassword.value })
    })
    show2FAPasswordModal.value = false
    setStatus(t('twofa.notificationDisabled'), 'success')
    window.location.href = '/login'
  } catch (e) {
    setStatus(t('twofa.errorDisableFailed'), 'error')
  }
}

async function regenerate2FABackupCodes() {
  try {
    const response = await request('/auth/2fa/regenerate-backup-codes', {
      method: 'POST',
      body: JSON.stringify({ password: twofaPassword.value })
    })
    
    twofaBackupCodes.value = response.backup_codes
    show2FAPasswordModal.value = false
    show2FABackupCodesModal.value = true
    twofaBackupCodesSaved.value = false
    setStatus(t('twofa.notificationCodesRegenerated'), 'success')
  } catch (e) {
    setStatus(t('twofa.errorRegenerateFailed'), 'error')
  }
}

function download2FABackupCodes() {
  const text = twofaBackupCodes.value.join('\n')
  const blob = new Blob([`Laze Report 2FA Backup Codes\n\n${text}\n\nStore these codes in a safe place. Each code can only be used once.`], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'lazeport-2fa-backup-codes.txt'
  a.click()
  URL.revokeObjectURL(url)
}

async function copy2FABackupCodes() {
  try {
    await navigator.clipboard.writeText(twofaBackupCodes.value.join('\n'))
    setStatus(t('twofa.backupCodesCopyAll'), 'success')
  } catch (e) {
    setStatus(t('twofa.errorCopyBackupCodes'), 'error')
  }
}

function print2FABackupCodes() {
  const text = twofaBackupCodes.value.join('\n')
  const win = window.open('', '', 'width=600,height=400')
  win.document.write(`<pre style="font-family:monospace;font-size:16px;line-height:2">${text}</pre>`)
  win.print()
  win.close()
}

/* ── Org Admin Check ── */
const organizations = ref([])
const currentOrgId = ref(null)
const currentUserId = ref(null)
const currentOrg = computed(() => organizations.value.find(o => o.id === currentOrgId.value))

async function loadOrgAdminStatus() {
  const user = await getSessionUser()
  if (!user) return
  if (user.role === 'admin') { isOrgAdmin.value = true }
  try {
    const me = await request('/api/me')
    currentUserId.value = me.id
    userOrgRole.value = user.role === 'admin' ? (me.org_role || 'org_owner') : (me.org_role || 'readonly')
    const orgs = await request('/api/orgs')
    organizations.value = orgs
    if (!orgs.length) return
    currentOrgId.value = user.org_id || orgs[0].id
    if (user.role === 'admin') return
    // Use org_role from session instead of calling members endpoint
    if (me.org_role && ['org_admin', 'org_owner'].includes(me.org_role)) {
      isOrgAdmin.value = true
    }
  } catch {
    // Silently fail - org tabs just won't show
  }
}

/* ── Audit Logs ── */
const auditLogs = ref([])
const auditLimit = ref(50)
const auditHasMore = ref(true)
const auditLoadingMore = ref(false)
const loadingAudit = ref(false)

async function loadAuditLogs(reset = true) {
  if (!currentOrgId.value) return
  if (reset) {
    loadingAudit.value = true
    auditLogs.value = []
    auditHasMore.value = true
  }
  const offset = reset ? 0 : auditLogs.value.length
  try {
    const limit = Math.min(500, Math.max(1, Number(auditLimit.value) || 50))
    const data = await request(
      `/api/orgs/${currentOrgId.value}/audit-logs?limit=${limit}&offset=${offset}`
    )
    if (reset) {
      auditLogs.value = data
    } else {
      auditLogs.value = [...auditLogs.value, ...data]
    }
    auditHasMore.value = data.length >= limit
  } catch (err) {
    console.error('Failed to load audit logs:', err)
  } finally {
    loadingAudit.value = false
    auditLoadingMore.value = false
  }
}

async function loadMoreAuditLogs() {
  if (!auditHasMore.value || auditLoadingMore.value || loadingAudit.value) return
  auditLoadingMore.value = true
  await loadAuditLogs(false)
}

function formatAuditTimestamp(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
}

function formatAuditDetails(details) {
  if (!details) return ''
  let obj
  try {
    obj = typeof details === 'object' ? details : JSON.parse(details)
  } catch {
    return String(details)
  }
  const entries = Object.entries(obj).filter(([k, v]) => v !== null && v !== undefined)
  if (entries.length === 0) return ''
  return entries.map(([k, v]) => `${k}: ${v}`).join(', ')
}

/* ── Members ── */
const members = ref([])
const loadingMembers = ref(false)
const showInviteModal = ref(false)
const inviteForm = ref({ email: '', role: 'consultant' })
const editingMemberRole = ref(null) // { user_id, email, currentRole, newRole }
const savingMemberRole = ref(false)

async function loadMembers() {
  if (!currentOrgId.value) return
  loadingMembers.value = true
  try {
    members.value = await request(`/api/orgs/${currentOrgId.value}/members`)
  } catch { setStatus(t('settings.members.failedToLoadMembers'), 'error') }
  finally { loadingMembers.value = false }
}

async function inviteUser() {
  if (!inviteForm.value.email || !inviteForm.value.role) return
  try {
    await request(`/api/orgs/${currentOrgId.value}/members`, {
      method: 'POST',
      body: JSON.stringify({ user_email: inviteForm.value.email, role: inviteForm.value.role }),
    })
    setStatus(t('settings.members.invitedEmail', { email: inviteForm.value.email }), 'success')
    showInviteModal.value = false
    inviteForm.value = { email: '', role: 'consultant' }
    await loadMembers()
  } catch (err) { setStatus(err.message || t('settings.members.failedToInvite'), 'error') }
}

function startEditingMemberRole(member) {
  editingMemberRole.value = {
    user_id: member.user_id,
    email: member.email,
    currentRole: member.role,
    newRole: member.role
  }
}

function cancelEditMemberRole() {
  editingMemberRole.value = null
}

async function saveMemberRoleChange() {
  if (!editingMemberRole.value) return
  
  savingMemberRole.value = true
  try {
    await request(`/api/orgs/${currentOrgId.value}/members/${editingMemberRole.value.user_id}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role: editingMemberRole.value.newRole }),
    })
    setStatus(t('settings.members.roleUpdated'), 'success')
    editingMemberRole.value = null
    await loadMembers()
  } catch {
    setStatus(t('settings.members.failedToUpdateRole'), 'error')
  } finally {
    savingMemberRole.value = false
  }
}

async function removeMember(member) {
  const ok = await showConfirm({ message: t('settings.members.removeConfirm', { email: member.email }), danger: true })
  if (!ok) return
  try {
    await request(`/api/orgs/${currentOrgId.value}/members/${member.user_id}`, { method: 'DELETE' })
    setStatus(t('settings.members.memberRemoved'), 'success')
    await loadMembers()
  } catch { setStatus(t('settings.members.failedToRemoveMember'), 'error') }
}

/* ── Email ── */
const emailSettings = ref({ host: '', port: 587, username: '', password: '', sender: '', use_tls: true, has_password: false })
const loadingEmail = ref(false)
const savingEmail = ref(false)
const sendingTest = ref(false)
const testEmail = ref('')

async function loadEmailSettings() {
  if (!currentOrgId.value) return
  loadingEmail.value = true
  try {
    const data = await request(`/api/orgs/${currentOrgId.value}/email-settings`)
    emailSettings.value = {
      host: data.host || '', port: data.port || 587, username: data.username || '',
      password: '', sender: data.sender || '', use_tls: data.use_tls !== false, has_password: !!data.has_password,
    }
  } catch { setStatus(t('settings.email.failedToLoadEmailSettings'), 'error') }
  finally { loadingEmail.value = false }
}

async function saveEmailSettings() {
  if (!currentOrgId.value) return
  savingEmail.value = true
  try {
    await request(`/api/orgs/${currentOrgId.value}/email-settings`, {
      method: 'PUT',
      body: JSON.stringify({
        host: emailSettings.value.host, port: Number(emailSettings.value.port || 0),
        username: emailSettings.value.username, password: emailSettings.value.password || null,
        sender: emailSettings.value.sender, use_tls: !!emailSettings.value.use_tls,
      }),
    })
    setStatus(t('settings.email.emailSettingsSaved'), 'success')
    emailSettings.value.password = ''
    await loadEmailSettings()
  } catch (err) { setStatus(err.message || t('settings.email.failedToSaveEmailSettings'), 'error') }
  finally { savingEmail.value = false }
}

async function sendTestEmail() {
  if (!currentOrgId.value || !testEmail.value.trim()) return
  sendingTest.value = true
  try {
    await request(`/api/orgs/${currentOrgId.value}/email-settings/test`, {
      method: 'POST',
      body: JSON.stringify({ to_email: testEmail.value.trim() }),
    })
    setStatus(t('settings.email.testEmailSent'), 'success')
  } catch (err) { setStatus(err.message || t('settings.email.failedToSendTestEmail'), 'error') }
  finally { sendingTest.value = false }
}

/* ── SSO / OIDC ── */
const oidcConfig = ref({ configured: false, provider_id: 'okta', provider_label: 'Okta', issuer: '', client_id: '', client_secret: '' })
const oidcDomains = ref([])
const newDomain = ref('')
const loadingSso = ref(false)
const savingSso = ref(false)

async function loadSsoSettings() {
  if (!currentOrgId.value) return
  loadingSso.value = true
  try {
    const [cfg, dom] = await Promise.all([
      request(`/api/orgs/${currentOrgId.value}/oidc-config`),
      request(`/api/orgs/${currentOrgId.value}/domains`),
    ])
    oidcConfig.value = { ...oidcConfig.value, ...cfg, client_secret: '' }
    oidcDomains.value = dom.domains || []
  } catch { setStatus(t('settings.sso.failedToLoad'), 'error') }
  finally { loadingSso.value = false }
}

async function saveOidcConfig() {
  if (!currentOrgId.value) return
  savingSso.value = true
  try {
    await request(`/api/orgs/${currentOrgId.value}/oidc-config`, {
      method: 'PUT',
      body: JSON.stringify({
        provider_id: oidcConfig.value.provider_id,
        provider_label: oidcConfig.value.provider_label,
        issuer: oidcConfig.value.issuer,
        client_id: oidcConfig.value.client_id,
        client_secret: oidcConfig.value.client_secret || undefined,
      }),
    })
    setStatus(t('settings.sso.saved'), 'success')
    oidcConfig.value.client_secret = ''
    await loadSsoSettings()
  } catch (err) { setStatus(err.message || t('settings.sso.failedToSave'), 'error') }
  finally { savingSso.value = false }
}

async function addDomain() {
  if (!currentOrgId.value || !newDomain.value.trim()) return
  try {
    await request(`/api/orgs/${currentOrgId.value}/domains`, {
      method: 'POST',
      body: JSON.stringify({ domain: newDomain.value.trim() }),
    })
    setStatus(t('settings.sso.domainAdded'), 'success')
    newDomain.value = ''
    await loadSsoSettings()
  } catch (err) { setStatus(err.message || t('settings.sso.failedToAddDomain'), 'error') }
}

async function removeDomain(domain) {
  if (!currentOrgId.value) return
  try {
    await request(`/api/orgs/${currentOrgId.value}/domains?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' })
    setStatus(t('settings.sso.domainRemoved'), 'success')
    await loadSsoSettings()
  } catch (err) { setStatus(err.message || t('settings.sso.failedToRemoveDomain'), 'error') }
}

const callbackUrl = computed(() => {
  if (typeof window === 'undefined') return ''
  return `${window.location.origin}/auth/oidc/callback`
})

/* ── Security ── */
const rateLimitSettings = ref({ max_attempts: 4, lockout_minutes: 15 })
const visionSettings = ref({ max_concurrent_tasks: 2 })
const twofaPolicy = ref('disabled')
const loadingSecurity = ref(false)
const savingSecurity = ref(false)
const savingVision = ref(false)
const saving2FAPolicy = ref(false)

/* ── Validation Settings ── */
const validationSettings = ref({ confidence_levels: 'Confirmed, Suspected, Tentative, False Positive' })
const loadingValidation = ref(false)
const savingValidation = ref(false)

async function loadSecuritySettings() {
  if (!currentOrgId.value) return
  loadingSecurity.value = true
  try {
    const data = await request(`/api/orgs/${currentOrgId.value}/rate-limit-settings`)
    rateLimitSettings.value = { max_attempts: data.max_attempts, lockout_minutes: data.lockout_minutes }
    const vision = await request(`/api/orgs/${currentOrgId.value}/vision-settings`)
    visionSettings.value = { max_concurrent_tasks: vision.max_concurrent_tasks || 2 }
    
    const orgData = await request(`/api/orgs/${currentOrgId.value}`)
    const orgSettings = orgData.settings ? JSON.parse(orgData.settings) : {}
    twofaPolicy.value = orgSettings.twofa_policy || 'disabled'
  } catch (err) { setStatus(err.message || t('settings.security.failedToLoadSecuritySettings'), 'error') }
  finally { loadingSecurity.value = false }
}

async function saveSecuritySettings() {
  if (!currentOrgId.value) return
  savingSecurity.value = true
  try {
    await request(`/api/orgs/${currentOrgId.value}/rate-limit-settings`, {
      method: 'PUT',
      body: JSON.stringify({ max_attempts: rateLimitSettings.value.max_attempts, lockout_minutes: rateLimitSettings.value.lockout_minutes }),
    })
    setStatus(t('settings.security.rateLimitSettingsSaved'), 'success')
  } catch (err) { setStatus(err.message || t('settings.security.failedToSaveSecuritySettings'), 'error') }
  finally { savingSecurity.value = false }
}

async function saveVisionSettings() {
  if (!currentOrgId.value) return
  savingVision.value = true
  try {
    await request(`/api/orgs/${currentOrgId.value}/vision-settings`, {
      method: 'PUT',
      body: JSON.stringify({ max_concurrent_tasks: visionSettings.value.max_concurrent_tasks }),
    })
    setStatus(t('settings.security.visionSettingsSaved'), 'success')
  } catch (err) { setStatus(err.message || t('settings.security.failedToSaveVisionSettings'), 'error') }
  finally { savingVision.value = false }
}

async function save2FAPolicy() {
  if (!currentOrgId.value) return
  saving2FAPolicy.value = true
  try {
    await request(`/api/admin/organization/settings`, {
      method: 'PUT',
      body: JSON.stringify({ twofa_policy: twofaPolicy.value }),
    })
    setStatus(t('twofa.orgPolicySaveButton'), 'success')
    // Reload settings to confirm the save
    await loadSecuritySettings()
  } catch (err) { setStatus(t('twofa.errorSave2FAPolicy'), 'error') }
  finally { saving2FAPolicy.value = false }
}

/* ── Validation Settings ── */
async function loadValidationSettings() {
  if (!currentOrgId.value) {
    loadingValidation.value = false
    return
  }
  loadingValidation.value = true
  try {
    const data = await request('/api/admin/confidence-levels')
    validationSettings.value.confidence_levels = (data.levels || []).join(', ')
  } catch (err) {
    console.error('Failed to load validation settings:', err)
    // Don't show error if endpoint doesn't exist, just use defaults
  } finally {
    loadingValidation.value = false
  }
}

async function saveValidationSettings() {
  if (!currentOrgId.value) return
  
  // Parse comma-separated string into array
  const levels = validationSettings.value.confidence_levels
    .split(',')
    .map(l => l.trim())
    .filter(l => l)
  
  if (levels.length < 2) {
    setStatus(t('settings.validation.atLeastTwoLevels'), 'error')
    return
  }
  
  savingValidation.value = true
  try {
    await request('/api/admin/organization/settings', {
      method: 'PUT',
      body: JSON.stringify({ confidence_levels: levels }),
    })
    setStatus(t('settings.validation.validationSettingsSaved'), 'success')
  } catch (err) {
    setStatus(err.message || t('settings.validation.failedToSaveValidationSettings'), 'error')
  } finally {
    savingValidation.value = false
  }
}

/* ── Helpers ── */
function formatDate(iso) {
  return iso ? new Date(iso).toLocaleDateString() : t('settings.emptyDate')
}

/* ── LLM Settings (org-level) ── */
const orgLlmSettings = inject('orgLlmSettings', ref({}))
const updateOrgLlmSettings = inject('updateOrgLlmSettings', () => {})

const llmForm = ref({
  provider: '',
  model: '',
  base_url: '',
  vision_model: '',
  timeout: null,
  extra_instructions: '',
  sampling_params: {
    temperature: null,
    top_p: null,
    frequency_penalty: null,
    presence_penalty: null,
    top_k: null,
    min_p: null,
    repeat_penalty: null,
    num_ctx: null,
    num_predict: null,
  },
})
const llmModelOptions = ref([])
const llmVisionModels = ref([])
const llmSaving = ref(false)
const llmShowSampling = ref(false)
const llmProviders = ref({})
const llmProviderCache = ref({})
const PROVIDER_PRESETS = {
  openai:      { baseUrl: '' },
  anthropic:   { baseUrl: 'https://api.anthropic.com/v1/' },
  gemini:      { baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai/' },
  groq:        { baseUrl: 'https://api.groq.com/openai/v1' },
  together:    { baseUrl: 'https://api.together.xyz/v1' },
  deepseek:    { baseUrl: 'https://api.deepseek.com/v1' },
  mistral:     { baseUrl: 'https://api.mistral.ai/v1' },
  ollama:      { baseUrl: 'http://localhost:11434' },
  openai_compatible: { baseUrl: '' },
}

function _extractProviderFields(obj) {
  const sp = obj.sampling_params || {}
  return {
    model: obj.model || '',
    base_url: obj.base_url || '',
    vision_model: obj.vision_model || '',
    timeout: obj.timeout || null,
    sampling_params: {
      temperature: sp.temperature ?? null,
      top_p: sp.top_p ?? null,
      frequency_penalty: sp.frequency_penalty ?? null,
      presence_penalty: sp.presence_penalty ?? null,
      top_k: sp.top_k ?? null,
      min_p: sp.min_p ?? null,
      repeat_penalty: sp.repeat_penalty ?? null,
      num_ctx: sp.num_ctx ?? null,
      num_predict: sp.num_predict ?? null,
    },
  }
}

async function loadLlmSettings() {
  try {
    if (!currentOrgId.value) return
    const data = await request(`/api/orgs/${currentOrgId.value}/llm-settings/all`)

    llmProviderCache.value = data.providers || {}

    const active = data.provider || ''
    const perProvider = llmProviderCache.value[active] || data
    const fields = _extractProviderFields(perProvider)

    llmForm.value = {
      provider: active,
      extra_instructions: data.extra_instructions || '',
      ...fields,
    }
    _prevLlmProvider = active
    await loadLlmProviderData()
    await loadLlmModelData()
  } catch (err) {
    console.error('Failed to load LLM settings:', err)
  }
}

async function loadLlmProviderData() {
  try {
    const res = await request('/api/providers')
    llmProviders.value = res || {}
  } catch { /* ignore */ }
}

async function loadLlmModelData() {
  try {
    const params = new URLSearchParams()
    if (llmForm.value.provider) params.append('provider', llmForm.value.provider)
    if (llmForm.value.base_url) params.append('base_url', llmForm.value.base_url)
    const [models, vision] = await Promise.all([
      request(`/api/providers/models?${params}`).catch(() => ({ models: [] })),
      request(`/api/providers/vision-models?${params}`).catch(() => ({ models: [] })),
    ])
    llmModelOptions.value = models.models || []
    llmVisionModels.value = vision.models || []
  } catch { /* ignore */ }
}

function _saveCurrentToCache() {
  const p = llmForm.value.provider
  if (!p) return
  const sp = llmForm.value.sampling_params || {}
  const cleanSp = {}
  for (const [k, v] of Object.entries(sp)) {
    if (v !== null && v !== '' && v !== undefined) cleanSp[k] = Number(v)
  }
  llmProviderCache.value[p] = {
    model: llmForm.value.model || undefined,
    base_url: llmForm.value.base_url || undefined,
    vision_model: llmForm.value.vision_model || undefined,
    timeout: llmForm.value.timeout ? Number(llmForm.value.timeout) : undefined,
    sampling_params: Object.keys(cleanSp).length > 0 ? cleanSp : undefined,
  }
}

let _prevLlmProvider = ''

function onLlmProviderChange() {
  if (_prevLlmProvider) {
    const oldProvider = _prevLlmProvider
    const sp = llmForm.value.sampling_params || {}
    const cleanSp = {}
    for (const [k, v] of Object.entries(sp)) {
      if (v !== null && v !== '' && v !== undefined) cleanSp[k] = Number(v)
    }
    llmProviderCache.value[oldProvider] = {
      model: llmForm.value.model || undefined,
      base_url: llmForm.value.base_url || undefined,
      vision_model: llmForm.value.vision_model || undefined,
      timeout: llmForm.value.timeout ? Number(llmForm.value.timeout) : undefined,
      sampling_params: Object.keys(cleanSp).length > 0 ? cleanSp : undefined,
    }
  }

  const newProvider = llmForm.value.provider
  _prevLlmProvider = newProvider

  const cached = llmProviderCache.value[newProvider]
  if (cached) {
    const fields = _extractProviderFields(cached)
    llmForm.value.model = fields.model
    llmForm.value.base_url = fields.base_url
    llmForm.value.vision_model = fields.vision_model
    llmForm.value.timeout = fields.timeout
    llmForm.value.sampling_params = fields.sampling_params
  } else {
    const preset = PROVIDER_PRESETS[newProvider]
    llmForm.value.model = ''
    llmForm.value.base_url = preset?.baseUrl || ''
    llmForm.value.vision_model = ''
    llmForm.value.timeout = null
    llmForm.value.sampling_params = {
      temperature: null, top_p: null, frequency_penalty: null,
      presence_penalty: null, top_k: null, min_p: null, repeat_penalty: null, num_ctx: null, num_predict: null,
    }
  }
  loadLlmModelData()
}

async function saveLlmSettings() {
  llmSaving.value = true
  try {
    _saveCurrentToCache()

    const sp = llmForm.value.sampling_params
    const cleanSp = {}
    for (const [k, v] of Object.entries(sp)) {
      if (v !== null && v !== '' && v !== undefined) cleanSp[k] = Number(v)
    }
    const payload = {
      provider: llmForm.value.provider || null,
      extra_instructions: llmForm.value.extra_instructions || null,
      model: llmForm.value.model || null,
      base_url: llmForm.value.base_url || null,
      vision_model: llmForm.value.vision_model || null,
      timeout: llmForm.value.timeout ? Number(llmForm.value.timeout) : null,
      sampling_params: Object.keys(cleanSp).length > 0 ? cleanSp : null,
      providers: { ...llmProviderCache.value },
    }
    const result = await request(`/api/orgs/${currentOrgId.value}/llm-settings`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    })
    updateOrgLlmSettings(result)
    setStatus(t('settings.llmSettingsSaved'), 'success')
  } catch (err) {
    setStatus(err.message || t('settings.llmSettingsFailed'), 'error')
  } finally {
    llmSaving.value = false
  }
}

/* ── Tab change handler ── */
function onTabChange(tab) {
  setTab(tab)
  if (tab === 'security') {
    load2FAStatus()
    if (isOrgAdmin.value) {
      loadSecuritySettings()
    }
  } else if (tab === 'members') {
    loadMembers()
  } else if (tab === 'sso') {
    loadSsoSettings()
  } else if (tab === 'email') {
    loadEmailSettings()
  } else if (tab === 'llm') {
    loadLlmSettings()
  } else if (tab === 'validation') {
    loadValidationSettings()
  } else if (tab === 'audit') {
    loadAuditLogs(true)
  }
}

/* ── Init ── */
onMounted(async () => {
  await loadOrgAdminStatus()

  // If the requested tab is org-admin-only but user isn't an admin, fall back
  const orgOnly = new Set(ORG_TABS.map(t => t.id))
  if (orgOnly.has(activeTab.value) && !isOrgAdmin.value && activeTab.value !== 'security') {
    setTab('profile')
  }

  await loadProfile()
  await loadKeys()
  await load2FAStatus()
  if (activeTab.value === 'security' && !isOrgAdmin.value) {
    // Personal security tab - 2FA already loaded
  } else if (isOrgAdmin.value) {
    if (activeTab.value === 'members') loadMembers()
    else if (activeTab.value === 'sso') loadSsoSettings()
    else if (activeTab.value === 'email') loadEmailSettings()
    else if (activeTab.value === 'security') loadSecuritySettings()
    else if (activeTab.value === 'llm') loadLlmSettings()
    else if (activeTab.value === 'validation') loadValidationSettings()
  }
})
</script>

<template>
  <div class="org-hero">
    <div class="org-title">
      <p class="kicker">{{ $t('settings.kicker') }}</p>
      <h1>{{ $t('settings.title') }}</h1>
      <p class="subtitle">{{ $t('settings.subtitle') }}</p>
    </div>
  </div>

  <!-- Tabs -->
  <div class="tabs" role="tablist">
    <template v-for="(t, index) in allTabs" :key="t.id + '_' + index">
      <span v-if="index === TABS.length && isOrgAdmin" class="tab-divider"></span>
      <button
        :class="['tab', activeTab === t.id && 'active']"
        @click="onTabChange(t.id)"
        role="tab"
        :aria-selected="activeTab === t.id"
      >
        <svg class="tab-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path :d="t.icon"/></svg>
        {{ $t(t.labelKey) }}
      </button>
    </template>
  </div>

  <!-- ============ Profile Tab ============ -->
  <div v-if="activeTab === 'profile'" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0">{{ $t('settings.profile.personalInfo') }}</div>
      <div class="row">
        <div>
          <label for="profile-name">{{ $t('common.name') }}</label>
          <input id="profile-name" v-model="profile.name" :placeholder="$t('settings.profile.namePlaceholder')" />
        </div>
        <div>
          <label for="profile-email-ro">{{ $t('settings.profile.loginEmailReadOnly') }}</label>
          <input id="profile-email-ro" v-model="profile.user_email" disabled />
        </div>
      </div>
      <div class="row">
        <div>
          <label for="profile-contact-email">{{ $t('settings.profile.contactEmail') }}</label>
          <input id="profile-contact-email" v-model="profile.email" type="email" :placeholder="$t('settings.profile.contactEmailPlaceholder')" />
          <p class="hint">{{ $t('settings.profile.authorEmailHint') }}</p>
        </div>
        <div>
          <label for="profile-phone">{{ $t('settings.profile.phone') }}</label>
          <input id="profile-phone" v-model="profile.phone" type="tel" :placeholder="$t('settings.profile.phonePlaceholder')" />
          <p class="hint">{{ $t('settings.profile.authorPhoneHint') }}</p>
        </div>
      </div>
      <div>
        <label for="profile-title">{{ $t('settings.profile.jobTitle') }}</label>
        <input id="profile-title" v-model="profile.title" :placeholder="$t('settings.profile.jobTitlePlaceholder')" />
        <p class="hint">{{ $t('settings.profile.authorTitleHint') }}</p>
      </div>

      <div class="section-header">{{ $t('settings.profile.companyInfo') }}</div>
      <div class="row">
        <div>
          <label for="profile-company">{{ $t('settings.profile.companyName') }}</label>
          <input id="profile-company" v-model="profile.company_name" :placeholder="$t('settings.profile.companyNamePlaceholder')" />
        </div>
        <div>
          <label for="profile-department">{{ $t('settings.profile.departmentName') }}</label>
          <input id="profile-department" v-model="profile.department_name" :placeholder="$t('settings.profile.departmentNamePlaceholder')" />
        </div>
      </div>

      <div class="section-header">{{ $t('settings.profile.reportDefaults') }}</div>
      <div>
        <label for="profile-default-template">{{ $t('settings.profile.defaultMasterTemplate') }}</label>
        <select id="profile-default-template" v-model="profile.default_master_template">
          <option v-for="name in masterTemplates" :key="name" :value="name">{{ name }}</option>
        </select>
        <p class="hint">{{ $t('settings.profile.defaultMasterTemplateHint') }}</p>
      </div>
      <div>
        <label for="profile-default-finding-template">{{ $t('settings.profile.defaultFindingTemplate') }}</label>
        <select id="profile-default-finding-template" v-model="profile.default_finding_template">
          <option value="">{{ $t('settings.profile.defaultFindingTemplateNone') }}</option>
          <option v-for="tpl in findingTemplates" :key="tpl.id" :value="tpl.name">{{ tpl.name }}</option>
        </select>
        <p class="hint">{{ $t('settings.profile.defaultFindingTemplateHint') }}</p>
      </div>

      <div class="section-header">{{ $t('settings.profile.language') }}</div>
      <div>
        <select id="profile-language" v-model="selectedLocale" style="max-width:240px">
          <option v-for="loc in LOCALES" :key="loc.id" :value="loc.id">{{ loc.label }}</option>
        </select>
        <p class="hint">{{ $t('settings.profile.languageHint') }}</p>
      </div>

      <div class="actions" style="margin-top:12px">
        <button @click="saveProfile">{{ $t('settings.profile.saveProfile') }}</button>
      </div>
    </div>
  </div>

  <!-- ============ API Keys Tab ============ -->
  <template v-if="activeTab === 'api-keys'">
    <!-- Section 1: Laze API Keys -->
    <div class="card card-tab-connected">
      <div class="section-header" style="margin-top:0">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px;opacity:0.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
        {{ $t('settings.apiKeys.lazeApiKeys') }}
      </div>
      <p class="muted" style="margin-bottom:16px">{{ $t('settings.apiKeys.lazeApiKeysDesc') }}</p>

      <div v-if="createdKey" role="status" aria-live="polite" class="key-created-banner">
        <p style="font-weight:600;margin-bottom:8px;color:var(--success)">{{ $t('settings.apiKeys.yourNewApiKey') }}</p>
        <p class="muted" style="font-size:13px;margin-bottom:12px">{{ $t('settings.apiKeys.copyKeyNowHint') }}</p>
        <div style="display:flex;gap:8px;align-items:center">
          <code class="key-display">{{ createdKey }}</code>
          <button class="secondary" @click="copyKey">{{ $t('settings.apiKeys.copy') }}</button>
          <button class="secondary" @click="createdKey = null">{{ $t('settings.apiKeys.done') }}</button>
        </div>
      </div>

      <div class="row" style="margin-bottom:20px">
        <div style="flex:1">
          <label for="new-key-name">{{ $t('settings.apiKeys.keyName') }}</label>
          <input id="new-key-name" v-model="newKeyName" :placeholder="$t('settings.apiKeys.keyNamePlaceholder')" @keyup.enter="createKey" />
        </div>
        <div class="actions" style="align-items:flex-end">
          <button @click="createKey" :disabled="!newKeyName.trim()">{{ $t('settings.apiKeys.generateKey') }}</button>
        </div>
      </div>

      <div class="table-wrapper" v-if="apiKeys.length">
        <table class="table">
          <thead>
            <tr>
              <th>{{ $t('common.name') }}</th>
              <th>{{ $t('settings.apiKeys.identifier') }}</th>
              <th>{{ $t('settings.apiKeys.created') }}</th>
              <th>{{ $t('settings.apiKeys.lastUsed') }}</th>
              <th style="width:100px">{{ $t('settings.apiKeys.action') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="key in apiKeys" :key="key.id">
              <td>{{ key.name }}</td>
              <td><code>{{ key.prefix }}...</code></td>
              <td>{{ formatDate(key.created_at) }}</td>
              <td>{{ key.last_used_at ? formatDate(key.last_used_at) : $t('settings.apiKeys.never') }}</td>
              <td><button class="danger" @click="revokeKey(key.id)" style="padding:4px 8px;font-size:11px">{{ $t('settings.apiKeys.revoke') }}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="muted">{{ $t('settings.apiKeys.noApiKeysYet') }}</p>
    </div>

    <!-- Section 2: AI Provider Keys (hidden for readonly - they can't generate) -->
    <div v-if="userOrgRole !== 'readonly'" class="card ai-keys-card">
      <div class="section-header" style="margin-top:0">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:6px;opacity:0.5"><path d="M12 2a4 4 0 0 1 4 4v1h1a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3v-8a3 3 0 0 1 3-3h1V6a4 4 0 0 1 4-4zm-2 4v1h4V6a2 2 0 1 0-4 0z"/></svg>
        {{ $t('settings.apiKeys.aiProviderKeys') }}
      </div>
      <p class="muted" style="margin-bottom:16px">
        {{ $t('settings.apiKeys.aiProviderKeysDesc') }}
      </p>

      <div class="ai-key-form">
        <div class="ai-key-provider-row">
          <div class="ai-key-provider-select">
            <label for="ai-provider-select">{{ $t('settings.apiKeys.provider') }}</label>
            <select id="ai-provider-select" v-model="selectedAiProvider">
              <option v-for="p in AI_PROVIDERS" :key="p.id" :value="p.id">{{ $t('llmConfig.providerLabel.' + p.id) }}</option>
            </select>
          </div>
          <div class="ai-key-status">
            <span v-if="isKeyConfiguredForSelected" class="ai-key-badge set">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              {{ $t('settings.apiKeys.keyConfigured') }}
            </span>
            <span v-else class="ai-key-badge unset">
              {{ $t('settings.apiKeys.notConfigured') }}
            </span>
          </div>
        </div>

        <div class="ai-key-input-row">
          <label :for="'ai-key-input'">{{ activeAiProvider.keyLabel }}</label>
          <div class="ai-key-input-group">
            <input
              id="ai-key-input"
              v-model="openaiApiKeyInput"
              type="password"
              :placeholder="activeAiProvider.placeholder"
              autocomplete="off"
              @focus="openaiApiKeyFieldTouched = true"
              @input="openaiApiKeyFieldTouched = true"
            />
          </div>
          <p class="hint">
            {{ $t('settings.apiKeys.storedHint') }}
          </p>
        </div>

        <div class="actions" style="margin-top:12px">
          <button @click="saveAiKey" :disabled="!openaiApiKeyFieldTouched || savingAiKey">
            {{ savingAiKey ? $t('settings.apiKeys.saving') : $t('settings.apiKeys.saveKey') }}
          </button>
        </div>
      </div>
    </div>
  </template>

  <!-- ============ Security Tab (Personal) ============ -->
  <div v-if="activeTab === 'security'" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0">{{ $t('twofa.title') }}</div>
      
      <!-- 2FA Not Enabled -->
      <div v-if="!twofa.enabled">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
          <span style="font-size:14px">{{ $t('twofa.status') }}:</span>
          <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:16px;font-size:13px;font-weight:600;background:var(--warning-bg);color:var(--warning)">
            ⚠️ {{ $t('twofa.statusNotConfigured') }}
          </span>
        </div>
        
        <p class="muted" style="margin-bottom:16px">{{ $t('twofa.description') }}</p>
        
        <div style="margin-bottom:16px">
          <p style="font-weight:600;margin-bottom:8px">{{ $t('twofa.supportedApps') }}</p>
          <ul style="list-style:disc;padding-left:20px;color:var(--text-secondary)">
            <li>{{ $t('twofa.appGoogle') }}</li>
            <li>{{ $t('twofa.app1Password') }}</li>
            <li>{{ $t('twofa.appAuthy') }}</li>
            <li>{{ $t('twofa.appMicrosoft') }}</li>
          </ul>
        </div>
        
        <div class="actions">
          <button @click="start2FAEnrollment">{{ $t('twofa.enableButton') }}</button>
        </div>
      </div>
      
      <!-- 2FA Enabled -->
      <div v-else>
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
          <span style="font-size:14px">{{ $t('twofa.status') }}:</span>
          <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:16px;font-size:13px;font-weight:600;background:var(--success-bg);color:var(--success)">
            ✅ {{ $t('twofa.statusEnabled') }}
          </span>
        </div>
        <div v-if="twofa.configured_at" style="font-size:13px;color:var(--text-secondary);margin-bottom:16px">
          {{ $t('twofa.configuredAt', { date: new Date(twofa.configured_at).toLocaleDateString() }) }}
        </div>
        
        <div class="actions" style="gap:12px">
          <button class="secondary" @click="open2FAPasswordModal('regenerate')">
            {{ $t('twofa.regenerateCodesButton') }}
          </button>
          <button class="danger" @click="open2FAPasswordModal('disable')">
            {{ $t('twofa.disableButton') }}
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ============ LLM Tab (Org Admin) ============ -->
  <div v-if="activeTab === 'llm' && isOrgAdmin" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0">{{ $t('settings.llmTab') }}</div>

      <div class="form-row-2col">
        <div>
          <label for="llm-provider">{{ $t('llmConfig.provider') }}</label>
          <select id="llm-provider" v-model="llmForm.provider" @change="onLlmProviderChange">
            <option value="">{{ $t('llmConfig.selectProvider') }}</option>
            <optgroup :label="$t('llmConfig.cloudProviders')">
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="gemini">Google Gemini</option>
              <option value="groq">Groq</option>
              <option value="together">Together AI</option>
              <option value="deepseek">DeepSeek</option>
              <option value="mistral">Mistral</option>
            </optgroup>
            <optgroup :label="$t('llmConfig.selfHosted')">
              <option value="ollama">{{ $t('llmConfig.providerLabel.ollama') }}</option>
              <option value="openai_compatible">{{ $t('llmConfig.providerLabel.openai_compatible') }}</option>
            </optgroup>
          </select>
        </div>
        <div>
          <label for="llm-model">{{ $t('llmConfig.model') }}</label>
          <select v-if="llmModelOptions.length" id="llm-model" v-model="llmForm.model">
            <option value="">{{ $t('llmConfig.autoDetect') }}</option>
            <option v-for="m in llmModelOptions" :key="m" :value="m">{{ m }}</option>
          </select>
          <input v-else id="llm-model" v-model="llmForm.model" :placeholder="$t('llmConfig.modelPlaceholder')" />
        </div>
      </div>

      <div v-if="llmForm.provider && llmForm.provider !== 'openai'">
        <label for="llm-base-url">{{ $t('llmConfig.baseUrl') }}</label>
        <input id="llm-base-url" v-model="llmForm.base_url" :placeholder="PROVIDER_PRESETS[llmForm.provider]?.baseUrl || $t('llmConfig.baseUrlPlaceholder')" @change="loadLlmModelData" />
      </div>

      <div>
        <label for="llm-vision-model">{{ $t('llmConfig.visionModel') }}</label>
        <input
          id="llm-vision-model"
          v-model="llmForm.vision_model"
          list="llm-vision-model-suggestions"
          :placeholder="$t('llmConfig.visionModelPlaceholder')"
          :aria-label="$t('llmConfig.visionModelAriaLabel')"
          autocomplete="off"
        />
        <datalist id="llm-vision-model-suggestions">
          <option v-for="vm in llmVisionModels" :key="vm" :value="vm" />
        </datalist>
      </div>

      <div>
        <label for="llm-timeout">{{ $t('llmConfig.timeout') }}</label>
        <input id="llm-timeout" type="number" min="10" max="600" step="10" v-model.number="llmForm.timeout" :placeholder="$t('llmConfig.timeoutPlaceholder')" />
        <p class="hint">{{ $t('llmConfig.timeoutHint') }}</p>
      </div>

      <div class="llm-section-toggle">
        <button type="button" class="toggle-btn" @click="llmShowSampling = !llmShowSampling" :aria-expanded="llmShowSampling">
          <span class="toggle-chevron" :class="{ open: llmShowSampling }">&#x25B8;</span>
          {{ $t('llmConfig.samplingParamsSection') }}
        </button>
      </div>

      <div v-show="llmShowSampling" class="sampling-params-grid">
        <p class="hint" style="grid-column:1/-1;margin:0">{{ $t('llmConfig.samplingParamsCompatNote') }}</p>

        <div>
          <label for="sp-temperature">{{ $t('llmConfig.sampling.temperature') }}</label>
          <input id="sp-temperature" type="number" min="0" max="2" step="0.1" v-model.number="llmForm.sampling_params.temperature" :placeholder="$t('llmConfig.sampling.temperaturePlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.temperatureHint') }}</p>
        </div>
        <div>
          <label for="sp-top-p">{{ $t('llmConfig.sampling.topP') }}</label>
          <input id="sp-top-p" type="number" min="0" max="1" step="0.05" v-model.number="llmForm.sampling_params.top_p" :placeholder="$t('llmConfig.sampling.topPPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.topPHint') }}</p>
        </div>
        <div>
          <label for="sp-freq-penalty">{{ $t('llmConfig.sampling.frequencyPenalty') }}</label>
          <input id="sp-freq-penalty" type="number" min="-2" max="2" step="0.1" v-model.number="llmForm.sampling_params.frequency_penalty" :placeholder="$t('llmConfig.sampling.frequencyPenaltyPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.frequencyPenaltyHint') }}</p>
        </div>
        <div>
          <label for="sp-pres-penalty">{{ $t('llmConfig.sampling.presencePenalty') }}</label>
          <input id="sp-pres-penalty" type="number" min="-2" max="2" step="0.1" v-model.number="llmForm.sampling_params.presence_penalty" :placeholder="$t('llmConfig.sampling.presencePenaltyPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.presencePenaltyHint') }}</p>
        </div>
        <div>
          <label for="sp-top-k">{{ $t('llmConfig.sampling.topK') }}</label>
          <input id="sp-top-k" type="number" min="1" max="200" step="1" v-model.number="llmForm.sampling_params.top_k" :placeholder="$t('llmConfig.sampling.topKPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.topKHint') }}</p>
        </div>
        <div>
          <label for="sp-min-p">{{ $t('llmConfig.sampling.minP') }}</label>
          <input id="sp-min-p" type="number" min="0" max="1" step="0.05" v-model.number="llmForm.sampling_params.min_p" :placeholder="$t('llmConfig.sampling.minPPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.minPHint') }}</p>
        </div>
        <div>
          <label for="sp-repeat-penalty">{{ $t('llmConfig.sampling.repeatPenalty') }}</label>
          <input id="sp-repeat-penalty" type="number" min="0" max="3" step="0.1" v-model.number="llmForm.sampling_params.repeat_penalty" :placeholder="$t('llmConfig.sampling.repeatPenaltyPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.repeatPenaltyHint') }}</p>
        </div>
        <div>
          <label for="sp-num-ctx">{{ $t('llmConfig.sampling.numCtx') }}</label>
          <input id="sp-num-ctx" type="number" min="512" max="131072" step="512" v-model.number="llmForm.sampling_params.num_ctx" :placeholder="$t('llmConfig.sampling.numCtxPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.numCtxHint') }}</p>
        </div>
        <div>
          <label for="sp-num-predict">{{ $t('llmConfig.sampling.numPredict') }}</label>
          <input id="sp-num-predict" type="number" min="-1" max="32768" step="256" v-model.number="llmForm.sampling_params.num_predict" :placeholder="$t('llmConfig.sampling.numPredictPlaceholder')" />
          <p class="hint">{{ $t('llmConfig.sampling.numPredictHint') }}</p>
        </div>
      </div>

      <div>
        <label for="llm-extra-instructions">{{ $t('llmConfig.extraInstructionsLabel') }}</label>
        <textarea id="llm-extra-instructions" v-model="llmForm.extra_instructions" :placeholder="$t('llmConfig.extraInstructionsPlaceholder')" rows="4" style="width:100%;resize:vertical" />
        <p class="hint">{{ $t('llmConfig.extraInstructionsHint') }}</p>
      </div>

      <div class="actions">
        <button @click="saveLlmSettings" :disabled="llmSaving">
          {{ llmSaving ? $t('llmConfig.saving') : $t('llmConfig.saveSettings') }}
        </button>
      </div>
    </div>
  </div>

  <!-- ============ Members Tab (Org Admin) ============ -->
  <div v-if="activeTab === 'members' && isOrgAdmin" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0;display:flex;align-items:center;justify-content:space-between">
        <span>{{ $t('settings.members.clientMembers') }}</span>
        <button @click="showInviteModal = true" style="font-size:13px">{{ $t('settings.members.inviteUser') }}</button>
      </div>

      <div v-if="organizations.length > 1">
        <label for="org-select-members">{{ $t('settings.members.organization') }}</label>
        <select id="org-select-members" v-model="currentOrgId" @change="loadMembers" style="max-width:300px">
          <option v-for="org in organizations" :key="org.id" :value="org.id">{{ org.name }}</option>
        </select>
      </div>

      <div v-if="loadingMembers" class="muted" style="padding:20px;text-align:center">{{ $t('settings.members.loadingMembers') }}</div>
      <div class="table-wrapper" v-else-if="members.length">
        <table class="table">
          <thead>
            <tr>
              <th>{{ $t('common.name') }}</th>
              <th>{{ $t('common.email') }}</th>
              <th>{{ $t('settings.members.role') }}</th>
              <th>{{ $t('settings.members.joined') }}</th>
              <th style="width:200px">{{ $t('settings.members.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="member in members" :key="member.user_id">
              <td>{{ member.name || $t('settings.emptyDate') }}</td>
              <td>{{ member.email }}</td>
              <td>
                <span class="role-badge" :class="'role-' + member.role">
                  {{ $t('settings.members.roles.' + member.role) }}
                </span>
              </td>
              <td>{{ formatDate(member.joined_at) }}</td>
              <td>
                <button v-if="member.user_id !== currentUserId" class="secondary" @click="startEditingMemberRole(member)" style="padding:4px 8px;font-size:11px;margin-right:4px">
                  {{ $t('settings.members.changeRole') }}
                </button>
                <button v-if="member.user_id !== currentUserId" class="danger" @click="removeMember(member)" style="padding:4px 8px;font-size:11px">
                  {{ $t('common.remove') }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="muted">{{ $t('settings.members.noMembersYet') }}</p>
    </div>
  </div>

  <!-- ============ SSO Tab (Org Admin) ============ -->
  <div v-if="activeTab === 'sso' && isOrgAdmin" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0">{{ $t('settings.sso.title') }}</div>
      <p class="hint" style="margin-top:-8px">{{ $t('settings.sso.hint') }}</p>

      <div v-if="loadingSso" class="muted" style="padding:20px;text-align:center">{{ $t('settings.sso.loading') }}</div>
      <template v-else>
        <div>
          <label for="oidc-issuer">{{ $t('settings.sso.issuer') }}</label>
          <input id="oidc-issuer" v-model="oidcConfig.issuer" :placeholder="$t('settings.sso.issuerPlaceholder')" />
        </div>
        <div class="row">
          <div>
            <label for="oidc-client-id">{{ $t('settings.sso.clientId') }}</label>
            <input id="oidc-client-id" v-model="oidcConfig.client_id" :placeholder="$t('settings.sso.clientIdPlaceholder')" />
          </div>
          <div>
            <label for="oidc-client-secret">{{ $t('settings.sso.clientSecret') }}</label>
            <input id="oidc-client-secret" v-model="oidcConfig.client_secret" type="password" :placeholder="oidcConfig.configured ? '••••••••' : $t('settings.sso.clientSecretPlaceholder')" />
            <p v-if="oidcConfig.configured" class="hint">{{ $t('settings.sso.clientSecretHint') }}</p>
          </div>
        </div>
        <div>
          <label for="oidc-provider-label">{{ $t('settings.sso.providerLabel') }}</label>
          <input id="oidc-provider-label" v-model="oidcConfig.provider_label" placeholder="Okta" />
          <p class="hint">{{ $t('settings.sso.providerLabelHint') }}</p>
        </div>

        <div class="section-header">{{ $t('settings.sso.callbackUrl') }}</div>
        <p class="hint" style="margin-top:-8px">{{ $t('settings.sso.callbackUrlHint') }}</p>
        <code style="display:block;padding:12px;background:var(--background-secondary);border-radius:4px;font-size:0.9em;word-break:break-all">{{ callbackUrl }}</code>

        <div class="actions" style="justify-content:flex-end">
          <button @click="saveOidcConfig" :disabled="savingSso || !oidcConfig.issuer || !oidcConfig.client_id">{{ $t('common.save') }}</button>
        </div>

        <div class="section-header">{{ $t('settings.sso.domains') }}</div>
        <p class="hint" style="margin-top:-8px">{{ $t('settings.sso.domainsHint') }}</p>
        <div class="row" style="align-items:flex-end">
          <div style="flex:1">
            <label for="new-domain">{{ $t('settings.sso.addDomain') }}</label>
            <input id="new-domain" v-model="newDomain" :placeholder="$t('settings.sso.domainPlaceholder')" @keydown.enter.prevent="addDomain" />
          </div>
          <button class="secondary" @click="addDomain" :disabled="!newDomain.trim()">{{ $t('common.add') }}</button>
        </div>
        <ul v-if="oidcDomains.length" style="list-style:none;padding:0;margin-top:12px">
          <li v-for="d in oidcDomains" :key="d" style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
            <span>{{ d }}</span>
            <button class="danger" style="padding:2px 8px;font-size:12px" @click="removeDomain(d)">{{ $t('common.remove') }}</button>
          </li>
        </ul>
        <p v-else class="muted" style="margin-top:8px">{{ $t('settings.sso.noDomains') }}</p>
      </template>
    </div>
  </div>

  <!-- ============ Email Tab (Org Admin) ============ -->
  <div v-if="activeTab === 'email' && isOrgAdmin" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0">{{ $t('settings.email.smtpConfig') }}</div>

      <div v-if="loadingEmail" class="muted" style="padding:20px;text-align:center">{{ $t('settings.email.loadingEmailSettings') }}</div>
      <template v-else>
        <div class="row">
          <div>
            <label for="smtp-host">{{ $t('settings.email.smtpHost') }}</label>
            <input id="smtp-host" v-model="emailSettings.host" :placeholder="$t('settings.email.smtpHostPlaceholder')" />
          </div>
          <div>
            <label for="smtp-port">{{ $t('settings.email.smtpPort') }}</label>
            <input id="smtp-port" v-model.number="emailSettings.port" type="number" min="1" />
          </div>
        </div>
        <div class="row">
          <div>
            <label for="smtp-username">{{ $t('settings.email.username') }}</label>
            <input id="smtp-username" v-model="emailSettings.username" :placeholder="$t('settings.email.usernamePlaceholder')" />
          </div>
          <div>
            <label for="smtp-password">{{ $t('common.password') }}</label>
            <input id="smtp-password" v-model="emailSettings.password" type="password" placeholder="••••••••" />
            <p v-if="emailSettings.has_password" class="hint">{{ $t('settings.email.passwordIsSetHint') }}</p>
          </div>
        </div>
        <div class="row">
          <div>
            <label for="smtp-from">{{ $t('settings.email.fromAddress') }}</label>
            <input id="smtp-from" v-model="emailSettings.sender" type="email" :placeholder="$t('settings.email.fromAddressPlaceholder')" />
          </div>
          <div style="display:flex;align-items:center;padding-top:20px">
            <label for="smtp-tls" style="display:flex;align-items:center;gap:8px;cursor:pointer">
              <input id="smtp-tls" v-model="emailSettings.use_tls" type="checkbox" /> {{ $t('settings.email.useTls') }}
            </label>
          </div>
        </div>

        <div class="actions" style="justify-content:flex-end">
          <button class="secondary" @click="loadEmailSettings">{{ $t('common.reset') }}</button>
          <button @click="saveEmailSettings" :disabled="savingEmail">{{ $t('common.save') }}</button>
        </div>

        <div class="section-header">{{ $t('settings.email.testEmail') }}</div>
        <div class="row">
          <div style="flex:1">
            <label for="test-email">{{ $t('settings.email.recipient') }}</label>
            <input id="test-email" v-model="testEmail" type="email" :placeholder="$t('settings.email.recipientPlaceholder')" />
          </div>
          <div class="actions" style="align-items:flex-end">
            <button class="secondary" @click="sendTestEmail" :disabled="sendingTest || !testEmail.trim()">{{ $t('settings.email.sendTest') }}</button>
          </div>
        </div>
      </template>
    </div>
  </div>

  <!-- ============ Security Tab (Org Admin) ============ -->
  <div v-if="activeTab === 'security' && isOrgAdmin" class="card">
    <div class="grid">
      <!-- 2FA Policy Section -->
      <div class="section-header" style="margin-top:0">{{ $t('twofa.orgPolicyTitle') }}</div>
      
      <div v-if="loadingSecurity" class="muted" style="padding:20px;text-align:center">{{ $t('settings.security.loadingSecuritySettings') }}</div>
      <template v-else>
        <div>
          <label for="twofa-policy">{{ $t('twofa.orgPolicyLabel') }}</label>
          <select id="twofa-policy" v-model="twofaPolicy" style="max-width:300px">
            <option value="disabled">{{ $t('twofa.orgPolicyDisabled') }}</option>
            <option value="optional">{{ $t('twofa.orgPolicyOptional') }}</option>
            <option value="mandatory">{{ $t('twofa.orgPolicyMandatory') }}</option>
          </select>
        </div>
        
        <div style="background:var(--background-secondary);padding:16px;border-radius:8px;margin-top:8px">
          <p style="font-weight:600;margin-bottom:12px">{{ $t('twofa.orgPolicyEffects') }}</p>
          <ul style="list-style:disc;padding-left:20px;color:var(--text-secondary);line-height:1.8">
            <li>{{ $t('twofa.orgPolicyDisabledDesc') }}</li>
            <li>{{ $t('twofa.orgPolicyOptionalDesc') }}</li>
            <li>{{ $t('twofa.orgPolicyMandatoryDesc') }}</li>
          </ul>
        </div>
        
        <div class="actions" style="justify-content:flex-end;margin-bottom:32px">
          <button @click="save2FAPolicy" :disabled="saving2FAPolicy">
            {{ saving2FAPolicy ? $t('common.saving') : $t('twofa.orgPolicySaveButton') }}
          </button>
        </div>
        
        <!-- Divider -->
        <div style="border-top:1px solid var(--border);margin:24px 0"></div>
      </template>
      
      <div class="section-header">{{ $t('settings.security.loginRateLimiting') }}</div>
      <p class="hint" style="margin-top:-12px">{{ $t('settings.security.rateLimitHint') }}</p>

      <div v-if="loadingSecurity" class="muted" style="padding:20px;text-align:center">{{ $t('settings.security.loadingSecuritySettings') }}</div>
      <template v-else>
        <div class="row">
          <div>
            <label for="max-attempts">{{ $t('settings.security.maxFailedAttempts') }}</label>
            <input id="max-attempts" v-model.number="rateLimitSettings.max_attempts" type="number" min="1" max="100" />
            <p class="hint">{{ $t('settings.security.maxAttemptsHint') }}</p>
          </div>
          <div>
            <label for="lockout-minutes">{{ $t('settings.security.lockoutDuration') }}</label>
            <input id="lockout-minutes" v-model.number="rateLimitSettings.lockout_minutes" type="number" min="1" max="1440" />
            <p class="hint">{{ $t('settings.security.lockoutHint') }}</p>
          </div>
        </div>
        <div class="actions" style="justify-content:flex-end">
          <button class="secondary" @click="loadSecuritySettings">{{ $t('common.reset') }}</button>
          <button @click="saveSecuritySettings" :disabled="savingSecurity">{{ $t('common.save') }}</button>
        </div>

        <div class="section-header">{{ $t('settings.security.visionProcessing') }}</div>
        <p class="hint" style="margin-top:-12px">{{ $t('settings.security.visionHint') }}</p>
        <div>
          <label for="max-vision-tasks">{{ $t('settings.security.maxConcurrentVisionTasks') }}</label>
          <input id="max-vision-tasks" v-model.number="visionSettings.max_concurrent_tasks" type="number" min="1" max="10" style="max-width:200px" />
          <p class="hint">{{ $t('settings.security.visionTasksHint') }}</p>
        </div>
        <div class="actions" style="justify-content:flex-end">
          <button class="secondary" @click="loadSecuritySettings">{{ $t('common.reset') }}</button>
          <button @click="saveVisionSettings" :disabled="savingVision">{{ $t('common.save') }}</button>
        </div>
      </template>
    </div>
  </div>

  <!-- ─────────────────────────────────────────────────────────────────── -->
  <!-- Tab: Validation -->
  <!-- ─────────────────────────────────────────────────────────────────── -->
  <div v-if="activeTab === 'validation' && isOrgAdmin" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0">{{ $t('settings.validation.title') }}</div>
      
      <!-- Severity Criteria Settings -->
      <div style="margin-bottom: 30px">
        <h4 style="margin: 0 0 10px 0">{{ $t('severity.title') }}</h4>
        <p style="margin: 0 0 15px 0; color: var(--text-secondary); font-size: 14px">{{ $t('severity.description') }}</p>
        <button @click="showSeverityModal = true">{{ $t('severity.edit') }}</button>
      </div>

      <div>
        <label for="confidence-levels">{{ $t('settings.validation.confidenceLevels') }}</label>
        <input
          id="confidence-levels"
          v-model="validationSettings.confidence_levels"
          type="text"
          :placeholder="$t('settings.validation.confidenceLevelsPlaceholder')"
        />
        <p class="hint">{{ $t('settings.validation.confidenceLevelsHint') }}</p>
      </div>

      <div class="actions" style="justify-content:flex-end">
        <button class="secondary" @click="loadValidationSettings">{{ $t('common.reset') }}</button>
        <button @click="saveValidationSettings" :disabled="savingValidation">
          {{ savingValidation ? $t('settings.validation.savingValidationSettings') : $t('settings.validation.saveValidationSettings') }}
        </button>
      </div>
    </div>
  </div>

  <!-- Severity Settings Modal -->
  <SeveritySettingsEditor :org-id="currentOrgId" :show="showSeverityModal" @close="showSeverityModal = false" />

  <div v-if="activeTab === 'audit' && isOrgAdmin" class="card">
    <div class="grid">
      <div class="section-header" style="margin-top:0;display:flex;align-items:center;justify-content:space-between">
        <span>{{ $t('settings.audit.title') }}</span>
        <div style="display:flex;gap:12px;align-items:center">
          <label for="audit-limit" style="font-size:13px;color:var(--text-secondary);margin:0">{{ $t('settings.audit.perPage') }}</label>
          <select id="audit-limit" v-model.number="auditLimit" @change="loadAuditLogs(true)" style="padding:6px 8px;font-size:13px">
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
            <option value="500">500</option>
          </select>
          <button type="button" class="secondary" @click="loadAuditLogs(true)" style="padding:6px 12px;font-size:13px">
            🔄 {{ $t('settings.audit.refresh') }}
          </button>
        </div>
      </div>

      <div v-if="loadingAudit" style="text-align:center;padding:2rem;color:var(--text-secondary)">
        {{ $t('settings.audit.loading') }}
      </div>

      <div v-else-if="auditLogs.length > 0" style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:14px">
          <thead>
            <tr style="border-bottom:2px solid var(--border);text-align:left">
              <th style="padding:12px 8px">{{ $t('settings.audit.timestamp') }}</th>
              <th style="padding:12px 8px">{{ $t('settings.audit.user') }}</th>
              <th style="padding:12px 8px">{{ $t('settings.audit.action') }}</th>
              <th style="padding:12px 8px">{{ $t('settings.audit.resource') }}</th>
              <th style="padding:12px 8px">{{ $t('settings.audit.details') }}</th>
              <th style="padding:12px 8px">IP</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in auditLogs" :key="log.id" style="border-bottom:1px solid var(--border)">
              <td style="padding:10px 8px;font-size:13px;color:var(--text-secondary)">{{ formatAuditTimestamp(log.timestamp) }}</td>
              <td style="padding:10px 8px">{{ log.user_name || log.user_email }}</td>
              <td style="padding:10px 8px">
                <span :style="{
                  display: 'inline-block',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: '500',
                  background: log.action === 'create' ? 'var(--success)' : log.action === 'delete' ? 'var(--danger)' : 'var(--accent)',
                  color: '#fff'
                }">
                  {{ log.action }}
                </span>
              </td>
              <td style="padding:10px 8px">{{ log.resource_type }}</td>
              <td style="padding:10px 8px;font-size:13px;color:var(--text-secondary);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                {{ formatAuditDetails(log.details) }}
              </td>
              <td style="padding:10px 8px;font-size:13px;color:var(--text-muted)">{{ log.ip_address || '—' }}</td>
            </tr>
          </tbody>
        </table>
        
        <div v-if="auditLoadingMore" style="text-align:center;padding:1rem;color:var(--text-secondary)">
          {{ $t('settings.audit.loadingMore') }}
        </div>
        <button
          v-else-if="auditHasMore"
          type="button"
          class="secondary"
          @click="loadMoreAuditLogs"
          style="margin-top:16px;width:100%"
        >
          {{ $t('settings.audit.loadMore') }}
        </button>
        <div v-else style="text-align:center;padding:1rem;color:var(--text-muted);font-size:13px">
          {{ $t('settings.audit.allLoaded') }}
        </div>
      </div>

      <div v-else style="text-align:center;padding:2rem;color:var(--text-secondary)">
        {{ $t('settings.audit.noLogs') }}
      </div>
    </div>
  </div>

  <!-- Edit Member Role Modal -->
  <Modal v-if="editingMemberRole" :title="$t('settings.members.changeRoleTitle')" @close="cancelEditMemberRole">
    <div style="display:grid;gap:16px">
      <p style="margin:0">{{ $t('settings.members.changingRoleFor') }}: <strong>{{ editingMemberRole.email }}</strong></p>
      <div>
        <label for="edit-role">{{ $t('settings.members.newRole') }}</label>
        <select id="edit-role" v-model="editingMemberRole.newRole" style="padding:8px;width:100%">
          <option value="readonly">{{ $t('settings.members.roles.readonly') }}</option>
          <option value="consultant">{{ $t('settings.members.roles.consultant') }}</option>
          <option value="org_admin">{{ $t('settings.members.roles.org_admin') }}</option>
          <option value="org_owner">{{ $t('settings.members.roles.org_owner') }}</option>
        </select>
      </div>
      <div class="actions" style="justify-content:flex-end">
        <button type="button" class="secondary" @click="cancelEditMemberRole">{{ $t('common.cancel') }}</button>
        <button type="button" @click="saveMemberRoleChange" :disabled="savingMemberRole">
          {{ savingMemberRole ? $t('common.saving') : $t('common.save') }}
        </button>
      </div>
    </div>
  </Modal>

  <!-- Invite Modal -->
  <Modal v-if="showInviteModal" :title="$t('settings.members.inviteUser')" @close="showInviteModal = false">
    <form @submit.prevent="inviteUser" style="display:grid;gap:16px">
      <div>
        <label for="invite-email">{{ $t('common.email') }}</label>
        <input id="invite-email" type="email" v-model="inviteForm.email" required :placeholder="$t('settings.members.inviteEmailPlaceholder')" />
      </div>
      <div>
        <label for="invite-role">{{ $t('settings.members.role') }}</label>
        <select id="invite-role" v-model="inviteForm.role" required>
          <option value="readonly">{{ $t('settings.members.roles.readonly') }}</option>
          <option value="consultant">{{ $t('settings.members.roles.consultant') }}</option>
          <option value="org_admin">{{ $t('settings.members.roles.org_admin') }}</option>
          <option value="org_owner">{{ $t('settings.members.roles.org_owner') }}</option>
        </select>
        <p class="hint" style="margin-top:8px">
          <strong>{{ $t('settings.members.roles.readonly') }}:</strong> {{ $t('settings.members.roleHintReadOnly') }} &middot;
          <strong>{{ $t('settings.members.roles.consultant') }}:</strong> {{ $t('settings.members.roleHintConsultant') }} &middot;
          <strong>{{ $t('settings.members.roles.org_admin') }}:</strong> {{ $t('settings.members.roleHintAdmin') }} &middot;
          <strong>{{ $t('settings.members.roles.org_owner') }}:</strong> {{ $t('settings.members.roleHintOwner') }}
        </p>
      </div>
      <div class="actions" style="justify-content:flex-end">
        <button type="button" class="secondary" @click="showInviteModal = false">{{ $t('common.cancel') }}</button>
        <button type="submit">{{ $t('settings.members.sendInvite') }}</button>
      </div>
    </form>
  </Modal>

  <!-- 2FA Enrollment Modal -->
  <Modal v-if="show2FAEnrollModal" :title="$t('twofa.setupTitle')" @close="show2FAEnrollModal = false" wide>
    <div style="display:grid;gap:24px">
      <!-- Step 1: QR Code -->
      <div>
        <h3 style="margin:0 0 8px 0">{{ $t('twofa.setupStep1') }}</h3>
        <p class="muted" style="margin-bottom:16px">{{ $t('twofa.setupStep1Desc') }}</p>
        <div style="text-align:center;padding:20px;background:white;border-radius:8px;margin-bottom:12px">
          <img :src="twofaQRCode" alt="QR Code" style="max-width:280px;width:100%" />
        </div>
        <button type="button" class="secondary" @click="showSecretKey = !showSecretKey" style="width:100%;margin-bottom:12px">
          {{ showSecretKey ? $t('twofa.setupHideKey') : $t('twofa.setupCantScan') }}
        </button>
        <div v-if="showSecretKey" style="background:var(--background-secondary);padding:16px;border-radius:8px;font-family:monospace;word-break:break-all">
          <p style="font-weight:600;margin-bottom:8px">{{ $t('twofa.setupSecretKey') }}</p>
          <p style="letter-spacing:2px;font-size:14px">{{ twofaSecret }}</p>
        </div>
      </div>
      
      <!-- Step 2: Verify Code -->
      <div>
        <h3 style="margin:0 0 8px 0">{{ $t('twofa.setupStep2') }}</h3>
        <p class="muted" style="margin-bottom:16px">{{ $t('twofa.setupStep2Desc') }}</p>
        <input 
          type="text" 
          v-model="twofaCode" 
          placeholder="000000"
          maxlength="6"
          style="text-align:center;font-size:24px;letter-spacing:8px;font-family:monospace;width:100%"
          @keyup.enter="verify2FAEnrollment"
        />
      </div>
      
      <div class="actions" style="justify-content:flex-end">
        <button type="button" class="secondary" @click="show2FAEnrollModal = false">{{ $t('common.cancel') }}</button>
        <button @click="verify2FAEnrollment" :disabled="twofaCode.length !== 6">{{ $t('twofa.setupVerifyButton') }}</button>
      </div>
    </div>
  </Modal>

  <!-- 2FA Backup Codes Modal -->
  <Modal v-if="show2FABackupCodesModal" :title="$t('twofa.backupCodesTitle')" :closeOnBackdrop="false" wide>
    <div style="display:grid;gap:24px">
      <div style="padding:16px;background:var(--warning-bg);border:1px solid var(--warning);border-radius:8px">
        <p style="font-weight:600;margin-bottom:8px">⚠️ {{ $t('twofa.backupCodesWarning') }}</p>
        <p class="muted" style="margin:0">{{ $t('twofa.backupCodesDesc') }}</p>
      </div>
      
      <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;padding:20px;background:var(--background-secondary);border-radius:8px;font-family:monospace;font-size:16px;letter-spacing:2px">
        <div v-for="(code, idx) in twofaBackupCodes" :key="idx" style="padding:8px;text-align:center">
          {{ code }}
        </div>
      </div>
      
      <div class="actions" style="gap:12px">
        <button class="secondary" @click="copy2FABackupCodes">📋 {{ $t('twofa.backupCodesCopyAll') }}</button>
        <button class="secondary" @click="download2FABackupCodes">💾 {{ $t('twofa.backupCodesDownload') }}</button>
        <button class="secondary" @click="print2FABackupCodes">🖨️ {{ $t('twofa.backupCodesPrint') }}</button>
      </div>
      
      <div style="display:flex;align-items:center;gap:12px;padding:16px;background:var(--background-secondary);border-radius:8px">
        <input type="checkbox" id="backup-codes-saved" v-model="twofaBackupCodesSaved" />
        <label for="backup-codes-saved" style="margin:0;cursor:pointer">{{ $t('twofa.backupCodesConfirmCheckbox') }}</label>
      </div>
      
      <div class="actions" style="justify-content:flex-end">
        <button @click="complete2FAEnrollment" :disabled="!twofaBackupCodesSaved">{{ $t('twofa.backupCodesContinue') }}</button>
      </div>
    </div>
  </Modal>

  <!-- 2FA Password Confirmation Modal -->
  <Modal v-if="show2FAPasswordModal" :title="$t('twofa.passwordConfirmTitle')" @close="show2FAPasswordModal = false">
    <div style="display:grid;gap:16px">
      <p>{{ $t('twofa.passwordConfirmDesc', { action: $t(`twofa.passwordConfirm${twofa2FAAction === 'disable' ? 'Disable' : 'Regenerate'}`) }) }}</p>
      <p v-if="twofa2FAAction === 'regenerate'" class="muted" style="color:var(--warning)">{{ $t('twofa.passwordConfirmInvalidateWarning') }}</p>
      <div>
        <label for="twofa-password">{{ $t('twofa.passwordConfirmPlaceholder') }}</label>
        <input 
          id="twofa-password" 
          type="password" 
          v-model="twofaPassword" 
          :placeholder="$t('twofa.passwordConfirmPlaceholder')"
          @keyup.enter="confirm2FAPassword"
        />
      </div>
      <div class="actions" style="justify-content:flex-end">
        <button type="button" class="secondary" @click="show2FAPasswordModal = false">{{ $t('common.cancel') }}</button>
        <button 
          @click="confirm2FAPassword" 
          :disabled="!twofaPassword"
          :class="{ danger: twofa2FAAction === 'disable' }"
        >
          {{ $t('twofa.passwordConfirmButton') }}
        </button>
      </div>
    </div>
  </Modal>
</template>

<style scoped>
.key-created-banner {
  padding: 16px;
  border-radius: 8px;
  margin-bottom: 20px;
  border: 1px solid var(--success);
  background: var(--success-bg);
}
.key-display {
  background: var(--bg-input);
  padding: 8px 12px;
  border-radius: 4px;
  flex: 1;
  border: 1px solid var(--border);
  overflow-x: auto;
  font-family: monospace;
  user-select: all;
}
.tab-divider {
  display: inline-block;
  width: 1px;
  height: 18px;
  background: var(--border);
  margin: 0 8px;
  align-self: center;
  opacity: 0.6;
  z-index: 1;
}
.tab-icon {
  flex-shrink: 0;
  opacity: 0.6;
  transition: opacity 0.15s;
}
.tab.active .tab-icon {
  opacity: 1;
}

/* ── AI Provider Keys ── */
.ai-keys-card {
  margin-top: 16px;
}
.ai-key-form {
  display: grid;
  gap: 16px;
}
.ai-key-provider-row {
  display: flex;
  align-items: flex-end;
  gap: 16px;
  flex-wrap: wrap;
}
.ai-key-provider-select {
  flex: 1;
  min-width: 180px;
  max-width: 280px;
}
.ai-key-status {
  padding-bottom: 2px;
}
.ai-key-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  font-weight: 600;
  padding: 6px 12px;
  border-radius: 20px;
  letter-spacing: 0.02em;
}
.ai-key-badge.set {
  background: var(--success-bg);
  color: var(--success);
  border: 1px solid var(--success);
}
.ai-key-badge.unset {
  background: var(--bg-meta);
  color: var(--text-muted);
  border: 1px solid var(--border);
}
.ai-key-badge.other {
  background: var(--info-bg, rgba(59,130,246,0.1));
  color: var(--info, #60a5fa);
  border: 1px solid var(--info, #60a5fa);
  font-size: 11px;
}
.ai-key-input-row {
  max-width: 520px;
}
.ai-key-input-group {
  display: flex;
  gap: 0;
}
.ai-key-input-group input {
  flex: 1;
  border-top-right-radius: 0;
  border-bottom-right-radius: 0;
  border-right: none;
}
.role-badge {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  padding: 4px 10px;
  border-radius: 12px;
}

.role-org_owner {
  background: var(--danger-bg);
  color: var(--danger);
}

.role-org_admin {
  background: var(--warning-bg);
  color: var(--warning);
}

.role-consultant {
  background: var(--info-bg);
  color: var(--info);
}

.role-readonly {
  background: var(--success-bg);
  color: var(--success);
}

.form-row-2col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
@media (max-width: 600px) {
  .form-row-2col { grid-template-columns: 1fr; }
}

.llm-section-toggle { margin-top: 8px; }
.toggle-btn {
  background: none;
  border: none;
  padding: 0;
  font: inherit;
  color: var(--text-muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 500;
}
.toggle-btn:hover { color: var(--text-primary); }
.toggle-chevron {
  display: inline-block;
  transition: transform 0.2s;
}
.toggle-chevron.open { transform: rotate(90deg); }

.sampling-params-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
@media (max-width: 600px) {
  .sampling-params-grid { grid-template-columns: 1fr; }
}
</style>
