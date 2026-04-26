<script setup>
import { onMounted, ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { request, getSessionUser } from '../services/api'
import { useRouter } from 'vue-router'
import { setStatus } from '../stores/status'
import { showConfirm } from '../composables/useConfirm'
import Modal from '../components/Modal.vue'
import TagInput from '../components/TagInput.vue'
import TagFilterPicker from '../components/TagFilterPicker.vue'
import { parseSearchWithTags, formatSearchWithTag } from '../utils/searchWithTags'

const { t } = useI18n()
const router = useRouter()
const route = useRoute()
const clients = ref([])
const applications = ref([])
const allReports = ref([])
const reportTagMap = ref({})   // { reportId: ['tagA', 'tagB'] }
const clientTagMap = ref({})     // { clientId: ['tagA', 'tagB'] }
const appTagMap = ref({})      // { appId: ['tagA', 'tagB'] }
const loading = ref(false)

/* ── Search / filter state ── */
const searchQuery = ref('')
const filterTeam = ref('')
const filterApp = ref('')
const filterTag = ref('')

/* ── Add Report state ── */
const showAddForm = ref(false)
const newTeam = ref('')
const newApp = ref('')
const newReportName = ref('')

/* ── Quick Add Application Modal ── */
const showQuickAddApp = ref(false)
const quickAppName = ref('')
const quickAppType = ref('')
const quickAppDescription = ref('')

/* ── Quick Add Team Modal ── */
const showQuickAddTeam = ref(false)
const quickTeamName = ref('')
const isOrgAdmin = ref(false)
const canCreateReports = ref(false)

const APP_TYPES = [
  { value: '', labelKey: 'applications.types.none' },
  { value: 'web', labelKey: 'applications.types.web' },
  { value: 'api', labelKey: 'applications.types.api' },
  { value: 'ios', labelKey: 'applications.types.ios' },
  { value: 'android', labelKey: 'applications.types.android' },
  { value: 'hardware', labelKey: 'applications.types.hardware' },
]

/* ── Edit / Share state ── */
const showModal = ref(false)
const editId = ref(null)
const editName = ref('')
const editTeam = ref('')
const editApp = ref('')
const showShareModal = ref(false)
const shareReport = ref(null)
const shareQuery = ref('')
const shareSuggestions = ref([])
const shareList = ref([])
const shareLoading = ref(false)
const shareSaving = ref(false)
let shareTimer = null

/* ── Collapsed client groups ── */
const collapsedTeams = ref(new Set())
function toggleTeam(clientId) {
  const s = new Set(collapsedTeams.value)
  s.has(clientId) ? s.delete(clientId) : s.add(clientId)
  collapsedTeams.value = s
}

/* ── Helpers ── */
function clientName(clientId) {
  if (clientId == null || clientId === '') return t('reports.unassigned')
  const client = clients.value.find((t) => String(t.id) === String(clientId))
  return client ? client.name : t('reports.unknown')
}

function appName(appId) {
  if (appId == null || appId === '') return t('reports.unassigned')
  const app = applications.value.find((a) => String(a.id) === String(appId))
  return app ? app.name : t('reports.unknown')
}

function relativeDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  const now = new Date()
  const days = Math.floor((now - d) / 86400000)
  if (days === 0) return t('applications.relativeDateToday')
  if (days === 1) return t('applications.relativeDateYesterday')
  if (days < 7) return t('applications.relativeDateDaysAgo', { days })
  if (days < 30) return t('applications.relativeDateWeeksAgo', { weeks: Math.floor(days / 7) })
  return d.toLocaleDateString()
}

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const SEV_VARS = {
  Critical: 'var(--sev-critical-solid)',
  High: 'var(--sev-high-solid)',
  Medium: 'var(--sev-medium-solid)',
  Low: 'var(--sev-low-solid)',
  Informational: 'var(--sev-info-solid)',
}

function severityBarStyle(report) {
  const breakdown = report.severity_breakdown || {}
  const total = report.finding_count || 0
  if (!total) return {}
  const stops = []
  let pos = 0
  for (const sev of SEV_ORDER) {
    const count = breakdown[sev] || 0
    if (!count) continue
    const end = pos + (count / total) * 100
    stops.push(`${SEV_VARS[sev]} ${pos.toFixed(2)}% ${end.toFixed(2)}%`)
    pos = end
  }
  return { background: `linear-gradient(90deg, ${stops.join(', ')})` }
}

/* ── Search display: supports @tag in query (e.g. "login @owasp") ── */
const searchDisplayValue = computed(() => formatSearchWithTag(searchQuery.value, filterTag.value))

function onSearchInput(val) {
  const { query, tag } = parseSearchWithTags(val)
  searchQuery.value = query
  filterTag.value = tag
}

/* ── Filtered & grouped reports ── */
const UNASSIGNED_ID = '__unassigned__'
const filteredReports = computed(() => {
  let list = allReports.value
  const q = searchQuery.value.trim().toLowerCase()
  if (q) {
    list = list.filter(r => {
      const tags = (reportTagMap.value[r.id] || []).join(' ').toLowerCase()
      return r.name.toLowerCase().includes(q) ||
        appName(r.application_id).toLowerCase().includes(q) ||
        clientName(r.client_id).toLowerCase().includes(q) ||
        tags.includes(q)
    })
  }
  if (filterTeam.value) {
    list = list.filter(r => (r.client_id == null || r.client_id === '') ? filterTeam.value === UNASSIGNED_ID : String(r.client_id) === filterTeam.value)
  }
  if (filterApp.value) {
    list = list.filter(r => (r.application_id == null || r.application_id === '') ? filterApp.value === UNASSIGNED_ID : String(r.application_id) === filterApp.value)
  }
  if (filterTag.value) {
    list = list.filter(r => {
      const reportHasTag = (reportTagMap.value[r.id] || []).includes(filterTag.value)
      const clientHasTag = (clientTagMap.value[r.client_id] || []).includes(filterTag.value)
      const appHasTag = (appTagMap.value[r.application_id] || []).includes(filterTag.value)
      return reportHasTag || clientHasTag || appHasTag
    })
  }
  return list
})

const clientsWithReports = computed(() => {
  const clientMap = new Map()
  for (const t of clients.value) {
    clientMap.set(String(t.id), { ...t, reports: [] })
  }
  clientMap.set(UNASSIGNED_ID, { id: UNASSIGNED_ID, name: t('reports.unassigned'), reports: [] })
  for (const r of filteredReports.value) {
    const key = r.client_id != null && r.client_id !== '' ? String(r.client_id) : UNASSIGNED_ID
    const entry = clientMap.get(key)
    if (entry) entry.reports.push(r)
  }
  const hasFilter = searchQuery.value.trim() || filterTeam.value || filterApp.value || filterTag.value
  let result = [...clientMap.values()]
  if (hasFilter) {
    result = result.filter(g => g.reports.length > 0)
  }
  return result.sort((a, b) => {
    if (a.id === UNASSIGNED_ID) return 1
    if (b.id === UNASSIGNED_ID) return -1
    if (a.reports.length && !b.reports.length) return -1
    if (!a.reports.length && b.reports.length) return 1
    return a.name.localeCompare(b.name)
  })
})

const totalReports = computed(() => allReports.value.length)
const matchingReports = computed(() => filteredReports.value.length)

/* ── Data loading ── */
async function loadAll() {
  loading.value = true
  try {
    const [clientsData, appsData, reportsData] = await Promise.all([
      request('/api/admin/clients'),
      request('/api/admin/applications'),
      request('/api/admin/reports'),
    ])
    clients.value = clientsData
    applications.value = appsData
    allReports.value = reportsData
    // Tags for filter are loaded on demand by TagFilterPicker (searchable)
    // Check if client/app is pre-selected via query param (from Teams or Applications page)
    const preselectedTeam = route.query.client
    const preselectedApp = route.query.app
    if (preselectedTeam && clients.value.some(t => String(t.id) === String(preselectedTeam))) {
      newTeam.value = String(preselectedTeam)
    } else if (!newTeam.value && clients.value.length) {
      newTeam.value = String(clients.value[0].id)
    } else if (!newTeam.value) {
      newTeam.value = ''
    }
    if (preselectedApp && applications.value.some(a => String(a.id) === String(preselectedApp))) {
      newApp.value = String(preselectedApp)
    } else if (!newApp.value && applications.value.length) {
      newApp.value = String(applications.value[0].id)
    } else if (!newApp.value || newApp.value === '__create_new__') {
      newApp.value = ''
    }
    // Bulk-fetch tags for all reports, clients, and applications
    if (reportsData.length) {
      const ids = reportsData.map(r => r.id).join(',')
      const tagMap = await request(`/api/admin/tags/entity-bulk/report?ids=${encodeURIComponent(ids)}`)
      reportTagMap.value = tagMap || {}
    }
    if (clientsData.length) {
      const ids = clientsData.map(t => t.id).join(',')
      const tagMap = await request(`/api/admin/tags/entity-bulk/client?ids=${encodeURIComponent(ids)}`)
      clientTagMap.value = tagMap || {}
    }
    if (appsData.length) {
      const ids = appsData.map(a => a.id).join(',')
      const tagMap = await request(`/api/admin/tags/entity-bulk/application?ids=${encodeURIComponent(ids)}`)
      appTagMap.value = tagMap || {}
    }
  } catch (e) {
    setStatus(t('reports.failedToLoad'), 'error')
  } finally {
    loading.value = false
  }
  try {
    const user = await getSessionUser()
    const orgRole = user?.org_role || 'readonly'
    isOrgAdmin.value = user.role === 'admin' || ['org_admin', 'org_owner'].includes(orgRole)
    canCreateReports.value = orgRole !== 'readonly'
  } catch {
    isOrgAdmin.value = false
    canCreateReports.value = false
  }
}

async function reloadTagMaps() {
  // Reload bulk tag maps after a tag is added/removed
  try {
    if (allReports.value.length) {
      const ids = allReports.value.map(r => r.id).join(',')
      const tagMap = await request(`/api/admin/tags/entity-bulk/report?ids=${encodeURIComponent(ids)}`)
      reportTagMap.value = tagMap || {}
    }
    if (clients.value.length) {
      const ids = clients.value.map(t => t.id).join(',')
      const tagMap = await request(`/api/admin/tags/entity-bulk/client?ids=${encodeURIComponent(ids)}`)
      clientTagMap.value = tagMap || {}
    }
    if (applications.value.length) {
      const ids = applications.value.map(a => a.id).join(',')
      const tagMap = await request(`/api/admin/tags/entity-bulk/application?ids=${encodeURIComponent(ids)}`)
      appTagMap.value = tagMap || {}
    }
  } catch (e) {
    console.error('Failed to reload tag maps:', e)
  }
}

/* ── Quick Add Application ── */
function openQuickAddApp() {
  quickAppName.value = ''
  quickAppType.value = ''
  quickAppDescription.value = ''
  showQuickAddApp.value = true
}

function closeQuickAddApp() {
  showQuickAddApp.value = false
  quickAppName.value = ''
  quickAppType.value = ''
  quickAppDescription.value = ''
}

async function createQuickApp() {
  if (!quickAppName.value.trim()) return
  setStatus(t('applications.addingApplication'), 'info')
  try {
    const newApplication = await request('/api/admin/applications', {
      method: 'POST',
      body: JSON.stringify({
        name: quickAppName.value.trim(),
        type: quickAppType.value || null,
        description: quickAppDescription.value.trim() || '',
      }),
    })
    applications.value.push(newApplication)
    const appId = String(newApplication.id)
    newApp.value = appId
    if (showModal.value) editApp.value = appId
    closeQuickAddApp()
    setStatus(t('applications.applicationAdded'), 'success')
  } catch (error) {
    setStatus(error.message || t('applications.errorAddingApplication'), 'error')
  }
}

function onAppSelectChange(event) {
  if (event.target.value === '__create_new__') {
    event.target.value = newApp.value
    openQuickAddApp()
  }
}

function onEditAppSelectChange(event) {
  if (event.target.value === '__create_new__') {
    event.target.value = editApp.value
    openQuickAddApp()
  }
}

/* ── Quick Add Team ── */
function openQuickAddTeam() {
  quickTeamName.value = ''
  showQuickAddTeam.value = true
}

function closeQuickAddTeam() {
  showQuickAddTeam.value = false
  quickTeamName.value = ''
}

async function createQuickTeam() {
  if (!quickTeamName.value.trim()) return
  setStatus(t('clients.addingTeam'), 'info')
  try {
    const newTeamObj = await request('/api/admin/clients', {
      method: 'POST',
      body: JSON.stringify({ name: quickTeamName.value.trim() }),
    })
    clients.value.push(newTeamObj)
    const clientId = String(newTeamObj.id)
    newTeam.value = clientId
    if (showModal.value) editTeam.value = clientId
    closeQuickAddTeam()
    setStatus(t('clients.clientAdded'), 'success')
  } catch (error) {
    setStatus(error.message || t('reports.failedToLoad'), 'error')
  }
}

function onTeamSelectChange() {
  if (newTeam.value === '__create_new__') {
    newTeam.value = ''
    openQuickAddTeam()
  }
}

function onEditTeamSelectChange() {
  if (editTeam.value === '__create_new__') {
    editTeam.value = ''
    openQuickAddTeam()
  }
}

/* ── Add report ── */
async function addReport() {
  if (!newReportName.value.trim()) return
  if (newApp.value === '__create_new__' || newTeam.value === '__create_new__') return
  setStatus(t('reports.addingReport'), 'info')
  const payload = { name: newReportName.value.trim() }
  if (newTeam.value) payload.client_id = newTeam.value
  if (newApp.value) payload.application_id = newApp.value
  const res = await request('/api/admin/reports', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
  newReportName.value = ''
  showAddForm.value = false
  await loadAll()
  setStatus(t('reports.reportAdded'), 'success')
  if (route.query.new === '1' && res?.id) {
    router.replace({ path: `/dashboard/reports/${res.id}/findings`, query: {} })
  }
}

/* ── Edit / Delete ── */
function openEdit(report) {
  editId.value = report.id
  editName.value = report.name
  editTeam.value = report.client_id != null && report.client_id !== '' ? String(report.client_id) : ''
  editApp.value = report.application_id != null && report.application_id !== '' ? String(report.application_id) : ''
  showModal.value = true
}

async function saveEdit() {
  setStatus(t('reports.savingReport'), 'info')
  const payload = { name: editName.value.trim() }
  if (editTeam.value) payload.client_id = editTeam.value
  else payload.client_id = null
  if (editApp.value) payload.application_id = editApp.value
  else payload.application_id = null
  await request(`/api/admin/reports/${editId.value}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
  showModal.value = false
  editId.value = null
  editName.value = ''
  editTeam.value = ''
  editApp.value = ''
  await loadAll()
  setStatus(t('reports.reportUpdated'), 'success')
}

async function removeReport(id) {
  const ok = await showConfirm({ message: t('reports.deleteConfirm'), danger: true })
  if (!ok) return
  setStatus(t('reports.deletingReport'), 'info')
  await request(`/api/admin/reports/${id}`, { method: 'DELETE' })
  await loadAll()
  setStatus(t('reports.reportDeleted'), 'success')
}

function goFindings(report) {
  router.push(`/dashboard/reports/${report.id}/findings`)
}

/* ── Sharing ── */
async function openShare(report) {
  shareReport.value = report
  shareQuery.value = ''
  shareSuggestions.value = []
  showShareModal.value = true
  await loadShareList()
}

async function loadShareList() {
  if (!shareReport.value) return
  shareLoading.value = true
  try {
    shareList.value = await request(`/api/admin/reports/${shareReport.value.id}/shares`)
  } finally {
    shareLoading.value = false
  }
}

function onShareQueryInput() {
  if (shareTimer) clearTimeout(shareTimer)
  shareTimer = setTimeout(loadShareSuggestions, 200)
}

async function loadShareSuggestions() {
  if (!shareReport.value) return
  const q = shareQuery.value.trim()
  if (!q) {
    shareSuggestions.value = []
    return
  }
  shareLoading.value = true
  try {
    shareSuggestions.value = await request(
      `/api/admin/reports/${shareReport.value.id}/share-candidates?query=${encodeURIComponent(q)}`
    )
  } finally {
    shareLoading.value = false
  }
}

async function addShare(candidate) {
  if (!shareReport.value || shareSaving.value) return
  shareSaving.value = true
  try {
    await request(`/api/admin/reports/${shareReport.value.id}/shares`, {
      method: 'POST',
      body: JSON.stringify({ user_id: candidate.user_id }),
    })
    setStatus(t('reports.sharedWithUser', { email: candidate.email }), 'success')
    shareQuery.value = ''
    shareSuggestions.value = []
    await loadShareList()
  } catch (err) {
    setStatus(err.message || t('reports.failedToShare'), 'error')
  } finally {
    shareSaving.value = false
  }
}

async function removeShare(shared) {
  if (!shareReport.value) return
  const ok = await showConfirm({ message: t('reports.removeShareConfirm', { email: shared.email }) })
  if (!ok) return
  try {
    await request(`/api/admin/reports/${shareReport.value.id}/shares/${shared.user_id}`, {
      method: 'DELETE',
    })
    setStatus(t('reports.removedAccessFor', { email: shared.email }), 'success')
    await loadShareList()
  } catch (err) {
    setStatus(err.message || t('reports.failedToRemoveShare'), 'error')
  }
}

function clearFilters() {
  searchQuery.value = ''
  filterTeam.value = ''
  filterApp.value = ''
  filterTag.value = ''
}

function onTagClick(tagName) {
  filterTag.value = filterTag.value === tagName ? '' : tagName
}

/* ── Keep URL in sync with tag filter (shareable / bookmarkable, no reload) ── */
function syncTagToUrl() {
  const tag = filterTag.value?.trim() || ''
  const next = { ...route.query }
  if (tag) next.tag = tag
  else delete next.tag
  if (JSON.stringify(next) !== JSON.stringify(route.query)) {
    router.replace({ path: route.path, query: next })
  }
}

watch(filterTag, () => { syncTagToUrl() })
watch(() => route.query.tag, (tag) => {
  const v = tag || ''
  if (filterTag.value !== v) filterTag.value = v
})

onMounted(() => {
  if (route.query.tag) {
    filterTag.value = route.query.tag
  }
  // Auto-open add form if navigating from Teams page
  if (route.query.new === '1') {
    showAddForm.value = true
  }
  if (route.query.new === '1') {
    showAddForm.value = true
  }
  loadAll()
})
</script>

<template>
  <div class="org-hero">
    <div class="org-title">
      <p class="kicker">{{ $t('reports.kicker') }}</p>
      <h1>{{ $t('reports.title') }}</h1>
      <p class="subtitle">{{ $t('reports.subtitle') }}</p>
    </div>
  </div>

  <!-- ── Toolbar: search + filter + add button ── -->
  <div class="toolbar card">
    <div class="toolbar-row">
      <div class="search-box">
        <svg class="search-icon" viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
          <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/>
        </svg>
        <input
          :value="searchDisplayValue"
          :placeholder="$t('reports.searchPlaceholder')"
          class="search-input"
          :aria-label="$t('reports.searchAriaLabel')"
          @input="(e) => onSearchInput(e.target.value)"
        />
      </div>

      <select v-model="filterTeam" class="filter-select" :aria-label="$t('reports.filterTeamAriaLabel')">
        <option value="">{{ $t('reports.allTeams') }}</option>
        <option :value="UNASSIGNED_ID">{{ $t('reports.unassigned') }}</option>
        <option v-for="t in clients" :key="t.id" :value="String(t.id)">{{ t.name }}</option>
      </select>

      <select v-model="filterApp" class="filter-select" :aria-label="$t('reports.filterAppAriaLabel')">
        <option value="">{{ $t('reports.allApplications') }}</option>
        <option :value="UNASSIGNED_ID">{{ $t('reports.unassigned') }}</option>
        <option v-for="a in applications" :key="a.id" :value="String(a.id)">{{ a.name }}</option>
      </select>

      <TagFilterPicker
        v-model="filterTag"
        :placeholder="$t('reports.allTags')"
        class="filter-tag-picker"
      />

      <button
        v-if="searchQuery || filterTeam || filterApp || filterTag"
        class="ghost-btn"
        @click="clearFilters"
        :aria-label="$t('reports.clearFiltersAriaLabel')"
      >{{ $t('common.reset') }}</button>

      <button v-if="canCreateReports" class="add-btn" @click="showAddForm = !showAddForm" :aria-label="$t('reports.newReportAriaLabel')">
        <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
          <path d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z"/>
        </svg>
        {{ $t('reports.newReport') }}
      </button>
    </div>

    <!-- Stats line -->
    <div class="toolbar-stats" v-if="!loading">
      <span v-if="searchQuery || filterTeam || filterApp || filterTag">
        {{ $t('reports.statsFiltered', { matching: matchingReports, total: totalReports }) }}
      </span>
      <span v-else>{{ $t('reports.statsOverview', { reportCount: $t(totalReports === 1 ? 'reports.reportCount' : 'reports.reportCountPlural', { count: totalReports }), clientCount: $t(clients.length === 1 ? 'reports.clientCount' : 'reports.clientCountPlural', { count: clients.length }) }) }}</span>
    </div>
  </div>

  <!-- ── Add report panel (slides open) ── -->
  <transition name="slide">
    <div v-if="showAddForm && canCreateReports" class="add-panel card">
      <div class="add-panel-header">
        <h3 class="add-panel-title">{{ $t('reports.createNewReport') }}</h3>
        <button class="ghost-btn" @click="showAddForm = false" :aria-label="$t('reports.closeAddFormAriaLabel')">{{ $t('common.cancel') }}</button>
      </div>
      <div class="add-panel-form">
        <div>
          <label for="new-client-select">{{ $t('reports.clientOptional') }}</label>
          <select id="new-client-select" v-model="newTeam" @change="onTeamSelectChange">
            <option value="">{{ $t('reports.unassigned') }}</option>
            <option v-for="t in clients" :key="t.id" :value="String(t.id)">{{ t.name }}</option>
            <option v-if="isOrgAdmin" value="__create_new__" style="font-weight: 600; color: var(--teal-600);">+ {{ $t('reports.createNewTeam') }}</option>
          </select>
        </div>
        <div>
          <label for="new-app-select">{{ $t('reports.applicationOptional') }}</label>
          <select id="new-app-select" v-model="newApp" @change="onAppSelectChange">
            <option value="">{{ $t('reports.unassigned') }}</option>
            <option v-for="a in applications" :key="a.id" :value="String(a.id)">{{ a.name }}</option>
            <option value="__create_new__" style="font-weight: 600; color: var(--teal-600);">+ {{ $t('reports.createNewApplication') }}</option>
          </select>
        </div>
        <div class="add-panel-name">
          <label for="new-report-name">{{ $t('reports.reportNameLabel') }}</label>
          <input
            id="new-report-name"
            v-model="newReportName"
            :placeholder="$t('reports.reportNamePlaceholder')"
            @keyup.enter="addReport"
            :aria-label="$t('reports.newReportNameAriaLabel')"
          />
        </div>
        <div class="add-panel-action">
          <button
            @click="addReport"
            :disabled="!newReportName.trim()"
            :aria-label="$t('reports.createReportAriaLabel')"
          >
            {{ $t('reports.createReport') }}
          </button>
        </div>
      </div>
    </div>
  </transition>

  <!-- ── Report list ── -->
  <div v-if="loading" class="card"><p class="muted">{{ $t('reports.loadingReports') }}</p></div>

  <template v-else>
    <div v-if="clientsWithReports.length === 0" class="card">
      <div class="empty-state">
        <p class="muted">{{ clients.length === 0 ? $t('reports.noTeamsYet') : (searchQuery || filterTeam || filterApp ? $t('reports.noReportsMatchFilters') : $t('reports.noReportsYet')) }}</p>
        <router-link v-if="clients.length === 0" to="/dashboard/clients" class="ghost-btn">{{ $t('reports.goToTeams') }}</router-link>
        <button v-else-if="searchQuery || filterTeam || filterApp" class="ghost-btn" @click="clearFilters">{{ $t('reports.clearFilters') }}</button>
      </div>
    </div>

    <div
      v-for="group in clientsWithReports"
      :key="group.id"
      class="card client-group"
    >
      <div class="client-group-header" @click="toggleTeam(group.id)">
        <div class="client-group-left">
          <svg
            class="chevron"
            :class="{ collapsed: collapsedTeams.has(group.id) }"
            viewBox="0 0 20 20"
            fill="currentColor"
            width="16"
            height="16"
          >
            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/>
          </svg>
          <h3 class="client-group-name">{{ group.name }}</h3>
        </div>
        <span class="client-group-count">{{ group.reports.length === 1 ? $t('reports.reportCount', { count: group.reports.length }) : $t('reports.reportCountPlural', { count: group.reports.length }) }}</span>
      </div>

      <template v-if="!collapsedTeams.has(group.id)">
        <div v-if="group.id === UNASSIGNED_ID && group.reports.length" class="unassigned-banner">
          {{ $t('reports.unassignedBanner') }}
        </div>
        <div class="report-list" v-if="group.reports.length">
          <div
            v-for="report in group.reports"
            :key="report.id"
            class="report-row"
            @click="goFindings(report)"
          >
            <div class="report-main">
              <div class="report-name">{{ report.name }}</div>
              <div class="report-meta">
                <template v-if="(report.client_id == null || report.client_id === '') && (report.application_id == null || report.application_id === '') && report.can_edit">
                  <button type="button" class="assign-btn" @click.stop="openEdit(report)" :aria-label="$t('reports.assignTeamAndAppAriaLabel')">
                    {{ $t('reports.assignTeamAndApp') }}
                  </button>
                </template>
                <template v-else>
                  <span class="report-client">{{ clientName(report.client_id) }}</span>
                  <span class="report-meta-sep">·</span>
                  <span class="report-app">{{ appName(report.application_id) }}</span>
                  <span class="report-meta-sep">·</span>
                  <span class="report-date">{{ relativeDate(report.created_at) }}</span>
                </template>
                <template v-if="report.finding_count > 0">
                  <span class="report-meta-sep">·</span>
                  <span class="report-finding-count">{{ report.finding_count }} {{ $t('reports.findings') }}</span>
                </template>
              </div>
              <div
                v-if="report.finding_count > 0"
                class="sev-bar"
                :style="severityBarStyle(report)"
                role="img"
                :aria-label="$t('reports.severityBreakdown')"
              ></div>
            </div>
            <div class="report-tags" @click.stop>
              <TagInput entityType="report" :entityId="report.id" :readonly="!report.can_edit" @tag-click="onTagClick" @tags-changed="reloadTagMaps" />
            </div>
            <div class="report-actions" @click.stop>
              <button class="icon-btn" @click="goFindings(report)" :title="$t('reports.viewFindings')" :aria-label="$t('reports.viewFindings')">
                <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z"/><path fill-rule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clip-rule="evenodd"/></svg>
              </button>
              <button v-if="report.can_edit" class="icon-btn" @click="openEdit(report)" :title="$t('reports.editReport')" :aria-label="$t('reports.editReport')">
                <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"/></svg>
              </button>
              <button v-if="report.can_manage_shares" class="icon-btn" @click="openShare(report)" :title="$t('reports.shareReport')" :aria-label="$t('reports.shareReport')">
                <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path d="M15 8a3 3 0 10-2.977-2.63l-4.94 2.47a3 3 0 100 4.319l4.94 2.47a3 3 0 10.895-1.789l-4.94-2.47a3.027 3.027 0 000-.74l4.94-2.47C13.456 7.68 14.19 8 15 8z"/></svg>
              </button>
              <button v-if="report.can_edit" class="icon-btn danger" @click="removeReport(report.id)" :title="$t('reports.deleteReport')" :aria-label="$t('reports.deleteReport')">
                <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16"><path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
              </button>
            </div>
          </div>
        </div>
        <p v-else class="muted" style="margin:0">{{ $t('reports.noReportsForTeam') }}</p>
      </template>
    </div>
  </template>

  <!-- ── Edit modal ── -->
  <Modal v-if="showModal" :title="$t('reports.editReportTitle')" @close="showModal = false">
    <div style="display:grid;gap:16px">
      <div>
        <label for="edit-report-name">{{ $t('reports.reportNameLabel') }}</label>
        <input id="edit-report-name" v-model="editName" @keyup.enter="saveEdit" :aria-label="$t('reports.editReportNameAriaLabel')" />
      </div>
      <div>
        <label for="edit-client-select">{{ $t('reports.clientOptional') }}</label>
        <select id="edit-client-select" v-model="editTeam" @change="onEditTeamSelectChange">
          <option value="">{{ $t('reports.unassigned') }}</option>
          <option v-for="t in clients" :key="t.id" :value="String(t.id)">{{ t.name }}</option>
          <option v-if="isOrgAdmin" value="__create_new__" style="font-weight: 600; color: var(--teal-600);">+ {{ $t('reports.createNewTeam') }}</option>
        </select>
      </div>
      <div>
        <label for="edit-app-select">{{ $t('reports.applicationOptional') }}</label>
        <select id="edit-app-select" v-model="editApp" @change="onEditAppSelectChange">
          <option value="">{{ $t('reports.unassigned') }}</option>
          <option v-for="a in applications" :key="a.id" :value="String(a.id)">{{ a.name }}</option>
          <option value="__create_new__" style="font-weight: 600; color: var(--teal-600);">+ {{ $t('reports.createNewApplication') }}</option>
        </select>
      </div>
      <div class="actions" style="justify-content:flex-end">
        <button class="secondary" @click="showModal = false" :aria-label="$t('reports.cancelEditingAriaLabel')">{{ $t('common.cancel') }}</button>
        <button @click="saveEdit" :disabled="!editName.trim()" :aria-label="$t('reports.saveReportNameAriaLabel')">{{ $t('common.save') }}</button>
      </div>
    </div>
  </Modal>

  <!-- ── Share modal ── -->
  <Modal v-if="showShareModal" :title="$t('reports.shareReportTitle')" wide @close="showShareModal = false">
    <div class="share-grid">
      <div class="share-panel">
        <label for="share-user-query">{{ $t('reports.findPeopleLabel') }}</label>
        <input
          id="share-user-query"
          v-model="shareQuery"
          :placeholder="$t('reports.shareSearchPlaceholder')"
          @input="onShareQueryInput"
          :aria-label="$t('reports.shareSearchAriaLabel')"
        />
        <div class="share-suggestions" v-if="shareQuery.trim()">
          <div v-if="shareLoading" class="muted">{{ $t('reports.searching') }}</div>
          <button
            v-for="candidate in shareSuggestions"
            :key="candidate.user_id"
            class="share-suggestion"
            @click="addShare(candidate)"
          >
            <div>
              <div class="share-name">{{ candidate.name || candidate.email }}</div>
              <div class="share-email">{{ candidate.email }}</div>
            </div>
            <span class="share-role">{{ candidate.role }}</span>
          </button>
          <div v-if="!shareLoading && shareSuggestions.length === 0" class="muted">
            {{ $t('reports.noMatchesInOrg') }}
          </div>
        </div>
      </div>

      <div class="share-panel">
        <div class="share-header">
          <h4>{{ $t('reports.sharedWith') }}</h4>
          <button class="secondary" @click="loadShareList">{{ $t('reports.refresh') }}</button>
        </div>
        <div v-if="shareLoading" class="muted">{{ $t('reports.loadingShares') }}</div>
        <div v-else-if="shareList.length === 0" class="muted">{{ $t('reports.noSharedUsers') }}</div>
        <div v-else class="share-list">
          <div class="share-row" v-for="shared in shareList" :key="shared.user_id">
            <div>
              <div class="share-name">{{ shared.name || shared.email }}</div>
              <div class="share-email">{{ shared.email }}</div>
            </div>
            <div class="share-actions">
              <span class="share-role">{{ shared.role || $t('reports.roleMember') }}</span>
              <button class="danger" @click="removeShare(shared)">{{ $t('common.remove') }}</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </Modal>

  <!-- ── Quick Add Team Modal ── -->
  <Modal v-if="showQuickAddTeam" :title="$t('reports.quickAddTeamTitle')" @close="closeQuickAddTeam">
    <div class="quick-add-form">
      <div>
        <label for="quick-client-name">{{ $t('common.name') }}</label>
        <input
          id="quick-client-name"
          v-model="quickTeamName"
          :placeholder="$t('clients.teamNamePlaceholder')"
          @keyup.enter="createQuickTeam"
          autofocus
        />
      </div>
      <div class="modal-actions">
        <button class="ghost-btn" @click="closeQuickAddTeam">{{ $t('common.cancel') }}</button>
        <button @click="createQuickTeam" :disabled="!quickTeamName.trim()">
          {{ $t('clients.addTeam') }}
        </button>
      </div>
    </div>
  </Modal>

  <!-- ── Quick Add Application Modal ── -->
  <Modal v-if="showQuickAddApp" :title="$t('reports.quickAddApplicationTitle')" @close="closeQuickAddApp">
    <div class="quick-add-form">
      <div>
        <label for="quick-app-name">{{ $t('common.name') }}</label>
        <input
          id="quick-app-name"
          v-model="quickAppName"
          :placeholder="$t('applications.namePlaceholder')"
          @keyup.enter="createQuickApp"
          autofocus
        />
      </div>
      <div>
        <label for="quick-app-type">{{ $t('applications.typeLabel') }}</label>
        <select id="quick-app-type" v-model="quickAppType">
          <option v-for="typeOpt in APP_TYPES" :key="typeOpt.value" :value="typeOpt.value">{{ $t(typeOpt.labelKey) }}</option>
        </select>
      </div>
      <div>
        <label for="quick-app-description">{{ $t('applications.descriptionLabel') }}</label>
        <textarea
          id="quick-app-description"
          v-model="quickAppDescription"
          :placeholder="$t('applications.descriptionPlaceholder')"
          rows="3"
        ></textarea>
      </div>
      <div class="modal-actions">
        <button class="ghost-btn" @click="closeQuickAddApp">{{ $t('common.cancel') }}</button>
        <button @click="createQuickApp" :disabled="!quickAppName.trim()">
          {{ $t('applications.addApplication') }}
        </button>
      </div>
    </div>
  </Modal>
</template>

<style scoped>
/* ── Toolbar ── */
.toolbar {
  position: sticky;
  top: 0;
  z-index: 10;
}
.toolbar-row {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}
.search-box {
  position: relative;
  flex: 1;
  min-width: 200px;
}
.search-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--text-faint);
  pointer-events: none;
}
.search-input {
  width: 100%;
  padding-left: 36px !important;
}
.filter-select {
  min-width: 140px;
  max-width: 200px;
}

.ghost-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  padding: 8px 14px;
  border-radius: 8px;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.ghost-btn:hover {
  background: var(--bg-input);
  color: var(--text-primary);
}

.add-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
  font-weight: 600;
}

.toolbar-stats {
  margin-top: 8px;
  font-size: 12px;
  color: var(--text-faint);
  letter-spacing: 0.02em;
}

/* ── Add panel slide ── */
.add-panel {
  border-left: 3px solid var(--primary);
}
.add-panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.add-panel-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
}
.add-panel-form {
  display: grid;
  grid-template-columns: 1fr 1fr 2fr auto;
  gap: 16px;
  align-items: end;
}
.add-panel-form > div {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.add-panel-form label {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
}
.add-panel-name {
  min-width: 0;
}
.add-panel-action {
  display: flex;
  align-items: flex-end;
  align-self: stretch;
}
.field-hint {
  margin-top: 4px;
  align-self: stretch;
}
.field-hint-below {
  margin-top: 8px;
  margin-bottom: 0;
}
.slide-enter-active, .slide-leave-active {
  transition: all 0.2s ease;
  overflow: hidden;
}
.slide-enter-from, .slide-leave-to {
  opacity: 0;
  max-height: 0;
  padding-top: 0;
  padding-bottom: 0;
  margin-top: 0;
  margin-bottom: 0;
}
.slide-enter-to, .slide-leave-from {
  opacity: 1;
  max-height: 200px;
}

@media (max-width: 768px) {
  .toolbar-row { flex-direction: column; align-items: stretch; }
  .filter-select { max-width: none; }
  .add-panel-form { grid-template-columns: 1fr; }
  .report-row {
    grid-template-columns: 1fr;
    grid-template-rows: auto auto auto;
  }
  .report-tags { order: 2; }
  .report-actions { order: 3; justify-content: flex-start; }
}

/* ── Team groups ── */
.client-group {
  margin-bottom: 0;
}
.client-group + .client-group {
  margin-top: 12px;
}
.client-group-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  cursor: pointer;
  user-select: none;
  padding: 2px 0;
}
.client-group-header:hover .client-group-name {
  color: var(--primary);
}
.client-group-left {
  display: flex;
  align-items: center;
  gap: 6px;
}
.chevron {
  color: var(--text-faint);
  transition: transform 0.2s;
  flex-shrink: 0;
}
.chevron.collapsed {
  transform: rotate(-90deg);
}
.client-group-name {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
  transition: color 0.15s;
}
.client-group-count {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-faint);
  white-space: nowrap;
}

/* ── Report rows (replacing table) ── */
.report-list {
  display: flex;
  flex-direction: column;
  gap: 1px;
  margin-top: 12px;
  border-radius: 10px;
  overflow: hidden;
  border: 1px solid var(--border);
}
.report-row {
  display: grid;
  grid-template-columns: 1fr minmax(120px, auto) auto;
  gap: 12px;
  align-items: center;
  padding: 12px 16px;
  background: var(--bg-input);
  cursor: pointer;
  transition: background 0.12s;
}
.report-row:hover {
  background: color-mix(in srgb, var(--primary) 6%, var(--bg-input));
}
.report-main {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}
.report-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.report-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  color: var(--text-muted);
}
.report-meta-sep {
  color: var(--text-faint);
  user-select: none;
}
.assign-btn {
  font-size: 12px;
  font-weight: 600;
  color: var(--primary);
  background: transparent;
  border: 1px dashed var(--primary);
  border-radius: 6px;
  padding: 10px 16px;
  min-height: 44px;
  cursor: pointer;
  transition: all 0.12s;
}
.assign-btn:hover {
  background: color-mix(in srgb, var(--primary) 10%, transparent);
}
.report-client,
.report-app {
  color: var(--text-secondary);
}
.report-date {
  color: var(--text-faint);
}
.report-finding-count {
  color: var(--text-faint);
}
.sev-bar {
  height: 5px;
  border-radius: 3px;
  margin-top: 5px;
  width: 100%;
}
.unassigned-banner {
  font-size: 13px;
  color: var(--text-muted);
  padding: 10px 16px;
  background: color-mix(in srgb, var(--primary) 4%, var(--bg-input));
  border-bottom: 1px solid var(--border);
}
.report-tags {
  min-width: 120px;
  max-width: 250px;
}

/* ── Icon buttons for actions ── */
.report-actions {
  display: flex;
  gap: 4px;
  flex-shrink: 0;
}
/* 44px min touch target per WCAG 2.5.5 */
.icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 44px;
  min-height: 44px;
  width: 44px;
  height: 44px;
  border-radius: 8px;
  border: none;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.12s;
  padding: 0;
}
.icon-btn:hover {
  background: var(--bg-card);
  color: var(--text-primary);
}
.icon-btn.danger:hover {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}

/* ── Empty state ── */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 12px;
}

/* ── Share modal ── */
.share-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 20px;
}
.share-panel {
  display: grid;
  gap: 12px;
}
.share-suggestions {
  display: grid;
  gap: 8px;
  max-height: 220px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px;
  background: var(--bg-input);
}
.share-suggestion {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  text-align: left;
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px solid transparent;
  background: transparent;
}
.share-suggestion:hover {
  border-color: var(--border);
  background: var(--bg-card);
}
.share-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.share-list {
  display: grid;
  gap: 10px;
}
.share-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--bg-card);
}
.share-name { font-weight: 600; }
.share-email { font-size: 12px; color: var(--text-secondary); }
.share-role {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-faint);
}
.share-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

/* ── Quick Add Application Modal ── */
.quick-add-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 8px 0;
}
.quick-add-form label {
  display: block;
  margin-bottom: 6px;
  font-weight: 600;
  color: var(--text-primary);
}
.quick-add-form input,
.quick-add-form select,
.quick-add-form textarea {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-input);
  color: var(--text-primary);
  font-size: 14px;
}
.quick-add-form textarea {
  resize: vertical;
  font-family: inherit;
}
.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding-top: 8px;
}
.field-hint {
  margin-top: 6px;
  font-size: 12px;
  color: var(--text-secondary);
  font-style: italic;
}

@media (max-width: 768px) {
  .report-row {
    grid-template-columns: 1fr;
    gap: 8px;
  }
  .report-actions {
    justify-content: flex-end;
  }
  .report-tags {
    max-width: none;
  }
}
</style>
