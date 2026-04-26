<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { useSeverityColors } from '../composables/useSeverityColors.js'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request } from '../services/api'
import { showConfirm } from '../composables/useConfirm'

const router = useRouter()
const { t } = useI18n()
const { sevColors } = useSeverityColors()
import StackedArea from '../components/charts/StackedArea.vue'
import HistogramBar from '../components/charts/HistogramBar.vue'
import SimpleLine from '../components/charts/SimpleLine.vue'
import HeatmapGrid from '../components/HeatmapGrid.vue'
/* ═══════════════════════════════════════════════
   Filter State
   ═══════════════════════════════════════════════ */
const dateRange = ref('All time')
const selectedTeam = ref([])
const selectedApp = ref([])
const selectedSeverity = ref([])
const selectedStatus = ref([])
const selectedTag = ref([])
const selectedCwe = ref([])

const clients = ref([])
const applications = ref([])

/* Which dropdown is open: null | 'date' | 'client' | 'app' | 'severity' | 'status' | 'tag' | 'presets' */
const openDropdown = ref(null)
const filterPillRefs = ref({})
const dropdownPos = ref({ top: 0, left: 0 })
const DIMENSION_KEYS = ['date', 'client', 'app', 'severity', 'status']

/* Filter dimension definitions */
const dateOptions = ['Last 7 days', 'Last 30 days', 'Last 90 days', 'Last 6 months', 'Last year', 'All time']
const severityOptions = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const statusOptions = ['Open', 'Closed', 'All']

/* Translation-key lookups for filter option labels */
const dateOptionKeys = {
  'Last 7 days': 'trends.dateOptions.last7',
  'Last 30 days': 'trends.dateOptions.last30',
  'Last 90 days': 'trends.dateOptions.last90',
  'Last 6 months': 'trends.dateOptions.last6mo',
  'Last year': 'trends.dateOptions.lastYear',
  'All time': 'trends.dateOptions.allTime',
}
const severityOptionKeys = {
  'Critical': 'trends.severityOptions.critical',
  'High': 'trends.severityOptions.high',
  'Medium': 'trends.severityOptions.medium',
  'Low': 'trends.severityOptions.low',
  'Informational': 'trends.severityOptions.informational',
}
const statusOptionKeys = {
  'Open': 'trends.statusOptions.open',
  'Closed': 'trends.statusOptions.closed',
  'All': 'trends.statusOptions.all',
}
const clearFilterKeys = {
  client: 'trends.clearFilter.client',
  app: 'trends.clearFilter.app',
  severity: 'trends.clearFilter.severity',
  status: 'trends.clearFilter.status',
}

const UNASSIGNED_ID = '__unassigned__'
const clientOptions = computed(() => [UNASSIGNED_ID, ...clients.value.map((tm) => tm.name)])
const appOptions = computed(() => [UNASSIGNED_ID, ...applications.value.map((a) => a.name)])

/* Active filter pills for the bar */
const filterDimensions = computed(() => [
  { key: 'date', label: dateRange.value, value: dateRange.value, alwaysShow: true },
  { key: 'client', label: formatMultiLabel(selectedTeam.value, 'client'), value: selectedTeam.value, isMulti: true },
  { key: 'app', label: formatMultiLabel(selectedApp.value, 'app'), value: selectedApp.value, isMulti: true },
  { key: 'severity', label: formatMultiLabel(selectedSeverity.value, 'severity'), value: selectedSeverity.value, isMulti: true },
  { key: 'status', label: formatMultiLabel(selectedStatus.value, 'status'), value: selectedStatus.value, isMulti: true },
])

function formatMultiLabel(arr, key) {
  if (!arr || !arr.length) return t(`trends.filterLabels.${key}`)
  if (arr.length === 1) return t(`trends.filterLabels.${key}WithValue`, { value: arr[0] })
  return `${t(`trends.filterLabels.${key}`)} (${arr.length})`
}

/* Active filters for the details drawer chips (only filled ones) */
const activeFilters = computed(() =>
  filterDimensions.value.filter((d) =>
    d.key === 'date' ? d.value : (Array.isArray(d.value) ? d.value.length : d.value)
  )
)

function optionsFor(key) {
  switch (key) {
    case 'date': return dateOptions
    case 'client': return clientOptions.value
    case 'app': return appOptions.value
    case 'severity': return severityOptions
    case 'status': return statusOptions
    default: return []
  }
}

function formatFilterLabel(dim) {
  if (dim.key === 'date') return t(dateOptionKeys[dim.value] || dim.value)
  const vals = Array.isArray(dim.value) ? dim.value : (dim.value ? [dim.value] : [])
  const valStr = vals.join(', ')
  if (dim.key === 'client') return vals.length ? t('trends.filterLabels.clientWithValue', { value: valStr }) : t('trends.filterLabels.client')
  if (dim.key === 'app') return vals.length ? t('trends.filterLabels.appWithValue', { value: valStr }) : t('trends.filterLabels.app')
  if (dim.key === 'severity') return vals.length ? t('trends.filterLabels.severityWithValue', { value: valStr }) : t('trends.filterLabels.severity')
  if (dim.key === 'status') return vals.length ? t('trends.filterLabels.statusWithValue', { value: valStr }) : t('trends.filterLabels.status')
  return dim.label
}

function formatOptionLabel(key, opt) {
  if (key === 'date') return t(dateOptionKeys[opt] || opt)
  if (key === 'severity') return t(severityOptionKeys[opt] || opt)
  if (key === 'status') return t(statusOptionKeys[opt] || opt)
  if (opt === UNASSIGNED_ID) return t('reports.unassigned')
  return opt
}

function currentValueFor(key) {
  switch (key) {
    case 'date': return dateRange.value
    case 'client': return selectedTeam.value
    case 'app': return selectedApp.value
    case 'severity': return selectedSeverity.value
    case 'status': return selectedStatus.value
    default: return []
  }
}

function isSelected(key, opt) {
  const val = currentValueFor(key)
  return Array.isArray(val) ? val.includes(opt) : val === opt
}

function isMultiSelect(key) {
  const dim = filterDimensions.value.find(d => d.key === key)
  return dim?.isMulti ?? false
}

function setFilter(key, value) {
  if (key === 'date') {
    dateRange.value = value
    openDropdown.value = null
    return
  }
  const arr = currentValueFor(key)
  const set = new Set(Array.isArray(arr) ? arr : (arr ? [arr] : []))
  if (set.has(value)) set.delete(value)
  else set.add(value)
  const newArr = [...set]
  switch (key) {
    case 'client': selectedTeam.value = newArr; break
    case 'app': selectedApp.value = newArr; break
    case 'severity': selectedSeverity.value = newArr; break
    case 'status': selectedStatus.value = newArr; break
  }
}

function clearFilter(key) {
  switch (key) {
    case 'date': dateRange.value = 'All time'; break
    case 'client': selectedTeam.value = []; break
    case 'app': selectedApp.value = []; break
    case 'severity': selectedSeverity.value = []; break
    case 'status': selectedStatus.value = []; break
  }
}

function toggleDropdown(key) {
  openDropdown.value = openDropdown.value === key ? null : key
}

function resetFilters() {
  dateRange.value = 'All time'
  selectedTeam.value = []
  selectedApp.value = []
  selectedSeverity.value = []
  selectedStatus.value = []
  selectedTag.value = []
  selectedCwe.value = []
  openDropdown.value = null
}

/* Close dropdowns on outside click */
function onDocClick(e) {
  if (!e.target.closest('.filter-pill-wrap') && !e.target.closest('.preset-wrap') && !e.target.closest('.filter-dropdown') && !e.target.closest('.save-prompt')) {
    openDropdown.value = null
  }
}

/* ═══════════════════════════════════════════════
   Saved filter presets (per-user, per-org, stored in DB)
   ═══════════════════════════════════════════════ */
const savedPresets = ref([])
const showSavePrompt = ref(false)
const savePresetName = ref('')
const saveInput = ref(null)
const presetsLoading = ref(false)

async function fetchPresets() {
  presetsLoading.value = true
  try {
    const data = await request('/api/admin/trends-presets')
    savedPresets.value = Array.isArray(data) ? data : []
  } catch {
    savedPresets.value = []
  } finally {
    presetsLoading.value = false
  }
}

function openSavePrompt() {
  savePresetName.value = ''
  showSavePrompt.value = true
  openDropdown.value = null
  nextTick(() => saveInput.value?.focus())
}

async function confirmSave() {
  const name = savePresetName.value.trim()
  if (!name) return
  const filters = {
    dateRange: dateRange.value,
    client: selectedTeam.value,
    app: selectedApp.value,
    severity: selectedSeverity.value,
    status: selectedStatus.value,
    tag: selectedTag.value,
    cwe: selectedCwe.value,
  }
  try {
    const created = await request('/api/admin/trends-presets', {
      method: 'POST',
      body: JSON.stringify({ name, filters }),
    })
    const idx = savedPresets.value.findIndex((p) => p.name === name)
    const item = { id: created.id, name: created.name, filters: created.filters || {} }
    if (idx >= 0) {
      savedPresets.value.splice(idx, 1, item)
    } else {
      savedPresets.value.push(item)
    }
    showSavePrompt.value = false
  } catch {
    // keep prompt open; user can retry
  }
}

function cancelSave() {
  showSavePrompt.value = false
}

function loadPreset(preset) {
  const f = preset.filters || {}
  dateRange.value = f.dateRange || 'All time'
  selectedTeam.value = Array.isArray(f.client) ? f.client : (f.client ? [f.client] : [])
  selectedApp.value = Array.isArray(f.app) ? f.app : (f.app ? [f.app] : [])
  selectedSeverity.value = Array.isArray(f.severity) ? f.severity : (f.severity ? [f.severity] : [])
  selectedStatus.value = Array.isArray(f.status) ? f.status : (f.status ? [f.status] : [])
  selectedTag.value = Array.isArray(f.tag) ? f.tag : (f.tag ? [f.tag] : [])
  selectedCwe.value = Array.isArray(f.cwe) ? f.cwe : (f.cwe ? [f.cwe] : [])
  openDropdown.value = null
}

async function deletePreset(preset) {
  const ok = await showConfirm({ message: t('trends.deletePresetConfirm', { name: preset.name }) })
  if (!ok) return
  try {
    await request(`/api/admin/trends-presets/${preset.id}`, { method: 'DELETE' })
    savedPresets.value = savedPresets.value.filter((p) => p.id !== preset.id)
  } catch {
    await fetchPresets()
  }
}

/* ═══════════════════════════════════════════════
   Click-to-filter from page elements
   ═══════════════════════════════════════════════ */
function onHeatmapCellClick({ row, col }) {
  const fullTeam = clients.value.find((tm) => tm.name.includes(row))
  const clientName = fullTeam ? fullTeam.name : row
  const sevMap = { Critical: 'Critical', High: 'High', Med: 'Medium', Low: 'Low' }
  const sev = sevMap[col] || col
  const t = new Set(selectedTeam.value || [])
  const s = new Set(selectedSeverity.value || [])
  t.add(clientName)
  s.add(sev)
  selectedTeam.value = [...t]
  selectedSeverity.value = [...s]
}

function onRemediationTeamClick(clientName) {
  const name = clientName.replace(/^Team\s+/, '')
  const fullTeam = clients.value.find((tm) => tm.name.includes(name))
  const v = fullTeam ? fullTeam.name : clientName
  const t = new Set(selectedTeam.value || [])
  t.add(v)
  selectedTeam.value = [...t]
}

function onTagChipClick(tagName) {
  const arr = selectedTag.value || []
  if (arr.includes(tagName)) {
    selectedTag.value = arr.filter((x) => x !== tagName)
  } else {
    selectedTag.value = [...arr, tagName]
  }
}

function onCweChipClick(cweId) {
  const arr = selectedCwe.value || []
  if (arr.includes(cweId)) {
    selectedCwe.value = arr.filter((x) => x !== cweId)
  } else {
    selectedCwe.value = [...arr, cweId]
  }
}

/* ── Chart drill-down handlers ── */
function onAreaDrill({ severity }) {
  if (severity) {
    const s = new Set(selectedSeverity.value || [])
    s.add(severity)
    selectedSeverity.value = [...s]
    mobileDrawerOpen.value = true
    nextTick(() => {
      const el = document.querySelector('.details-drawer')
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    })
  }
}

function onAgingDrill() {
  mobileDrawerOpen.value = true
  nextTick(() => {
    const el = document.querySelector('.details-drawer')
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  })
}

/* Navigate to the actual finding in its report, scrolling to that finding */
function goToFinding(finding) {
  if (finding.report_id) {
    mobileDrawerOpen.value = false
    router.push({
      path: `/dashboard/reports/${finding.report_id}/findings`,
      query: finding.finding_id ? { finding: finding.finding_id } : {},
    })
  }
}

/* ═══════════════════════════════════════════════
   Chart / KPI data (populated from API)
   ═══════════════════════════════════════════════ */
const loading = ref(false)

const kpi = ref({ open: 0, criticalHigh: 0, oldestOpen: 0, medianFix: 0, openedVsClosed: 0 })

const areaXData = ref([])
const _rawAreaSeries = ref([])
const areaSeries = computed(() =>
  _rawAreaSeries.value.map((s) => ({
    ...s,
    color: sevColors.value[s.name] || '#888888',
  }))
)

const agingXData = ref([])
const agingYData = ref([])
const agingColors = ref(['#5eead4', '#2dd4bf', '#0d9488', '#0f766e', '#0f766e', '#0f766e'])

const heatmapRows = ref([])
const heatmapCols = ref(['Critical', 'High', 'Med', 'Low'])
const heatmapColColors = computed(() =>
  heatmapCols.value.map((c) => sevColors.value[c === 'Med' ? 'Medium' : c] || '#888888')
)
const heatmapData = ref([])

const remediationTab = ref('quickest')
const remediationQuickest = ref([])
const remediationOldest = ref([])
const remediationList = computed(() =>
  remediationTab.value === 'quickest' ? remediationQuickest.value : remediationOldest.value
)

const lineXData = ref([])
const lineSeries = ref([])

const tagChipData = ref([])
const cweChipData = ref([])

const showAllTagsExpanded = ref(false)
const showAllCweExpanded = ref(false)
const mobileDrawerOpen = ref(false)
const detailFindings = ref([])

/* Fetch trends data from the real API */
let fetchDebounce = null
async function fetchTrends() {
  loading.value = true
  try {
    const params = new URLSearchParams()
    const clientIds = (selectedTeam.value || []).filter((v) => v === UNASSIGNED_ID).length ? [UNASSIGNED_ID] : []
    const appIds = (selectedApp.value || []).filter((v) => v === UNASSIGNED_ID).length ? [UNASSIGNED_ID] : []
    for (const name of (selectedTeam.value || [])) {
      if (name === UNASSIGNED_ID) params.append('client_id', UNASSIGNED_ID)
      else {
        const id = clients.value.find((tm) => tm.name === name)?.id
        if (id) params.append('client_id', id)
      }
    }
    for (const name of (selectedApp.value || [])) {
      if (name === UNASSIGNED_ID) params.append('application_id', UNASSIGNED_ID)
      else {
        const id = applications.value.find((a) => a.name === name)?.id
        if (id) params.append('application_id', id)
      }
    }
    for (const s of (selectedSeverity.value || [])) params.append('severity', s)
    for (const s of (selectedStatus.value || [])) { if (s && s !== 'All') params.append('status', s) }
    for (const t of (selectedTag.value || [])) params.append('tag', t)
    for (const c of (selectedCwe.value || [])) params.append('cwe', c)
    // Map date range to days for the API
    const dateMap = { 'Last 7 days': 7, 'Last 30 days': 30, 'Last 90 days': 90, 'Last 6 months': 180, 'Last year': 365 }
    const days = dateMap[dateRange.value]
    if (days) params.append('days', days)

    const data = await request(`/api/admin/trends?${params}`)
    if (!data) return

    // KPI
    kpi.value = data.kpi || kpi.value

    // Stacked area — strip color from series (applied via CSS vars in areaSeries computed)
    areaXData.value = data.areaXData || []
    _rawAreaSeries.value = (data.areaSeries || []).map((s) => ({ name: s.name, data: s.data }))

    // Aging
    agingXData.value = data.agingXData || []
    agingYData.value = data.agingYData || []
    if (data.agingColors) agingColors.value = data.agingColors

    // Heatmap — column colors now derived from CSS vars via heatmapColColors computed
    heatmapRows.value = data.heatmapRows || []
    heatmapCols.value = data.heatmapCols || heatmapCols.value
    heatmapData.value = data.heatmapData || []

    // Remediation
    remediationQuickest.value = data.remediationQuickest || []
    remediationOldest.value = data.remediationOldest || []

    // Line
    lineXData.value = data.lineXData || []
    lineSeries.value = [
      { name: 'Opened', color: '#0d9488', data: data.lineOpened || [] },
      { name: 'Closed', color: '#ddebff', data: data.lineClosed || [] },
    ]

    // Tags
    tagChipData.value = data.tagCounts || []

    // CWE distribution
    cweChipData.value = data.cweCounts || []

    // Detail findings
    detailFindings.value = data.detailFindings || []
  } catch {
    // silently keep current data
  } finally {
    loading.value = false
  }
}

function debouncedFetchTrends() {
  clearTimeout(fetchDebounce)
  fetchDebounce = setTimeout(fetchTrends, 150)
}

function severityClass(sev) {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return 'sev-critical'
  if (s === 'high') return 'sev-high'
  if (s === 'medium' || s === 'med') return 'sev-medium'
  if (s === 'low') return 'sev-low'
  return 'sev-info'
}

function agePillClass(age) {
  const d = parseInt(age)
  if (d <= 7) return 'age-new'
  if (d <= 30) return 'age-mid'
  return 'age-old'
}

/* ═══════════════════════════════════════════════
   Init + reactive re-fetch
   ═══════════════════════════════════════════════ */
onMounted(async () => {
  fetchPresets()
  document.addEventListener('click', onDocClick, true)

  try {
    const [clientsData, appsData] = await Promise.all([
      request('/api/admin/clients?include_inactive=true'),
      request('/api/admin/applications'),
    ])
    clients.value = clientsData || []
    applications.value = appsData || []

    // Start with all data visible; user narrows via filter pills
    // (don't pre-select client/app/severity so charts show the full picture)
  } catch {
    // continue with empty state
  }

  // Initial data load
  await fetchTrends()
})

const DROPDOWN_MAX_HEIGHT = 280

watch(openDropdown, (key) => {
  if (key && DIMENSION_KEYS.includes(key)) {
    nextTick(() => {
      const el = filterPillRefs.value[key]
      if (el) {
        const rect = el.getBoundingClientRect()
        const padding = 12
        let top = rect.bottom + 8
        let left = rect.left
        // Keep dropdown inside viewport (avoid clipping at bottom/right)
        if (top + DROPDOWN_MAX_HEIGHT > window.innerHeight - padding) {
          top = Math.max(padding, window.innerHeight - DROPDOWN_MAX_HEIGHT - padding)
        }
        const dropdownMinWidth = 220
        if (left + dropdownMinWidth > window.innerWidth - padding) {
          left = window.innerWidth - dropdownMinWidth - padding
        }
        if (left < padding) left = padding
        dropdownPos.value = { top, left }
      }
    })
  }
})

// Re-fetch trends whenever any filter changes
watch(
  [dateRange, selectedTeam, selectedApp, selectedSeverity, selectedStatus, selectedTag, selectedCwe],
  () => { debouncedFetchTrends() },
)

onUnmounted(() => {
  document.removeEventListener('click', onDocClick, true)
  clearTimeout(fetchDebounce)
})
</script>

<template>
  <div class="trends-page">
    <!-- Header -->
    <div class="trends-header">
      <span class="kicker">{{ $t('trends.kicker') }}</span>
      <h1 class="trends-title">{{ $t('trends.title') }}</h1>
      <p class="trends-subtitle">
        {{ $t('trends.subtitle') }}
      </p>
    </div>

    <!-- Outer wrapper: content + details drawer -->
    <div class="trends-body">
      <div class="trends-content">
        <!-- ── Filter bar ── -->
        <div class="filter-bar card">
          <div class="filter-bar-row">
            <span class="filter-label">{{ $t('trends.filters') }}</span>

            <!-- Saved presets dropdown -->
            <div v-if="savedPresets.length" class="preset-wrap">
            <button
              class="preset-trigger"
              @click.stop="toggleDropdown('presets')"
              :aria-expanded="openDropdown === 'presets'"
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2z"/></svg>
              {{ $t('trends.saved') }}
              <svg class="dd-chevron" :class="{ open: openDropdown === 'presets' }" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
            </button>
            <Transition name="dd">
              <div v-if="openDropdown === 'presets'" class="filter-dropdown preset-dropdown">
                <div
                  v-for="p in savedPresets"
                  :key="p.id || p.name"
                  class="dd-option preset-option"
                >
                  <span class="preset-name" @click="loadPreset(p)">{{ p.name }}</span>
                  <button class="preset-delete" @click.stop="deletePreset(p)" :aria-label="$t('trends.deletePresetAriaLabel')">&times;</button>
                </div>
              </div>
            </Transition>
          </div>

          <!-- Filter pills -->
          <div class="filter-pills">
            <div
              v-for="dim in filterDimensions"
              :key="dim.key"
              :ref="(el) => { if (el) filterPillRefs[dim.key] = el }"
              class="filter-pill-wrap"
            >
              <button
                :class="['filter-pill', !(Array.isArray(dim.value) ? dim.value?.length : dim.value) && 'filter-pill-empty']"
                @click.stop="toggleDropdown(dim.key)"
                :aria-expanded="openDropdown === dim.key"
                :title="formatFilterLabel(dim)"
              >
                <span class="filter-pill-label">{{ formatFilterLabel(dim) }}</span>
                <svg class="dd-chevron" :class="{ open: openDropdown === dim.key }" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
              </button>
              <!-- Clear "x" on filled pills (except date). Always rendered to prevent layout jump. -->
              <button
                v-if="dim.key !== 'date'"
                :class="['filter-pill-clear', !(Array.isArray(dim.value) ? dim.value.length : dim.value) && 'filter-pill-clear-hidden']"
                @click.stop="clearFilter(dim.key)"
                :aria-label="$t(clearFilterKeys[dim.key])"
                :tabindex="(Array.isArray(dim.value) ? dim.value.length : dim.value) ? 0 : -1"
              >&times;</button>
            </div>
          </div>

            <div class="filter-actions">
              <button class="ghost filter-btn-reset" @click="resetFilters">{{ $t('common.reset') }}</button>
              <button class="filter-btn-save" @click="openSavePrompt">{{ $t('common.save') }}</button>
            </div>
          </div>
        </div>

        <!-- Filter dropdowns: Teleport to body so they aren't clipped by overflow -->
        <Teleport to="body">
          <Transition name="dd">
            <div
              v-if="openDropdown && DIMENSION_KEYS.includes(openDropdown)"
              class="filter-dropdown filter-dropdown-teleport"
              :style="{ top: `${dropdownPos.top}px`, left: `${dropdownPos.left}px` }"
            >
              <div
                v-for="opt in optionsFor(openDropdown)"
                  :key="opt"
                  :class="['dd-option', isMultiSelect(openDropdown) && 'dd-option-multi', isSelected(openDropdown, opt) && 'dd-option-active']"
                  @click="setFilter(openDropdown, opt)"
                >
                  <span v-if="isMultiSelect(openDropdown)" class="dd-checkbox" :class="{ 'dd-checkbox-checked': isSelected(openDropdown, opt) }">
                    <svg v-if="isSelected(openDropdown, opt)" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                  </span>
                  <span v-else class="dd-radio" :class="{ 'dd-radio-checked': isSelected(openDropdown, opt) }"></span>
                  {{ formatOptionLabel(openDropdown, opt) }}
                </div>
              <div v-if="!optionsFor(openDropdown).length" class="dd-empty">{{ $t('trends.noOptionsAvailable') }}</div>
            </div>
          </Transition>
        </Teleport>

        <!-- Save prompt (inline overlay) -->
        <Transition name="fade">
          <div v-if="showSavePrompt" class="save-prompt-backdrop" @click.self="cancelSave">
            <div class="save-prompt card">
              <h2 class="save-prompt-heading">{{ $t('trends.saveCurrentFilter') }}</h2>
              <p class="save-prompt-hint">{{ $t('trends.savePresetHint') }}</p>
              <input
                ref="saveInput"
                v-model="savePresetName"
                :placeholder="$t('trends.savePresetPlaceholder')"
                class="save-prompt-input"
                @keydown.enter="confirmSave"
                @keydown.escape="cancelSave"
              />
              <div class="save-prompt-actions">
                <button class="ghost" @click="cancelSave">{{ $t('common.cancel') }}</button>
                <button :disabled="!savePresetName.trim()" @click="confirmSave">{{ $t('common.save') }}</button>
              </div>
            </div>
          </div>
        </Transition>

        <!-- ── KPI row ── -->
        <div class="kpi-row">
          <div class="kpi-card card">
            <div class="kpi-label">{{ $t('trends.kpi.open') }}</div>
            <div class="kpi-value kpi-default">{{ kpi.open }}</div>
          </div>
          <div class="kpi-card card">
            <div class="kpi-label">{{ $t('trends.kpi.criticalHigh') }}</div>
            <div class="kpi-value kpi-danger">{{ kpi.criticalHigh }}</div>
          </div>
          <div class="kpi-card card">
            <div class="kpi-label">{{ $t('trends.kpi.oldestOpen') }}</div>
            <div class="kpi-value kpi-warn">{{ kpi.oldestOpen }}d</div>
          </div>
          <div class="kpi-card card">
            <div class="kpi-label">{{ $t('trends.kpi.medianFix') }}</div>
            <div class="kpi-value kpi-success">{{ kpi.medianFix }}d</div>
          </div>
          <div class="kpi-card card" :title="$t('trends.kpi.openedVsClosedHint')">
            <div class="kpi-label">{{ $t('trends.kpi.openedVsClosed') }}</div>
            <div class="kpi-value" :class="kpi.openedVsClosed < 0 ? 'kpi-success' : 'kpi-danger'">
              {{ kpi.openedVsClosed }}
            </div>
            <div class="kpi-hint">{{ $t('trends.kpi.openedVsClosedHint') }}</div>
          </div>
        </div>

        <!-- ── Main grid ── -->
        <h2 class="visually-hidden">{{ $t('trends.charts.sectionHeading') }}</h2>
        <div class="trends-grid">
          <!-- Row 1 -->
          <div class="chart-card card">
            <div class="chart-card-header">
              <h3>{{ $t('trends.charts.openFindingsOverTime') }}</h3>
              <p class="chart-card-sub">{{ $t('trends.charts.stackedBySeverity') }}</p>
            </div>
            <div class="chart-body chart-body-lg">
              <StackedArea :x-data="areaXData" :series="areaSeries" @drill="onAreaDrill" />
            </div>
          </div>

          <div class="chart-card card">
            <div class="chart-card-header">
              <h3>{{ $t('trends.charts.agingDistribution') }}</h3>
              <p class="chart-card-sub">{{ $t('trends.charts.agingSubtitle') }}</p>
            </div>
            <div class="chart-body chart-body-lg">
              <HistogramBar
                :x-data="agingXData"
                :y-data="agingYData"
                :bar-colors="agingColors"
                @drill="onAgingDrill"
              />
            </div>
          </div>

          <!-- Row 2 -->
          <div class="chart-card card">
            <div class="chart-card-header">
              <h3>{{ $t('trends.charts.heatmapTitle') }}</h3>
              <p class="chart-card-sub">
                {{ (selectedTeam?.length || selectedSeverity?.length) ? $t('trends.charts.heatmapFilteredHint') : $t('trends.charts.heatmapSubtitle') }}
              </p>
            </div>
            <div class="chart-body-heatmap">
              <HeatmapGrid
                :rows="heatmapRows"
                :row-label-formatter="(r) => r === UNASSIGNED_ID ? t('reports.unassigned') : r"
                :columns="heatmapCols"
                :data="heatmapData"
                :column-colors="heatmapColColors"
                :filter-active="!!(selectedTeam?.length || selectedSeverity?.length)"
                @cell-click="onHeatmapCellClick"
              />
            </div>
          </div>

          <div class="chart-card card">
            <div class="chart-card-header">
              <h3>{{ $t('trends.charts.remediationPerformance') }}</h3>
              <p class="chart-card-sub">{{ $t('trends.charts.remediationSubtitle') }}</p>
            </div>
            <div class="remediation-body">
              <div class="remediation-tabs">
                <button
                  :class="['rem-tab', remediationTab === 'quickest' && 'rem-tab-active']"
                  @click="remediationTab = 'quickest'"
                >{{ $t('trends.charts.quickest') }}</button>
                <button
                  :class="['rem-tab', remediationTab === 'oldest' && 'rem-tab-active']"
                  @click="remediationTab = 'oldest'"
                >{{ $t('trends.charts.oldest') }}</button>
              </div>
              <ul class="remediation-list">
                <li
                  v-for="(item, i) in remediationList"
                  :key="i"
                  class="remediation-item remediation-item-clickable"
                  @click="onRemediationTeamClick(item.client)"
                  :title="$t('trends.charts.filterByTeam', { client: item.client === UNASSIGNED_ID ? $t('reports.unassigned') : item.client })"
                >
                  <span class="remediation-rank">{{ i + 1 }}.</span>
                  <span class="remediation-client">{{ item.client === UNASSIGNED_ID ? $t('reports.unassigned') : item.client }}</span>
                  <span class="remediation-value">{{ item.value }}</span>
                </li>
              </ul>
            </div>
          </div>

          <!-- Row 3 -->
          <div class="chart-card card">
            <div class="chart-card-header">
              <h3>{{ $t('trends.charts.openedVsClosed') }}</h3>
              <p class="chart-card-sub">{{ $t('trends.charts.openedVsClosedSubtitle') }}</p>
            </div>
            <div class="chart-body chart-body-lg">
              <SimpleLine :x-data="lineXData" :series="lineSeries" />
            </div>
          </div>

          <div class="chart-card card">
            <div class="chart-card-header">
              <h3>{{ $t('trends.charts.tagsTitle') }}</h3>
              <p class="chart-card-sub">{{ $t('trends.charts.tagsSubtitle') }}</p>
            </div>
            <div class="tags-body">
              <div v-if="tagChipData.length" class="tag-chips">
                <span
                  v-for="tc in (showAllTagsExpanded ? tagChipData : tagChipData.slice(0, 8))"
                  :key="tc.name"
                  :class="['tag-chip', 'tag-chip-clickable', (selectedTag || []).includes(tc.name) && 'tag-chip-active']"
                  @click="onTagChipClick(tc.name)"
                  :title="$t('trends.charts.tagChipTitle', { name: tc.name, count: tc.count })"
                >
                  {{ tc.name }}
                  <span class="tag-chip-count">{{ tc.count }}</span>
                </span>
              </div>
              <div v-if="tagChipData.length > 8" class="tags-footer">
                <button class="tags-show-more" @click="showAllTagsExpanded = !showAllTagsExpanded">
                  {{ showAllTagsExpanded ? $t('trends.charts.showFewerTags') : $t('trends.charts.showAllTags', { count: tagChipData.length }) }}
                </button>
              </div>
              <p v-if="!tagChipData.length" class="tags-empty">{{ $t('trends.charts.noTagsYet') }}</p>
            </div>
          </div>

          <!-- Row 4: CWE Distribution (full width) -->
          <div class="chart-card card cwe-card">
            <div class="chart-card-header">
              <h3>{{ $t('trends.charts.cweTitle') }}</h3>
              <p class="chart-card-sub">{{ $t('trends.charts.cweSubtitle') }}</p>
            </div>
            <div class="cwe-body">
              <div v-if="cweChipData.length" class="cwe-chips">
                <span
                  v-for="cwe in (showAllCweExpanded ? cweChipData : cweChipData.slice(0, 12))"
                  :key="cwe.id"
                  :class="['cwe-chip', 'cwe-chip-clickable', (selectedCwe || []).includes(cwe.id) && 'cwe-chip-active']"
                  @click="onCweChipClick(cwe.id)"
                  :title="$t('trends.charts.cweChipTitle', { id: cwe.id, count: cwe.count })"
                  role="button"
                  tabindex="0"
                  :aria-pressed="(selectedCwe || []).includes(cwe.id)"
                  @keydown.enter.space.prevent="onCweChipClick(cwe.id)"
                >
                  <span class="cwe-chip-id">{{ cwe.id }}</span>
                  <span class="cwe-chip-count">{{ cwe.count }}</span>
                </span>
              </div>
              <div v-if="cweChipData.length > 12" class="cwe-footer">
                <button class="cwe-show-more" @click="showAllCweExpanded = !showAllCweExpanded">
                  {{ showAllCweExpanded ? $t('trends.charts.showFewerCwe') : $t('trends.charts.showAllCwe', { count: cweChipData.length }) }}
                </button>
              </div>
              <p v-if="!cweChipData.length" class="cwe-empty">{{ $t('trends.charts.noCweYet') }}</p>
            </div>
          </div>
        </div>
      </div>

      <!-- ── Details drawer (desktop: sidebar, mobile: bottom sheet) ── -->
      <aside :class="['details-drawer', mobileDrawerOpen && 'details-drawer-mobile-open']">
        <div class="details-header">
          <h3>{{ $t('trends.details.title') }}</h3>
          <button class="ghost details-close" @click="mobileDrawerOpen = false" :aria-label="$t('trends.details.closeDetails')">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <div class="details-context-chips">
          <span v-for="f in activeFilters" :key="'d-' + f.key" class="details-context-chip">{{ formatFilterLabel(f) }}</span>
        </div>
        <div class="details-count" v-if="detailFindings.length">
          {{ $t('trends.details.showingFindings', { shown: detailFindings.length, total: kpi.open }) }}
        </div>
        <ul class="details-list">
          <li
            v-for="(f, i) in detailFindings"
            :key="i"
            class="details-finding details-finding-link"
            @click="goToFinding(f)"
            :title="$t('trends.details.openInReport')"
          >
            <div class="details-finding-title">
              {{ f.title }}
              <svg class="goto-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M7 17L17 7M17 7H7M17 7v10"/>
              </svg>
            </div>
            <div class="details-finding-meta">
              <span
                :class="['detail-pill', 'detail-pill-clickable', severityClass(f.severity)]"
                @click.stop="setFilter('severity', f.severity)"
                :title="$t('trends.charts.filterBy', { value: f.severity })"
              >{{ f.severity }}</span>
              <span :class="['detail-pill', agePillClass(f.age)]">{{ f.age }}</span>
            </div>
          </li>
        </ul>
        <div v-if="!detailFindings.length" class="details-empty">
          {{ $t('trends.details.noMatch') }}
        </div>
      </aside>

      <!-- Mobile backdrop for bottom sheet -->
      <Transition name="fade">
        <div v-if="mobileDrawerOpen" class="mobile-drawer-backdrop" @click="mobileDrawerOpen = false"></div>
      </Transition>
    </div>

    <!-- Mobile FAB to open details -->
    <button
      v-if="!mobileDrawerOpen && detailFindings.length"
      class="mobile-details-fab"
      @click="mobileDrawerOpen = true"
      :aria-label="$t('trends.details.showFindings', { count: detailFindings.length })"
    >
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
      </svg>
      <span class="fab-label">{{ $t('trends.details.fabLabel') }}</span>
      <span class="fab-badge">{{ detailFindings.length }}</span>
    </button>
  </div>
</template>

<style scoped>
/* ─── Transitions ─── */
.dd-enter-from, .dd-leave-to { opacity: 0; transform: translateY(-4px); }
.dd-enter-to, .dd-leave-from { opacity: 1; transform: translateY(0); }
.dd-enter-active, .dd-leave-active { transition: opacity 0.15s, transform 0.15s; }

.fade-enter-from, .fade-leave-to { opacity: 0; }
.fade-enter-to, .fade-leave-from { opacity: 1; }
.fade-enter-active, .fade-leave-active { transition: opacity 0.15s; }

/* ─── Page layout ─── */
.trends-page {
  display: flex;
  flex-direction: column;
  min-height: 0;
  /* Break out of .main's max-width so the grid + drawer have room */
  max-width: none;
  width: calc(100% + 16px);  /* reclaim a bit of parent padding */
  margin-left: -8px;
  margin-right: -8px;
}

.trends-header {
  margin-bottom: 20px;
  max-width: 960px;
}

.trends-title {
  margin: 0 0 4px;
  font-size: 36px;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.trends-subtitle {
  margin: 0;
  font-size: 15px;
  color: var(--text-muted);
  max-width: 52ch;
  line-height: 1.5;
}

/* ─── Body: content + drawer ─── */
.trends-body {
  display: flex;
  gap: 0;
  align-items: flex-start;
}

.trends-content {
  flex: 1;
  min-width: 0;
}

/* ─── Shared card lift for contrast ─── */
.trends-page :deep(.card),
.trends-page .card {
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.25), 0 0 0 1px rgba(255, 255, 255, 0.03) inset;
}

/* ═══════════════════════════════════════════════
   Filter bar
   ═══════════════════════════════════════════════ */
.filter-bar {
  padding: 16px 20px;
  margin-bottom: 16px;
  max-width: 960px;
}

.filter-bar-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.filter-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-faint);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  flex-shrink: 0;
  line-height: 36px;
}

/* Saved presets */
.preset-wrap {
  position: relative;
  flex-shrink: 0;
}

.preset-trigger {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 36px;
  padding: 0 14px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  background: var(--bg-input);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}

.preset-trigger:hover {
  background: var(--bg-hover-solid);
  color: var(--text-primary);
}

/* Filter pills - fixed-width slots so selection length never causes layout shift. */
.filter-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  flex: 1;
  min-width: 200px;
  padding: 2px 0;
}

.filter-pill-wrap {
  display: flex;
  align-items: center;
  gap: 4px;
  width: 160px;
  min-width: 160px;
  flex-shrink: 0;
}

.filter-pill {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 1;
  min-width: 0;
  height: 36px;
  padding: 0 10px 0 12px;
  border-radius: 8px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
  min-height: unset;
  transition: background 0.15s, box-shadow 0.15s;
  text-align: left;
}

.filter-pill-label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}

.filter-pill:hover {
  background: var(--bg-hover-solid);
  color: var(--text-primary);
}

.filter-pill[aria-expanded="true"] {
  background: var(--primary-bg);
  border-color: var(--primary);
  color: var(--primary);
}

.filter-pill-empty {
  color: var(--text-faint);
}

.filter-pill-empty:hover {
  color: var(--text-secondary);
}

.dd-chevron {
  transition: transform 0.2s;
  opacity: 0.6;
  flex-shrink: 0;
}

.dd-chevron.open {
  transform: rotate(180deg);
}

.filter-pill-clear {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 36px;
  padding: 0;
  border-radius: 6px;
  border: none;
  background: transparent;
  color: var(--text-faint);
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  min-height: unset;
  line-height: 1;
  transition: background 0.15s, color 0.15s;
}

.filter-pill-clear:hover {
  background: var(--danger-bg);
  color: var(--danger);
}

.filter-pill-clear-hidden {
  visibility: hidden;
  pointer-events: none;
}

.filter-dropdown {
  position: absolute;
  top: calc(100% + 8px);
  left: 0;
  width: 220px;
  min-width: 220px;
  max-width: 220px;
  max-height: 280px;
  overflow-y: auto;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 6px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
  z-index: 200;
}

.filter-dropdown-teleport {
  position: fixed;
  z-index: 500;
}

.filter-dropdown-tag {
  overflow: visible;
  min-width: 220px;
  max-height: none;
}

.tag-picker-in-dropdown {
  min-width: 100%;
}

.dd-option {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 12px;
  font-size: 13px;
  color: var(--text-secondary);
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.1s;
}

.dd-option:hover {
  background: var(--bg-hover-solid);
  color: var(--text-primary);
}

.dd-option-active {
  color: var(--primary);
  font-weight: 600;
}

.dd-option-multi {
  justify-content: flex-start;
  gap: 10px;
}

.dd-checkbox {
  flex-shrink: 0;
  width: 18px;
  height: 18px;
  border: 2px solid var(--border);
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.15s, border-color 0.15s;
}

.dd-checkbox-checked {
  background: var(--primary);
  border-color: var(--primary);
  color: #fff;
}

.dd-radio {
  flex-shrink: 0;
  width: 16px;
  height: 16px;
  border: 2px solid var(--border);
  border-radius: 50%;
  position: relative;
  transition: border-color 0.15s;
}

.dd-radio-checked {
  border-color: var(--primary);
}

.dd-radio-checked::after {
  content: '';
  position: absolute;
  top: 3px;
  left: 3px;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--primary);
}

.dd-check {
  flex-shrink: 0;
  color: var(--primary);
}

.dd-empty {
  padding: 12px;
  font-size: 12px;
  color: var(--text-faint);
  text-align: center;
}

/* Preset-specific dropdown styles */
.preset-dropdown {
  min-width: 200px;
}

.preset-option {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.preset-name {
  flex: 1;
  cursor: pointer;
}

.preset-delete {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  padding: 0;
  border: none;
  border-radius: 4px;
  background: transparent;
  color: var(--text-faint);
  font-size: 15px;
  cursor: pointer;
  min-height: unset;
  transition: background 0.15s, color 0.15s;
}

.preset-delete:hover {
  background: var(--danger-bg);
  color: var(--danger);
  transform: none;
  box-shadow: none;
}

/* Filter actions */
.filter-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-left: auto;
  flex-shrink: 0;
}

.filter-btn-reset,
.filter-btn-save {
  height: 36px;
  padding: 0 16px;
  font-size: 13px;
  font-weight: 500;
  border-radius: 8px;
  min-height: unset;
}

.filter-btn-reset {
  border: 1px solid var(--border);
  color: var(--text-secondary);
  background: transparent;
}

.filter-btn-reset:hover {
  background: var(--bg-hover-solid);
  color: var(--text-primary);
  transform: none;
  box-shadow: none;
}

.filter-btn-save {
  padding: 0 18px;
}

/* ═══════════════════════════════════════════════
   Save prompt
   ═══════════════════════════════════════════════ */
.save-prompt-backdrop {
  position: fixed;
  inset: 0;
  background: var(--bg-modal-overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 500;
}

.save-prompt {
  width: 100%;
  max-width: 400px;
  padding: 24px;
}

.save-prompt-heading {
  margin: 0 0 4px;
  font-size: 16px;
  font-weight: 700;
}

.save-prompt-hint {
  margin: 0 0 14px;
  font-size: 13px;
  color: var(--text-muted);
  line-height: 1.4;
}

.save-prompt-input {
  width: 100%;
  margin-bottom: 14px;
}

.save-prompt-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

/* ─── KPI row ─── */
.kpi-row {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  margin-bottom: 16px;
  max-width: 960px;
}

.kpi-card {
  padding: 16px 18px;
}

.kpi-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: 6px;
  letter-spacing: 0.01em;
}

.kpi-value {
  font-size: 32px;
  font-weight: 700;
  font-family: 'IBM Plex Mono', monospace;
  letter-spacing: -0.02em;
  line-height: 1;
}

.kpi-default { color: var(--text-primary); }
.kpi-danger  { color: #ef4444; }
.kpi-warn    { color: #f59e0b; }
.kpi-success { color: #10b981; }

.kpi-hint {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 6px;
  line-height: 1.3;
}

/* ─── Main grid ─── */
.trends-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.chart-card {
  padding: 20px;
  display: flex;
  flex-direction: column;
}

.chart-card-header h3 {
  margin: 0 0 2px;
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.chart-card-sub {
  margin: 0 0 14px;
  font-size: 12px;
  color: var(--text-muted);
}

.chart-body {
  flex: 1;
  min-height: 0;
}

.chart-body-lg {
  flex: 0 0 280px;   /* fixed height; don't grow/shrink */
  min-height: 280px; /* belt-and-suspenders for grid contexts */
}

.chart-body-heatmap {
  flex: 1;
  padding-top: 4px;
}

/* ─── Remediation ─── */
.remediation-body {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.remediation-tabs {
  display: flex;
  gap: 2px;
  margin-bottom: 14px;
  background: var(--bg-input);
  border-radius: 8px;
  padding: 3px;
  width: fit-content;
}

.rem-tab {
  font-size: 12px;
  font-weight: 600;
  padding: 6px 16px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  min-height: unset;
  transition: background 0.15s, color 0.15s;
}

.rem-tab:hover {
  color: var(--text-secondary);
  background: transparent;
  transform: none;
  box-shadow: none;
}

.rem-tab-active {
  background: var(--bg-card);
  color: var(--text-primary);
  box-shadow: 0 1px 3px rgba(0,0,0,0.2);
}

.rem-tab-active:hover {
  background: var(--bg-card);
  color: var(--text-primary);
}

.remediation-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.remediation-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  font-size: 14px;
  border-bottom: 1px solid var(--border);
}

.remediation-item:last-child {
  border-bottom: none;
}

.remediation-item-clickable {
  cursor: pointer;
  padding: 8px 6px;
  margin: 0 -6px;
  border-radius: 6px;
  transition: background 0.15s;
}

.remediation-item-clickable:hover {
  background: var(--bg-hover);
}

.remediation-rank {
  color: var(--text-faint);
  font-size: 12px;
  font-weight: 500;
  width: 20px;
  flex-shrink: 0;
}

.remediation-client {
  color: var(--text-secondary);
  flex: 1;
}

.remediation-value {
  color: var(--text-muted);
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px;
}

/* ─── Tags ─── */
.tags-body {
  flex: 1;
  padding-top: 4px;
  min-height: 160px;
  display: flex;
  flex-direction: column;
}

.tag-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  flex: 1;
  align-content: flex-start;
}

.tag-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 14px;
  border-radius: 999px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: default;
  transition: background 0.15s, border-color 0.15s;
}

.tag-chip-clickable {
  cursor: pointer;
}

.tag-chip:hover {
  background: var(--bg-hover-solid);
  border-color: var(--text-faint);
}

.tag-chip-count {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-faint);
  background: var(--bg-hover-solid);
  border-radius: 999px;
  padding: 1px 6px;
  min-width: 18px;
  text-align: center;
}

.tags-footer {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--border);
}

.tags-show-more {
  font-size: 12px;
  font-weight: 500;
  color: var(--primary);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  min-height: unset;
}

.tags-show-more:hover {
  text-decoration: underline;
  transform: none;
  box-shadow: none;
}

.tags-empty {
  font-size: 13px;
  color: var(--text-faint);
  margin: 16px 0 0;
}

/* ─── CWE Distribution ─── */
.cwe-card {
  grid-column: 1 / -1;
}

.cwe-body {
  padding-top: 4px;
  min-height: 80px;
  display: flex;
  flex-direction: column;
}

.cwe-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  flex: 1;
  align-content: flex-start;
}

.cwe-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 6px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: default;
  transition: background 0.15s, border-color 0.15s;
}

.cwe-chip-clickable {
  cursor: pointer;
}

.cwe-chip:hover {
  background: var(--bg-hover-solid);
  border-color: var(--text-faint);
}

.cwe-chip-active {
  background: var(--primary-bg);
  border-color: var(--primary);
  color: var(--primary);
}

.cwe-chip-id {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.02em;
}

.cwe-chip-count {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-faint);
  background: var(--bg-hover-solid);
  border-radius: 4px;
  padding: 1px 6px;
  min-width: 18px;
  text-align: center;
}

.cwe-chip-active .cwe-chip-count {
  background: var(--primary-bg);
  color: var(--primary);
}

.cwe-footer {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--border);
}

.cwe-show-more {
  font-size: 12px;
  font-weight: 500;
  color: var(--primary);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  min-height: unset;
}

.cwe-show-more:hover {
  text-decoration: underline;
  transform: none;
  box-shadow: none;
}

.cwe-empty {
  font-size: 13px;
  color: var(--text-faint);
  margin: 16px 0 0;
}

/* ─── Details drawer ─── */
.details-drawer {
  width: 280px;
  min-width: 280px;
  flex-shrink: 0;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 16px;
  margin-left: 16px;
  position: sticky;
  top: 20px;
  max-height: calc(100vh - 80px);
  overflow-y: auto;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

.details-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}

.details-header h3 {
  margin: 0;
  font-size: 18px;
  font-weight: 700;
}

.details-close {
  display: none;
  padding: 4px;
  min-height: unset;
  border-radius: 4px;
  color: var(--text-faint);
}

.details-close:hover {
  color: var(--text-primary);
  transform: none;
  box-shadow: none;
}

.details-context-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-bottom: 14px;
}

.details-context-chip {
  display: inline-flex;
  align-items: center;
  padding: 3px 9px;
  border-radius: 999px;
  background: var(--bg-input);
  border: 1px solid var(--border);
  font-size: 11px;
  font-weight: 500;
  color: var(--text-muted);
}

.details-count {
  font-size: 11px;
  color: var(--text-muted);
  margin-bottom: 10px;
  opacity: .7;
}

.details-empty {
  text-align: center;
  padding: 24px 8px;
  font-size: 13px;
  color: var(--text-muted);
  opacity: .6;
}

.details-list {
  list-style: none;
  margin: 0;
  padding: 0;
}

.details-finding {
  padding: 10px 8px;
  border-bottom: 1px solid var(--border);
  border-radius: 6px;
  margin: 0 -8px;
  cursor: pointer;
  transition: background 0.15s;
}

.details-finding:hover {
  background: var(--bg-hover);
}

.details-finding:last-child {
  border-bottom: none;
}

.details-finding-link:hover .details-finding-title {
  color: #60a5fa;
}

.details-finding-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary);
  margin-bottom: 6px;
  line-height: 1.3;
  display: flex;
  align-items: flex-start;
  gap: 4px;
  transition: color .15s;
}

.goto-icon {
  flex-shrink: 0;
  margin-top: 2px;
  opacity: 0;
  transition: opacity .15s;
}

.details-finding-link:hover .goto-icon {
  opacity: .6;
}

.details-finding-meta {
  display: flex;
  gap: 6px;
  align-items: center;
}

.detail-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}

.detail-pill-clickable {
  cursor: pointer;
  transition: filter 0.15s;
}

.detail-pill-clickable:hover {
  filter: brightness(1.3);
}

.sev-critical { background: var(--sev-critical-bg); color: var(--sev-critical-text); }
.sev-high     { background: var(--sev-high-bg);     color: var(--sev-high-text); }
.sev-medium   { background: var(--sev-medium-bg);   color: var(--sev-medium-text); }
.sev-low      { background: var(--sev-low-bg);      color: var(--sev-low-text); }
.sev-info     { background: var(--sev-info-bg);      color: var(--sev-info-text); }

.age-new { background: var(--sev-info-bg);   color: var(--sev-info-text); }
.age-mid { background: var(--sev-medium-bg); color: var(--sev-medium-text); }
.age-old { background: var(--sev-high-bg);   color: var(--sev-high-text); }

/* ─── Wide screen ─── */
@media (min-width: 1600px) {
  .trends-page {
    max-width: 1600px;
  }
  .filter-bar,
  .kpi-row {
    max-width: 1080px;
  }
}

/* ─── Mobile FAB ─── */
.mobile-details-fab {
  display: none;  /* only shown on small screens */
}

/* ─── Mobile backdrop ─── */
.mobile-drawer-backdrop {
  display: none;
}

/* ─── Responsive ─── */
@media (max-width: 1200px) {
  /* Desktop sidebar hidden, replaced by mobile bottom sheet */
  .details-drawer {
    display: none;
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    width: 100%;
    min-width: 0;
    max-height: 70vh;
    margin: 0;
    border-radius: 16px 16px 0 0;
    z-index: 1001;
    box-shadow: 0 -4px 24px rgba(0, 0, 0, 0.4);
    transform: translateY(100%);
    transition: transform 0.3s ease;
    overflow-y: auto;
    -webkit-overflow-scrolling: touch;
  }

  .details-drawer-mobile-open {
    display: block;
    transform: translateY(0);
  }

  .details-close {
    display: block;
  }

  .mobile-drawer-backdrop {
    display: block;
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 1000;
  }

  .mobile-details-fab {
    display: flex;
    align-items: center;
    gap: 8px;
    position: fixed;
    bottom: 20px;
    right: 20px;
    z-index: 999;
    background: var(--primary);
    color: #fff;
    border: none;
    border-radius: 999px;
    padding: 14px 20px;
    font-size: 14px;
    font-weight: 600;
    box-shadow: 0 4px 16px rgba(13, 148, 136, 0.4);
    cursor: pointer;
    transition: transform 0.15s, box-shadow 0.15s;
    animation: fab-entrance 0.6s ease-out;
  }

  @keyframes fab-entrance {
    0% { opacity: 0; transform: scale(0.6) translateY(20px); }
    60% { opacity: 1; transform: scale(1.05) translateY(-2px); }
    100% { transform: scale(1) translateY(0); }
  }

  .mobile-details-fab:active {
    transform: scale(0.95);
  }

  .fab-label {
    white-space: nowrap;
  }

  .fab-badge {
    background: rgba(255, 255, 255, 0.25);
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 12px;
  }
}

@media (max-width: 900px) {
  .kpi-row {
    grid-template-columns: repeat(3, 1fr);
    max-width: none;
  }
  .filter-bar {
    max-width: none;
  }
  .trends-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 600px) {
  .kpi-row {
    grid-template-columns: 1fr 1fr;
  }
  .kpi-value {
    font-size: 24px;
  }
  .trends-title {
    font-size: 28px;
  }
}
</style>
