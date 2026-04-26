<script setup>
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request, getSessionUser } from '../services/api'
import { setStatus } from '../stores/status'
import { showConfirm } from '../composables/useConfirm'
import Modal from '../components/Modal.vue'

const router = useRouter()
const { t } = useI18n()
const applications = ref([])
const newName = ref('')
const newType = ref('')
const newDescription = ref('')
const showModal = ref(false)
const editId = ref(null)
const editName = ref('')
const editType = ref('')
const editDescription = ref('')
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

function typeLabel(type) {
  const match = APP_TYPES.find((opt) => opt.value === type)
  return match ? t(match.labelKey) : type || t('applications.typeEmpty')
}

async function load() {
  applications.value = await request('/api/admin/applications?enriched=true')
}

function relativeDate(iso) {
  if (!iso) return t('applications.typeEmpty')
  const d = new Date(iso)
  const now = new Date()
  const days = Math.floor((now - d) / 86400000)
  if (days === 0) return t('applications.relativeDateToday')
  if (days === 1) return t('applications.relativeDateYesterday')
  if (days < 30) return t('applications.relativeDateDaysAgo', { days })
  if (days < 365) return t('applications.relativeDateMonthsAgo', { months: Math.floor(days / 30) })
  return d.toLocaleDateString()
}

async function addApplication() {
  if (!newName.value.trim()) return
  setStatus(t('applications.addingApplication'), 'info')
  await request('/api/admin/applications', {
    method: 'POST',
    body: JSON.stringify({
      name: newName.value,
      type: newType.value || null,
      description: newDescription.value || '',
    }),
  })
  newName.value = ''
  newType.value = ''
  newDescription.value = ''
  await load()
  setStatus(t('applications.applicationAdded'), 'success')
}

function openEdit(app) {
  editId.value = app.id
  editName.value = app.name
  editType.value = app.type || ''
  editDescription.value = app.description || ''
  showModal.value = true
}

async function saveEdit() {
  setStatus(t('applications.savingApplication'), 'info')
  await request(`/api/admin/applications/${editId.value}`, {
    method: 'PUT',
    body: JSON.stringify({
      name: editName.value,
      type: editType.value || null,
      description: editDescription.value || '',
    }),
  })
  showModal.value = false
  editId.value = null
  editName.value = ''
  editType.value = ''
  editDescription.value = ''
  await load()
  setStatus(t('applications.applicationUpdated'), 'success')
}

function goToApp(app) {
  if (app.last_report_id) {
    router.push(`/dashboard/reports/${app.last_report_id}/findings`)
  } else {
    createReport(app)
  }
}

function createReport(app) {
  router.push({ path: '/dashboard/reports', query: { new: '1', app: app.id } })
}

async function removeApplication(id) {
  const ok = await showConfirm({ message: t('applications.deleteConfirm'), danger: true })
  if (!ok) return
  setStatus(t('applications.deletingApplication'), 'info')
  await request(`/api/admin/applications/${id}`, { method: 'DELETE' })
  await load()
  setStatus(t('applications.applicationDeleted'), 'success')
}

async function checkUserRole() {
  try {
    const user = await getSessionUser()
    if (user.role === 'admin') {
      isOrgAdmin.value = true
      canCreateReports.value = true
      return
    }
    
    // Check organization role from user session
    if (user.org_role) {
      isOrgAdmin.value = ['org_admin', 'org_owner'].includes(user.org_role)
      canCreateReports.value = user.org_role !== 'readonly'
    } else {
      canCreateReports.value = false
    }
  } catch (err) {
    isOrgAdmin.value = false
    canCreateReports.value = false
  }
}

onMounted(async () => {
  await checkUserRole()
  await load()
})
</script>

<template>
  <div class="org-hero">
    <div class="org-title">
      <p class="kicker">{{ $t('applications.title') }}</p>
      <h1>{{ $t('applications.heading') }}</h1>
      <p class="subtitle">{{ $t('applications.subtitle') }}</p>
    </div>
  </div>

  <div v-if="isOrgAdmin" class="card">
    <div class="row-3">
      <div>
        <label for="new-app-name">{{ $t('common.name') }}</label>
        <input
          id="new-app-name"
          v-model="newName"
          :placeholder="$t('applications.namePlaceholder')"
          @keyup.enter="addApplication"
          :aria-label="$t('applications.newAppAriaLabel')"
        />
      </div>
      <div>
        <label for="new-app-type">{{ $t('applications.typeLabel') }}</label>
        <select id="new-app-type" v-model="newType" :aria-label="$t('applications.typeAriaLabel')">
          <option v-for="typeOpt in APP_TYPES" :key="typeOpt.value" :value="typeOpt.value">{{ $t(typeOpt.labelKey) }}</option>
        </select>
      </div>
      <div class="actions" style="align-items:flex-end">
        <button
          @click="addApplication"
          :disabled="!newName.trim()"
          :aria-label="$t('applications.addAppAriaLabel')"
        >
          {{ $t('applications.addApplication') }}
        </button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="app-grid" v-if="applications.length">
      <div v-for="app in applications" :key="app.id" class="app-card card" @click="goToApp(app)">
        <div class="app-card-top">
          <div class="app-card-name">{{ app.name }}</div>
          <span class="type-badge" v-if="app.type">{{ typeLabel(app.type) }}</span>
        </div>
        <div class="app-card-desc" v-if="app.description">{{ app.description }}</div>

        <!-- Usage stats -->
        <div class="app-stats">
          <div class="app-stat">
            <span class="app-stat-value">{{ app.report_count ?? 0 }}</span>
            <span class="app-stat-label">{{ (app.report_count ?? 0) === 1 ? $t('applications.reportSingular') : $t('applications.reportPlural') }}</span>
          </div>
          <div class="app-stat">
            <span class="app-stat-value">{{ app.finding_count ?? 0 }}</span>
            <span class="app-stat-label">{{ $t('applications.findings') }}</span>
          </div>
          <div class="app-stat" v-if="app.last_report">
            <span class="app-stat-value">{{ relativeDate(app.last_report) }}</span>
            <span class="app-stat-label">{{ $t('applications.lastAssessed') }}</span>
          </div>
        </div>

        <!-- Clients associated with this app -->
        <div class="app-clients" v-if="app.clients && app.clients.length">
          <span class="app-clients-label">{{ $t('applications.testedBy') }}</span>
          <div class="app-clients-list">
            <span v-for="client in app.clients" :key="client" class="client-pill">{{ client }}</span>
          </div>
        </div>
        <div class="app-clients app-clients-empty" v-else>
          <span class="muted">{{ $t('applications.noReportsYet') }}</span>
        </div>

        <div class="app-card-actions" @click.stop>
          <button v-if="canCreateReports" @click="createReport(app)" :aria-label="$t('applications.createReportAriaLabel')">{{ $t('applications.createReport') }}</button>
          <button v-if="isOrgAdmin" class="secondary" @click="openEdit(app)">{{ $t('common.edit') }}</button>
          <button v-if="isOrgAdmin" class="danger" @click="removeApplication(app.id)">{{ $t('common.delete') }}</button>
        </div>
      </div>
    </div>
    <p v-else class="muted">{{ $t('applications.noApplications') }}</p>
  </div>

  <Modal v-if="showModal" :title="$t('applications.editModalTitle')" @close="showModal = false">
    <div style="display:grid;gap:16px">
      <div>
        <label for="edit-app-name">{{ $t('applications.appNameLabel') }}</label>
        <input id="edit-app-name" v-model="editName" @keyup.enter="saveEdit" :aria-label="$t('applications.editAppNameAriaLabel')" />
      </div>
      <div>
        <label for="edit-app-type">{{ $t('applications.typeLabel') }}</label>
        <select id="edit-app-type" v-model="editType" :aria-label="$t('applications.editTypeAriaLabel')">
          <option v-for="typeOpt in APP_TYPES" :key="typeOpt.value" :value="typeOpt.value">{{ $t(typeOpt.labelKey) }}</option>
        </select>
      </div>
      <div>
        <label for="edit-app-desc">{{ $t('applications.descriptionLabel') }}</label>
        <textarea id="edit-app-desc" v-model="editDescription" rows="3" :aria-label="$t('applications.editDescAriaLabel')"></textarea>
      </div>
      <div class="actions" style="justify-content:flex-end">
        <button class="secondary" @click="showModal = false" :aria-label="$t('applications.cancelEditingAriaLabel')">{{ $t('common.cancel') }}</button>
        <button @click="saveEdit" :disabled="!editName.trim()" :aria-label="$t('applications.saveAppAriaLabel')">{{ $t('common.save') }}</button>
      </div>
    </div>
  </Modal>
</template>

<style scoped>
/* ── Grid of app cards ── */
.app-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}

.app-card {
  cursor: pointer;
  padding: 20px;
  transition: border-color 0.15s, box-shadow 0.15s;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.app-card:hover {
  border-color: var(--primary);
  box-shadow: 0 0 0 1px var(--primary), 0 2px 8px rgba(13, 148, 136, 0.15);
}

.app-card-top {
  display: flex;
  align-items: center;
  gap: 8px;
}
.app-card-name {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-primary);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.type-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  background: var(--bg-input);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  flex-shrink: 0;
}

.app-card-desc {
  font-size: 13px;
  color: var(--text-muted);
  line-height: 1.4;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

/* ── Stats row ── */
.app-stats {
  display: flex;
  gap: 16px;
  padding: 10px 0;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}
.app-stat {
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.app-stat-value {
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
}
.app-stat-label {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

/* ── Team pills ── */
.app-clients {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.app-clients-label {
  font-size: 11px;
  color: var(--text-muted);
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-right: 2px;
}
.app-clients-empty {
  padding: 4px 0;
}
.app-clients-list {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}
.client-pill {
  display: inline-flex;
  align-items: center;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 500;
  background: rgba(13, 148, 136, 0.1);
  color: #60a5fa;
  border: 1px solid rgba(13, 148, 136, 0.2);
}

/* ── Card actions ── */
.app-card-actions {
  display: flex;
  gap: 8px;
  margin-top: auto;
  padding-top: 4px;
}

@media (max-width: 700px) {
  .app-grid {
    grid-template-columns: 1fr;
  }
}
</style>
