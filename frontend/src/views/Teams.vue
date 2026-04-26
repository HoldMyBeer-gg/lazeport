<script setup>
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { request, getSessionUser } from '../services/api'
import { setStatus } from '../stores/status'
import { showConfirm } from '../composables/useConfirm'
import Modal from '../components/Modal.vue'
import TagInput from '../components/TagInput.vue'

const { t } = useI18n()
const router = useRouter()
const clients = ref([])
const newName = ref('')
const showModal = ref(false)
const editId = ref(null)
const editName = ref('')
const isOrgAdmin = ref(false)
const canCreateReports = ref(false)

async function load() {
  clients.value = await request('/api/admin/clients')
}

async function addTeam() {
  if (!newName.value.trim()) return
  setStatus(t('clients.addingTeam'), 'info')
  await request('/api/admin/clients', {
    method: 'POST',
    body: JSON.stringify({ name: newName.value }),
  })
  newName.value = ''
  await load()
  setStatus(t('clients.clientAdded'), 'success')
}

function openEdit(client) {
  editId.value = client.id
  editName.value = client.name
  showModal.value = true
}

async function saveEdit() {
  setStatus(t('clients.savingTeam'), 'info')
  await request(`/api/admin/clients/${editId.value}`, {
    method: 'PUT',
    body: JSON.stringify({ name: editName.value }),
  })
  showModal.value = false
  editId.value = null
  editName.value = ''
  await load()
  setStatus(t('clients.clientUpdated'), 'success')
}

async function removeTeam(id) {
  const ok = await showConfirm({ message: t('clients.deleteConfirm'), danger: true })
  if (!ok) return
  setStatus(t('clients.deletingTeam'), 'info')
  await request(`/api/admin/clients/${id}`, { method: 'DELETE' })
  await load()
  setStatus(t('clients.clientDeleted'), 'success')
}

function onTagClick(tagName) {
  router.push({ path: '/dashboard/reports', query: { tag: tagName } })
}

function createReport(client) {
  // Navigate to Reports page with new report form open, client pre-selected
  router.push({
    path: '/dashboard/reports',
    query: { new: '1', client: client.id }
  })
}

function openClient(client) {
  if (client.report_count > 0 || !canCreateReports.value) {
    router.push({ path: '/dashboard/reports', query: { client: client.id } })
  } else {
    router.push({ path: '/dashboard/reports', query: { new: '1', client: client.id } })
  }
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
      <p class="kicker">{{ $t('clients.title') }}</p>
      <h1>{{ $t('clients.heading') }}</h1>
      <p class="subtitle">{{ $t('clients.subtitle') }}</p>
    </div>
  </div>

  <div v-if="isOrgAdmin" class="card">
    <div class="row">
      <div>
        <label for="new-client-name">{{ $t('clients.newTeam') }}</label>
        <input
          id="new-client-name"
          v-model="newName"
          :placeholder="$t('clients.teamNamePlaceholder')"
          @keyup.enter="addTeam"
          :aria-label="$t('clients.newTeamAriaLabel')"
        />
      </div>
      <div class="actions" style="align-items:flex-end">
        <button
          @click="addTeam"
          :disabled="!newName.trim()"
          :aria-label="$t('clients.addTeamAriaLabel')"
        >
          {{ $t('clients.addTeam') }}
        </button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="table-wrapper" v-if="clients.length">
      <table class="table">
        <thead>
          <tr>
            <th>{{ $t('common.name') }}</th>
            <th v-if="isOrgAdmin">{{ $t('clients.tags') }}</th>
            <th style="width:280px">{{ $t('clients.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="client in clients" :key="client.id">
            <td>
              <button class="client-name-btn" @click="openClient(client)">{{ client.name }}</button>
            </td>
            <td v-if="isOrgAdmin" style="min-width:150px;max-width:300px"><TagInput entityType="client" :entityId="client.id" @tag-click="onTagClick" /></td>
            <td v-else></td>
            <td>
              <div class="actions">
                <button v-if="canCreateReports" @click="createReport(client)" :aria-label="$t('clients.createReportAriaLabel')">{{ $t('clients.createReport') }}</button>
                <button v-if="isOrgAdmin" class="secondary" @click="openEdit(client)">{{ $t('common.edit') }}</button>
                <button v-if="isOrgAdmin" class="danger" @click="removeTeam(client.id)">{{ $t('common.delete') }}</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-else class="muted">{{ $t('clients.noTeams') }}</p>
  </div>

  <Modal v-if="showModal" :title="$t('clients.editTeamModalTitle')" @close="showModal = false">
    <div style="display:grid;gap:16px">
      <div>
        <label for="edit-client-name">{{ $t('clients.teamNameLabel') }}</label>
        <input id="edit-client-name" v-model="editName" @keyup.enter="saveEdit" :aria-label="$t('clients.editTeamNameAriaLabel')" />
      </div>
      <div class="actions" style="justify-content:flex-end">
        <button class="secondary" @click="showModal = false" :aria-label="$t('clients.cancelEditingAriaLabel')">{{ $t('common.cancel') }}</button>
        <button @click="saveEdit" :disabled="!editName.trim()" :aria-label="$t('clients.saveTeamAriaLabel')">{{ $t('common.save') }}</button>
      </div>
    </div>
  </Modal>
</template>

<style scoped>
.client-name-btn {
  background: none !important;
  border: none;
  border-radius: 0;
  color: var(--primary) !important;
  font-size: inherit;
  font-weight: 500;
  padding: 0;
  cursor: pointer;
  text-align: left;
  text-decoration: underline;
  text-underline-offset: 2px;
  transition: color 0.15s;
}

.client-name-btn:hover {
  background: none !important;
  color: var(--btn-primary-hover) !important;
}
</style>
