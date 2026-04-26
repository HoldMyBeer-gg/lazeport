<script setup>
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { request, getSessionUser } from '../services/api'
import { setStatus } from '../stores/status'
import { showConfirm } from '../composables/useConfirm'
import Modal from '../components/Modal.vue'

const { t } = useI18n()
const router = useRouter()
const connectors = ref([])
const showModal = ref(false)
const editingId = ref(null)
const modalTitle = ref('')
const isOrgAdmin = ref(false)
const checkingPermissions = ref(true)

// Form state
const form = ref({
  type: 'jira',
  name: '',
  enabled: true,
  config: {
    url: '',
    email: '',
    api_token: '',
  }
})

const testing = ref(false)

async function checkPermissions() {
  checkingPermissions.value = true
  try {
    const user = await getSessionUser()
    if (user.role === 'admin') {
      isOrgAdmin.value = true
      return true
    }
    
    // Check organization role from user session
    if (user.org_role && ['org_admin', 'org_owner'].includes(user.org_role)) {
      isOrgAdmin.value = true
      return true
    } else {
      setStatus(t('connectors.accessDenied'), 'error')
      router.push('/dashboard')
      return false
    }
  } catch (err) {
    router.push('/dashboard')
    return false
  } finally {
    checkingPermissions.value = false
  }
}

async function loadConnectors() {
  connectors.value = await request('/api/admin/connectors')
}

function openAdd() {
  editingId.value = null
  form.value = {
    type: 'jira',
    name: '',
    enabled: true,
    config: {
      url: '',
      email: '',
      api_token: '',
    }
  }
  modalTitle.value = t('connectors.modalTitleNew')
  showModal.value = true
}

function openEdit(connector) {
  editingId.value = connector.id
  const config = JSON.parse(connector.config || '{}')
  form.value = {
    type: connector.type,
    name: connector.name,
    enabled: connector.enabled,
    config: {
      url: config.url || '',
      email: config.email || '',
      api_token: config.api_token || '',
    }
  }
  modalTitle.value = t('connectors.modalTitleEdit')
  showModal.value = true
}

async function testConnection() {
  if (!form.value.config.url || !form.value.config.email || !form.value.config.api_token) {
    setStatus(t('connectors.fillAllFieldsBeforeTest'), 'error')
    return
  }

  testing.value = true
  setStatus(t('connectors.testingConnection'), 'info')

  try {
    const result = await request('/api/admin/connectors/jira/test', {
      method: 'POST',
      body: JSON.stringify({
        type: 'jira',
        name: form.value.name,
        config: form.value.config,
        enabled: true,
      })
    })

    if (result.success) {
      setStatus(t('connectors.testSuccess', { message: result.message }), 'success')
    } else {
      setStatus(t('connectors.testError', { message: result.message }), 'error')
    }
  } catch (e) {
    setStatus(e.message || t('connectors.connectionTestFailed'), 'error')
  } finally {
    testing.value = false
  }
}

async function saveConnector() {
  if (!form.value.name || !form.value.config.url || !form.value.config.email || !form.value.config.api_token) {
    setStatus(t('connectors.fillAllRequiredFields'), 'error')
    return
  }

  setStatus(t('connectors.savingConnector'), 'info')

  try {
    if (editingId.value) {
      await request(`/api/admin/connectors/${editingId.value}`, {
        method: 'PUT',
        body: JSON.stringify(form.value)
      })
    } else {
      await request('/api/admin/connectors', {
        method: 'POST',
        body: JSON.stringify(form.value)
      })
    }

    showModal.value = false
    await loadConnectors()
    setStatus(t('connectors.connectorSaved'), 'success')
  } catch (e) {
    setStatus(e.message || t('connectors.failedToSaveConnector'), 'error')
  }
}

async function deleteConnector(id) {
  const ok = await showConfirm({ message: t('connectors.deleteConfirm'), danger: true })
  if (!ok) return

  setStatus(t('connectors.deletingConnector'), 'info')
  await request(`/api/admin/connectors/${id}`, { method: 'DELETE' })
  await loadConnectors()
  setStatus(t('connectors.connectorDeleted'), 'success')
}

async function toggleEnabled(connector) {
  await request(`/api/admin/connectors/${connector.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      type: connector.type,
      name: connector.name,
      config: JSON.parse(connector.config),
      enabled: !connector.enabled,
    })
  })
  await loadConnectors()
  setStatus(connector.enabled ? t('connectors.connectorDisabled') : t('connectors.connectorEnabled'), 'success')
}

onMounted(async () => {
  const hasAccess = await checkPermissions()
  if (hasAccess) {
    await loadConnectors()
  }
})
</script>

<template>
  <div v-if="checkingPermissions" class="loading-state">
    <p>{{ $t('connectors.checkingPermissions') }}</p>
  </div>

  <template v-else-if="isOrgAdmin">
    <div class="org-hero">
      <div class="org-title">
        <p class="kicker">{{ $t('connectors.kicker') }}</p>
        <h1>{{ $t('connectors.title') }}</h1>
        <p class="subtitle">{{ $t('connectors.subtitle') }}</p>
      </div>
    </div>

    <div class="card">
      <button @click="openAdd" :aria-label="$t('connectors.addConnectorAriaLabel')">{{ $t('connectors.addConnector') }}</button>
    </div>

  <div class="card">
    <div class="table-wrapper" v-if="connectors.length">
      <table class="table">
        <thead>
          <tr>
            <th>{{ $t('connectors.type') }}</th>
            <th>{{ $t('common.name') }}</th>
            <th>{{ $t('connectors.status') }}</th>
            <th style="width:220px">{{ $t('connectors.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="connector in connectors" :key="connector.id">
            <td style="text-transform:capitalize">{{ connector.type }}</td>
            <td>{{ connector.name }}</td>
            <td>
              <span :class="['pill', connector.enabled ? 'low' : '']" style="font-size:11px;padding:2px 8px">
                {{ connector.enabled ? $t('connectors.enabled') : $t('connectors.disabled') }}
              </span>
            </td>
            <td>
              <div class="actions">
                <button class="secondary" @click="toggleEnabled(connector)">
                  {{ connector.enabled ? $t('connectors.disable') : $t('connectors.enable') }}
                </button>
                <button class="secondary" @click="openEdit(connector)">{{ $t('common.edit') }}</button>
                <button class="danger" @click="deleteConnector(connector.id)">{{ $t('common.delete') }}</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-else class="muted">{{ $t('connectors.noConnectors') }}</p>
  </div>

  <!-- Connector modal -->
  <Modal v-if="showModal" :title="modalTitle" :wide="true" @close="showModal = false">
    <div style="display:grid;gap:16px">
      <div>
        <label for="connector-type">{{ $t('connectors.connectorType') }}</label>
        <select id="connector-type" v-model="form.type" disabled :aria-label="$t('connectors.connectorTypeAriaLabel')">
          <option value="jira">Jira</option>
        </select>
        <p class="hint">{{ $t('connectors.moreConnectorsSoon') }}</p>
      </div>

      <div>
        <label for="connector-name">{{ $t('common.name') }}</label>
        <input id="connector-name" v-model="form.name" :placeholder="$t('connectors.connectorNamePlaceholder')" :aria-label="$t('connectors.connectorNameAriaLabel')" />
        <p class="hint">{{ $t('connectors.connectorNameHint') }}</p>
      </div>

      <div v-if="form.type === 'jira'">
        <div style="display:grid;gap:16px">
          <div>
            <label for="jira-url">{{ $t('connectors.jiraUrl') }}</label>
            <input id="jira-url" v-model="form.config.url" type="url" :placeholder="$t('connectors.jiraUrlPlaceholder')" :aria-label="$t('connectors.jiraUrlAriaLabel')" />
          </div>

          <div>
            <label for="jira-email">{{ $t('common.email') }}</label>
            <input id="jira-email" v-model="form.config.email" type="email" :placeholder="$t('connectors.jiraEmailPlaceholder')" :aria-label="$t('connectors.jiraEmailAriaLabel')" />
          </div>

          <div>
            <label for="jira-api-token">{{ $t('connectors.apiToken') }}</label>
            <input id="jira-api-token" v-model="form.config.api_token" type="password"
                   :placeholder="editingId ? $t('connectors.apiTokenPlaceholderLeaveUnchanged') : $t('connectors.apiTokenPlaceholder')"
                   :aria-label="$t('connectors.apiTokenAriaLabel')" />
            <p class="hint">
              {{ $t('connectors.apiTokenHintPrefix') }}
              <a href="https://id.atlassian.com/manage-profile/security/api-tokens"
                 target="_blank" style="color: var(--primary, #0d9488); text-decoration: underline">
                {{ $t('connectors.atlassianAccountSettings') }}
              </a>
            </p>
          </div>

          <div class="actions">
            <button class="secondary" @click="testConnection" :disabled="testing" :aria-label="$t('connectors.testConnectionAriaLabel')">
              {{ testing ? $t('connectors.testing') : $t('connectors.testConnection') }}
            </button>
          </div>
        </div>
      </div>

      <div class="actions" style="justify-content:flex-end;padding-top:16px;border-top:1px solid var(--border)">
        <button class="secondary" @click="showModal = false" :aria-label="$t('connectors.cancelEditingAriaLabel')">{{ $t('common.cancel') }}</button>
        <button @click="saveConnector" :aria-label="$t('connectors.saveConnectorAriaLabel')">{{ $t('connectors.saveConnector') }}</button>
      </div>
    </div>
  </Modal>
  </template>
</template>
