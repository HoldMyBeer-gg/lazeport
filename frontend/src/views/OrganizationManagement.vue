<template>
  <div class="org-mgmt">
    <div class="org-hero">
      <div class="org-title">
        <p class="kicker">{{ $t('orgManagement.systemAdminKicker') }}</p>
        <h1>{{ $t('orgManagement.title') }}</h1>
        <p class="subtitle">{{ $t('orgManagement.systemAdminSubtitle') }}</p>
      </div>
    </div>

    <div class="org-content">
      <!-- System Admin: Create Organization -->
      <div class="org-card" v-if="isSystemAdmin">
        <div class="card-title">{{ $t('orgManagement.createOrganization') }}</div>
        <form @submit.prevent="createOrganization" class="create-org-form">
          <div class="form-group">
            <label for="new-org-name">{{ $t('orgManagement.orgName') }}</label>
            <input
              id="new-org-name"
              v-model="newOrg.name"
              type="text"
              :placeholder="$t('orgManagement.orgNamePlaceholder')"
              required
              maxlength="100"
            />
          </div>
          <div class="form-group">
            <label for="new-org-slug">{{ $t('orgManagement.orgSlug') }}</label>
            <input
              id="new-org-slug"
              v-model="newOrg.slug"
              type="text"
              :placeholder="$t('orgManagement.orgSlugPlaceholder')"
              required
              maxlength="50"
              pattern="[a-z0-9-_]+"
              @input="sanitizeSlug"
            />
            <small class="form-hint">{{ $t('orgManagement.orgSlugHint') }}</small>
          </div>
          <button type="submit" class="btn-primary" :disabled="creatingOrg">
            {{ creatingOrg ? $t('orgManagement.creating') : $t('orgManagement.create') }}
          </button>
        </form>
      </div>

      <!-- Existing Organizations List -->
      <div class="org-card" v-if="isSystemAdmin && organizations.length > 0">
        <div class="card-title">{{ $t('orgManagement.existingOrgs') }}</div>
        <div v-for="org in organizations" :key="org.id" class="org-item">
          <div class="org-header" @click="toggleOrgDetails(org.id)">
            <div class="org-info">
              <strong>{{ org.name }}</strong>
              <code>{{ org.slug }}</code>
              <span class="org-date">{{ $t('orgManagement.created') }} {{ formatDate(org.created_at) }}</span>
            </div>
            <button
              type="button"
              class="expand-btn"
              :aria-label="expandedOrg === org.id ? $t('orgManagement.collapseOrgAriaLabel') : $t('orgManagement.expandOrgAriaLabel')"
              :aria-expanded="expandedOrg === org.id"
            >
              {{ expandedOrg === org.id ? '▼' : '▶' }}
            </button>
          </div>

          <div v-if="expandedOrg === org.id" class="org-details">
            <!-- Members List -->
            <div class="members-section">
              <div class="section-header">
                <h4>{{ $t('orgManagement.members') }}</h4>
                <button type="button" class="btn-sm" @click="showAddMemberForm(org.id)">
                  {{ $t('orgManagement.addMember') }}
                </button>
              </div>

              <div v-if="loadingMembers[org.id]" class="loading-text">{{ $t('orgManagement.loadingMembers') }}</div>
              <div v-else-if="members[org.id] && members[org.id].length > 0" class="members-list">
                <div v-for="member in members[org.id]" :key="member.user_id" class="member-item">
                  <div class="member-info">
                    <strong>{{ member.email }}</strong>
                    <span v-if="member.name" class="member-name">{{ member.name }}</span>
                    <span class="member-role" :class="'role-' + member.role">{{ roleLabel(member.role) }}</span>
                  </div>
                  <div class="member-actions">
                    <button
                      v-if="member.user_id !== currentUserId"
                      type="button"
                      class="btn-secondary-sm"
                      @click="startEditingRole(org.id, member.user_id, member.role)"
                    >
                      {{ $t('orgManagement.changeRole') }}
                    </button>
                    <button
                      v-if="member.user_id !== currentUserId"
                      type="button"
                      class="btn-danger-sm"
                      @click="removeMember(org.id, member.user_id, member.email)"
                      :disabled="removingMember[member.user_id]"
                    >
                      {{ removingMember[member.user_id] ? $t('orgManagement.removing') : $t('common.remove') }}
                    </button>
                    <span v-else class="self-indicator">{{ $t('orgManagement.you') }}</span>
                  </div>
                </div>
              </div>
              <div v-else class="empty-text">{{ $t('orgManagement.noMembersYet') }}</div>

              <!-- Add Member Form -->
              <div v-if="addingMemberTo === org.id" class="add-member-form">
                <h5>{{ $t('orgManagement.addNewMember') }}</h5>
                <div class="form-row">
                  <input
                    v-model="newMember.email"
                    type="email"
                    :placeholder="$t('orgManagement.emailPlaceholder')"
                    required
                  />
                  <select v-model="newMember.role" required>
                    <option value="">{{ $t('orgManagement.selectRole') }}</option>
                    <option value="org_owner">{{ $t('orgManagement.roleOptionOrgOwner') }}</option>
                    <option value="org_admin">{{ $t('orgManagement.roleOptionOrgAdmin') }}</option>
                    <option value="consultant">{{ $t('orgManagement.roles.consultant') }}</option>
                    <option value="readonly">{{ $t('orgManagement.roles.readonly') }}</option>
                  </select>
                </div>
                <div class="form-actions">
                  <button type="button" class="btn-secondary" @click="cancelAddMember">{{ $t('common.cancel') }}</button>
                  <button
                    type="button"
                    class="btn-primary"
                    @click="addMember(org.id)"
                    :disabled="addingMember || !newMember.email || !newMember.role"
                  >
                    {{ addingMember ? $t('orgManagement.creating') : $t('orgManagement.addMemberButton') }}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="!isSystemAdmin" class="empty-state">
        <p>{{ $t('orgManagement.accessDenied') }}</p>
      </div>
    </div>

    <!-- Error/Success Messages -->
    <div v-if="message" :class="['message', message.type]">
      {{ message.text }}
    </div>
  </div>

  <!-- Edit Member Role Modal -->
  <Modal v-if="editingMember" title="Change Member Role" @close="cancelEditRole">
    <div style="display:grid;gap:16px">
      <div>
        <label for="edit-role">New Role</label>
        <select id="edit-role" v-model="editingMember.newRole" style="padding:8px;width:100%">
          <option value="readonly">Read Only</option>
          <option value="consultant">Consultant</option>
          <option value="org_admin">Admin</option>
          <option value="org_owner">Owner</option>
        </select>
      </div>
      <div class="actions" style="justify-content:flex-end">
        <button type="button" class="secondary" @click="cancelEditRole">Cancel</button>
        <button type="button" @click="saveRoleChange" :disabled="savingRole">
          {{ savingRole ? 'Saving...' : 'Save' }}
        </button>
      </div>
    </div>
  </Modal>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { request, getSessionUser } from '../services/api.js';
import Modal from '../components/Modal.vue';

const { t } = useI18n();
const isSystemAdmin = ref(false);
const currentUserId = ref(null);
const creatingOrg = ref(false);
const newOrg = ref({ name: '', slug: '' });
const organizations = ref([]);
const message = ref(null);
const expandedOrg = ref(null);
const members = ref({});
const loadingMembers = ref({});
const addingMemberTo = ref(null);
const newMember = ref({ email: '', role: '' });
const addingMember = ref(false);
const removingMember = ref({});
const editingMember = ref(null);
const savingRole = ref(false);

function roleLabel(role) {
  return t(`orgManagement.roles.${role}`) || role;
}

onMounted(async () => {
  await checkSystemAdmin();
  await loadOrganizations();
});

async function checkSystemAdmin() {
  try {
    const user = await getSessionUser();
    isSystemAdmin.value = user?.role === 'admin';
    currentUserId.value = user?.id;
  } catch (err) {
    isSystemAdmin.value = false;
  }
}

async function loadOrganizations() {
  try {
    const data = await request('/api/orgs');
    organizations.value = data;
  } catch (err) {
    showMessage(t('orgManagement.loadOrgsFailed'), 'error');
  }
}

function sanitizeSlug() {
  newOrg.value.slug = newOrg.value.slug
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-_]/g, '');
}

async function createOrganization() {
  if (!newOrg.value.name.trim() || !newOrg.value.slug.trim()) {
    showMessage(t('orgManagement.fillAllFields'), 'error');
    return;
  }

  creatingOrg.value = true;
  try {
    const created = await request('/api/orgs', {
      method: 'POST',
      body: JSON.stringify({
        name: newOrg.value.name.trim(),
        slug: newOrg.value.slug.trim()
      })
    });
    
    showMessage(t('orgManagement.orgCreated', { name: created.name }), 'success');
    newOrg.value = { name: '', slug: '' };
    
    await loadOrganizations();
  } catch (err) {
    showMessage(err.message || t('orgManagement.createOrgFailed'), 'error');
  } finally {
    creatingOrg.value = false;
  }
}

async function toggleOrgDetails(orgId) {
  if (expandedOrg.value === orgId) {
    expandedOrg.value = null;
  } else {
    expandedOrg.value = orgId;
    await loadMembers(orgId);
  }
}

async function loadMembers(orgId) {
  loadingMembers.value[orgId] = true;
  try {
    const data = await request(`/api/orgs/${orgId}/members`);
    members.value[orgId] = data;
  } catch (err) {
    showMessage(t('orgManagement.loadMembersFailed'), 'error');
  } finally {
    loadingMembers.value[orgId] = false;
  }
}

function showAddMemberForm(orgId) {
  addingMemberTo.value = orgId;
  newMember.value = { email: '', role: '' };
}

function cancelAddMember() {
  addingMemberTo.value = null;
  newMember.value = { email: '', role: '' };
}

async function addMember(orgId) {
  if (!newMember.value.email || !newMember.value.role) {
    showMessage(t('orgManagement.fillAllFields'), 'error');
    return;
  }

  addingMember.value = true;
  try {
    await request(`/api/orgs/${orgId}/members`, {
      method: 'POST',
      body: JSON.stringify({
        user_email: newMember.value.email,
        role: newMember.value.role
      })
    });
    
    showMessage(t('orgManagement.memberInvitedSuccess'), 'success');
    cancelAddMember();
    await loadMembers(orgId);
  } catch (err) {
    showMessage(err.message || t('orgManagement.failedAddMember'), 'error');
  } finally {
    addingMember.value = false;
  }
}

function startEditingRole(orgId, userId, currentRole) {
  editingMember.value = { orgId, userId, newRole: currentRole };
}

function cancelEditRole() {
  editingMember.value = null;
}

async function saveRoleChange() {
  if (!editingMember.value) return;
  
  const { orgId, userId, newRole } = editingMember.value;
  savingRole.value = true;
  
  try {
    await request(`/api/orgs/${orgId}/members/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role: newRole })
    });
    showMessage(t('orgManagement.memberRoleUpdated'), 'success');
    editingMember.value = null;
    await loadMembers(orgId);
  } catch (err) {
    showMessage(err.message || t('orgManagement.roleUpdateFailed'), 'error');
  } finally {
    savingRole.value = false;
  }
}

async function removeMember(orgId, userId, email) {
  if (!confirm(t('orgManagement.removeConfirm', { email }))) {
    return;
  }

  removingMember.value[userId] = true;
  try {
    await request(`/api/orgs/${orgId}/members/${userId}`, {
      method: 'DELETE'
    });
    
    showMessage(t('orgManagement.memberRemoved'), 'success');
    await loadMembers(orgId);
  } catch (err) {
    showMessage(err.message || t('orgManagement.memberRemoveFailed'), 'error');
  } finally {
    removingMember.value[userId] = false;
  }
}

function formatDate(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  return d.toLocaleDateString();
}

function showMessage(text, type) {
  message.value = { text, type };
  setTimeout(() => {
    message.value = null;
  }, 5000);
}
</script>

<style scoped>
.org-mgmt {
  padding: 28px 20px 40px;
  max-width: 800px;
  margin: 0 auto;
}

.org-hero {
  margin-bottom: 32px;
}

.org-title h1 {
  margin: 0 0 8px 0;
  font-size: 34px;
}

.kicker {
  text-transform: uppercase;
  letter-spacing: 0.32em;
  font-size: 11px;
  color: var(--text-faint);
  margin: 0 0 10px;
}

.subtitle {
  color: var(--text-secondary);
  margin: 0;
  max-width: 560px;
}

.org-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.org-card {
  background: var(--bg-card);
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.card-title {
  font-weight: 600;
  font-size: 15px;
  color: var(--text-primary);
  margin-bottom: 16px;
}

.create-org-form .form-group {
  margin-bottom: 16px;
}

.create-org-form label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-primary);
  margin-bottom: 6px;
}

.create-org-form input {
  width: 100%;
  padding: 10px 12px;
  font-size: 14px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg-primary);
  color: var(--text-primary);
  transition: border-color 0.2s;
}

.create-org-form input:focus {
  outline: none;
  border-color: var(--accent);
}

.create-org-form .form-hint {
  display: block;
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}

.create-org-form button {
  width: 100%;
  margin-top: 8px;
}

.org-item {
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 12px;
  overflow: hidden;
}

.org-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.org-header:hover {
  background: var(--bg-hover);
}

.org-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.org-info strong {
  font-size: 16px;
}

.org-info code {
  background: var(--bg-secondary);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 12px;
  color: var(--accent);
  width: fit-content;
}

.org-date {
  font-size: 12px;
  color: var(--text-muted);
}

.expand-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 16px;
  color: var(--text-secondary);
  padding: 4px 8px;
}

.org-details {
  padding: 0 16px 16px 16px;
  border-top: 1px solid var(--border);
  background: var(--bg-secondary);
}

.members-section {
  padding-top: 16px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.section-header h4 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.btn-sm {
  padding: 6px 12px;
  font-size: 13px;
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-sm:hover {
  opacity: 0.9;
}

.loading-text,
.empty-text {
  text-align: center;
  padding: 16px;
  color: var(--text-muted);
  font-size: 13px;
}

.members-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.member-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background: var(--bg-card);
  border-radius: 4px;
  border: 1px solid var(--border);
}

.member-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1;
}

.member-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}

.role-select {
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg-secondary);
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  min-width: 140px;
}

.role-select:hover {
  border-color: var(--btn-primary-bg);
}

.role-select:focus {
  outline: none;
  border-color: var(--btn-primary-bg);
  box-shadow: 0 0 0 2px rgba(13, 148, 136, 0.1);
}

.member-info strong {
  font-size: 14px;
}

.member-name {
  font-size: 12px;
  color: var(--text-secondary);
}

.member-role {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 12px;
  width: fit-content;
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

.btn-danger-sm {
  padding: 6px 12px;
  font-size: 12px;
  background: transparent;
  color: var(--danger);
  border: 1px solid var(--danger);
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-danger-sm:hover:not(:disabled) {
  background: var(--danger);
  color: white;
}

.btn-danger-sm:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary-sm {
  padding: 6px 12px;
  font-size: 12px;
  background: transparent;
  color: var(--text-primary);
  border: 1px solid var(--border);
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary-sm:hover {
  background: var(--bg-secondary);
  border-color: var(--btn-primary-bg);
}

.btn-cancel {
  padding: 8px 16px;
  font-size: 13px;
  background: transparent;
  color: var(--text-primary);
  border: 1px solid var(--border);
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-cancel:hover {
  background: var(--bg-secondary);
}

.btn-primary {
  padding: 8px 16px;
  font-size: 13px;
  background: var(--btn-primary-bg);
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 600;
  transition: opacity 0.2s;
}

.btn-primary:hover:not(:disabled) {
  opacity: 0.9;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.self-indicator {
  font-size: 12px;
  color: var(--text-muted);
  font-style: italic;
}

.add-member-form {
  margin-top: 16px;
  padding: 16px;
  background: var(--bg-card);
  border-radius: 6px;
  border: 1px solid var(--border);
}

.add-member-form h5 {
  margin: 0 0 12px 0;
  font-size: 14px;
  font-weight: 600;
}

.form-row {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 12px;
  margin-bottom: 12px;
}

.form-row input,
.form-row select {
  padding: 8px 12px;
  font-size: 14px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--bg-primary);
  color: var(--text-primary);
}

.form-row input:focus,
.form-row select:focus {
  outline: none;
  border-color: var(--accent);
}

.form-actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.empty-state {
  text-align: center;
  padding: 3rem;
  color: var(--text-secondary);
}

.message {
  position: fixed;
  bottom: 2rem;
  right: 2rem;
  padding: 1rem 1.5rem;
  border-radius: 12px;
  box-shadow: 0 10px 24px rgba(0, 0, 0, 0.18);
  z-index: 1001;
  animation: slideIn 0.3s ease;
}

.message.success {
  background: var(--success);
  color: #fff;
}

.message.error {
  background: var(--danger);
  color: #fff;
}

@keyframes slideIn {
  from {
    transform: translateX(400px);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

@media (max-width: 768px) {
  .org-mgmt {
    padding: 16px 12px 32px;
  }

  .org-title h1 {
    font-size: 28px;
  }

  .message {
    bottom: 1rem;
    right: 1rem;
    left: 1rem;
    text-align: center;
  }
}

@media (max-width: 480px) {
  .org-mgmt {
    padding: 12px 8px 24px;
  }

  .org-title h1 {
    font-size: 24px;
  }
}
</style>
