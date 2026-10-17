<script setup>
import { onMounted, onUnmounted, ref, watch, computed, nextTick, provide } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { getSessionUser, logout, request } from '../services/api'
import { THEMES, state as themeState, setTheme, loadTheme } from '../stores/theme'
import { startPolling, stopPolling, getGenerationTasks, cancelTask as cancelGenerationTask, acknowledgeTask } from '../stores/generationTaskStore'
import { showConfirm, confirmState, resolveConfirm } from '../composables/useConfirm'
import { status as globalStatus, clearStatus } from '../stores/status'
import TaskBar from '../components/TaskBar.vue'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import navLogoDarkPng from '../assets/nav-logo-dark.png'
import navLogoDarkWebp from '../assets/nav-logo-dark.webp'
import navLogoLightPng from '../assets/nav-logo-light.png'
import navLogoLightWebp from '../assets/nav-logo-light.webp'

const router = useRouter()
const route = useRoute()
const { t } = useI18n()

const isGenerateActive = computed(() => {
  const path = route.path
  return path === '/dashboard/generate' || /^\/dashboard\/reports\/[^/]+\/findings$/.test(path)
})

/* Theme-aware logo: dark logo on light backgrounds, light logo on dark */
function pickNavLogo(useWebp) {
  const suffix = useWebp ? 'Webp' : 'Png'
  const t = themeState.current
  if (t === 'light' || t === 'solarized-light' || t === 'accessibility') return useWebp ? navLogoDarkWebp : navLogoDarkPng
  if (t === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches
      ? (useWebp ? navLogoLightWebp : navLogoLightPng)
      : (useWebp ? navLogoDarkWebp : navLogoDarkPng)
  }
  return useWebp ? navLogoLightWebp : navLogoLightPng
}
const sidebarLogoPng = computed(() => pickNavLogo(false))
const sidebarLogoWebp = computed(() => pickNavLogo(true))

const user = ref(null)
const showThemePopup = ref(false)
const themePopupPos = ref({ top: 0, left: 0 })
const themeTriggerTopbar = ref(null)
const themeTriggerSidebar = ref(null)
const isOrgAdmin = ref(false)
const isSystemAdmin = ref(false)
const userOrgRole = ref('readonly')
const mobileMenuOpen = ref(false)
const sidebarCollapsed = ref(false)

// Org-level LLM settings (loaded from API, provided to child components)
const orgLlmSettings = ref({})

provide('orgLlmSettings', orgLlmSettings)
provide('updateOrgLlmSettings', (newVal) => { orgLlmSettings.value = newVal })
provide('refetchOrgLlmSettings', loadOrgLlmSettings)

async function loadOrgLlmSettings() {
  try {
    if (!user.value?.org_id) return
    const data = await request(`/api/orgs/${user.value.org_id}/llm-settings`)
    orgLlmSettings.value = data || {}
  } catch {
    orgLlmSettings.value = {}
  }
}

async function loadUser() {
  user.value = await getSessionUser()
  if (!user.value) {
    router.push('/login')
  }
}

async function loadOrgAdminStatus() {
  try {
    if (!user.value) return
    
    // Check if system admin
    isSystemAdmin.value = user.value.role === 'admin'
    
    if (user.value.role === 'admin') {
      isOrgAdmin.value = true
      userOrgRole.value = 'org_owner'
      return
    }
    
    // Check organization role from user session
    if (user.value.org_role) {
      userOrgRole.value = user.value.org_role
      isOrgAdmin.value = ['org_admin', 'org_owner'].includes(user.value.org_role)
    } else {
      userOrgRole.value = 'readonly'
      isOrgAdmin.value = false
    }
  } catch {
    isOrgAdmin.value = user.value?.role === 'admin'
    userOrgRole.value = 'readonly'
  }
}

async function doLogout() {
  await logout()
  router.push('/login')
}

function pickTheme(id) {
  setTheme(id)
  showThemePopup.value = false
}

function updateThemePopupPosition() {
  nextTick(() => {
    for (const el of [themeTriggerTopbar.value, themeTriggerSidebar.value]) {
      if (!el) continue
      const rect = el.getBoundingClientRect()
      if (rect.width > 0 && rect.height > 0) {
        themePopupPos.value = { top: rect.bottom + 8, left: rect.left }
        return
      }
    }
  })
}

function toggleThemePopup() {
  showThemePopup.value = !showThemePopup.value
  if (showThemePopup.value) updateThemePopupPosition()
}

function toggleMobileMenu() {
  mobileMenuOpen.value = !mobileMenuOpen.value
}

function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value
}

function closeMobileMenu() {
  mobileMenuOpen.value = false
}

function closePopupOnOutside(e) {
  if (showThemePopup.value && !e.target.closest('.theme-trigger') && !e.target.closest('.theme-popup')) {
    showThemePopup.value = false
  }
}

function onKeydown(e) {
  if (e.key !== 'Escape') return
  if (showThemePopup.value) {
    showThemePopup.value = false
    return
  }
  if (confirmState.visible) {
    resolveConfirm(false)
    return
  }
}

// Close mobile menu on route change
router.afterEach(() => {
  closeMobileMenu()
})

function onGenerationTaskClick(task) {
  if (!task.report_id) return
  const needsReview = task.task_type === 'regenerate_finding' || task.task_type === 'generate_summaries'
  if (needsReview && task.status === 'completed') {
    // Pass taskId so ReportFindings can fetch result_json and open the right modal
    // Use query param change so navigation fires even if already on that page (Rule 15)
    router.push({ path: `/dashboard/reports/${task.report_id}/findings`, query: { reviewTask: task.id } })
  } else if (task.task_type === 'validate_guidance' && task.status === 'completed' && task.finding_id) {
    // Navigate to finding with validation guidance panel open
    router.push({ path: `/dashboard/reports/${task.report_id}/findings`, query: { viewValidation: task.finding_id, t: Date.now() } })
  } else if (task.finding_id && task.status === 'completed') {
    // Scroll to and highlight the finding (generate_finding, import_finding)
    router.push({ path: `/dashboard/reports/${task.report_id}/findings`, query: { finding: task.finding_id, t: Date.now() } })
  } else {
    router.push({ path: `/dashboard/reports/${task.report_id}/findings`, query: { t: Date.now() } })
  }
}

async function onGenerationTaskCancel(task) {
  await cancelGenerationTask(task.id)
}

function onGenerationTaskDismiss(task) {
  acknowledgeTask(task.id)
}

function onDismissAllTasks() {
  const allTasks = getGenerationTasks()
  const terminal = allTasks.filter(t =>
    t.status === 'completed' || t.status === 'failed' ||
    t.status === 'cancelled' || t.status === 'stale'
  )
  for (const task of terminal) {
    acknowledgeTask(task.id)
  }
}

onMounted(async () => {
  await loadUser()
  await loadOrgAdminStatus()
  await loadOrgLlmSettings()
  loadTheme()
  startPolling()
  document.addEventListener('click', closePopupOnOutside)
  document.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  stopPolling()
  document.removeEventListener('click', closePopupOnOutside)
  document.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <!-- Skip Navigation Link -->
  <a href="#main-content" class="skip-link">{{ $t('dashboard.skipToContent') }}</a>

  <!-- Generation task bar: Celery-backed tasks (finding gen, summaries, vision, import) -->
  <task-bar
    :tasks="getGenerationTasks()"
    @task-click="onGenerationTaskClick"
    @task-cancel="onGenerationTaskCancel"
    @task-dismiss="onGenerationTaskDismiss"
    @dismiss-all="onDismissAllTasks"
  />

  <!-- Mobile Header -->
  <div class="mobile-header">
    <button 
      class="mobile-menu-btn" 
      @click="toggleMobileMenu"
      :aria-expanded="mobileMenuOpen"
      :aria-label="$t('dashboard.toggleNavAriaLabel')"
      aria-controls="main-navigation"
    >
      <div class="mobile-menu-icon" aria-hidden="true">
        <span></span>
        <span></span>
        <span></span>
      </div>
      <span>{{ $t('dashboard.menu') }}</span>
    </button>
    <RouterLink to="/dashboard">
        <picture>
          <source :srcset="sidebarLogoWebp" type="image/webp" />
          <img :src="sidebarLogoPng" alt="Laze Report" style="height:28px;width:auto;margin:0;" />
        </picture>
      </RouterLink>
  </div>

  <!-- Mobile Overlay -->
  <div 
    :class="['mobile-overlay', mobileMenuOpen && 'active']" 
    @click="closeMobileMenu"
  ></div>

  <!-- Top bar (desktop) -->
  <header class="dashboard-topbar">
    <button
      class="topbar-menu-btn"
      @click="toggleSidebar"
      :aria-label="sidebarCollapsed ? $t('dashboard.expandNavAriaLabel') : $t('dashboard.collapseNavAriaLabel')"
      :aria-expanded="!sidebarCollapsed"
      aria-controls="main-navigation"
    >
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>
      </svg>
    </button>
    <RouterLink to="/dashboard" class="topbar-logo">
      <picture>
        <source :srcset="sidebarLogoWebp" type="image/webp" />
        <img :src="sidebarLogoPng" alt="Lazeport" style="height:28px;width:auto;" />
      </picture>
    </RouterLink>
    <nav class="topbar-nav">
      <RouterLink to="/dashboard/generate" :class="['topbar-link', 'topbar-link-featured', isGenerateActive && 'active']" data-testid="nav-generate">{{ $t('dashboard.navContinue') }}</RouterLink>
      <RouterLink to="/dashboard/reports" class="topbar-link" data-testid="nav-reports" :class="{ active: route.path === '/dashboard/reports' }">{{ $t('dashboard.navReports') }}</RouterLink>
    </nav>
    <div class="topbar-spacer"></div>
    <div class="topbar-actions">
      <div ref="themeTriggerTopbar" class="theme-trigger topbar-theme">
        <button class="theme-btn" @click.stop="toggleThemePopup" :aria-label="$t('dashboard.themeToggleAriaLabel')" :aria-expanded="showThemePopup">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
        </button>
      </div>
      <div v-if="user" class="topbar-user muted">{{ user.email }}</div>
      <button class="secondary topbar-logout" @click="doLogout">{{ $t('dashboard.logout') }}</button>
    </div>
  </header>

  <div class="layout" :class="{ 'sidebar-collapsed': sidebarCollapsed }">
    <aside 
      :class="['sidebar', mobileMenuOpen && 'mobile-open', sidebarCollapsed && 'collapsed']"
      role="navigation"
      :aria-label="$t('dashboard.mainNavAriaLabel')"
      id="main-navigation"
    >
      <nav class="nav" role="navigation" aria-label="Primary">
        <RouterLink to="/dashboard/generate" :class="['nav-mobile-only', isGenerateActive && 'nav-featured']" data-testid="nav-generate">{{ $t('dashboard.navContinue') }}</RouterLink>
        <RouterLink to="/dashboard/reports" class="nav-mobile-only" data-testid="nav-reports">{{ $t('dashboard.navReports') }}</RouterLink>
        <RouterLink to="/dashboard/clients" data-testid="nav-clients">{{ $t('dashboard.navTeams') }}</RouterLink>
        <RouterLink to="/dashboard/applications">{{ $t('dashboard.navApplications') }}</RouterLink>
        <RouterLink to="/dashboard/templates">{{ $t('dashboard.navTemplates') }}</RouterLink>
        <RouterLink v-if="isOrgAdmin" to="/dashboard/connectors">{{ $t('dashboard.navConnectors') }}</RouterLink>
        <RouterLink to="/dashboard/settings">{{ $t('dashboard.navSettings') }}</RouterLink>
        <RouterLink to="/dashboard/trends">{{ $t('dashboard.navTrends') }}</RouterLink>
      </nav>
      <div v-if="isSystemAdmin" class="nav-section">
        <div class="nav-label">{{ $t('dashboard.navSystemAdmin') }}</div>
        <nav class="nav">
          <RouterLink to="/dashboard/organization">
            {{ $t('dashboard.navOrganizations') }}
          </RouterLink>
        </nav>
      </div>
      <div class="sidebar-footer">
        <div ref="themeTriggerSidebar" class="theme-trigger sidebar-theme">
          <button class="theme-btn" @click.stop="toggleThemePopup" :aria-label="$t('dashboard.themeToggleAriaLabel')" :aria-expanded="showThemePopup">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
            {{ $t('dashboard.theme') }}
          </button>
        </div>
        <div v-if="user" class="muted" style="font-size: 13px; margin-bottom: 8px;">{{ user.email }}</div>
        <button class="secondary" style="width: 100%;" @click="doLogout">{{ $t('dashboard.logout') }}</button>
      </div>
    </aside>
    <!-- Global status toast (setStatus calls from any page) -->
    <Transition name="status-toast">
      <div
        v-if="globalStatus.text"
        class="status-toast"
        :class="'status-toast--' + globalStatus.type"
        role="status"
        aria-live="polite"
      >
        <span class="status-toast__text">{{ globalStatus.text }}</span>
        <button
          class="status-toast__close"
          type="button"
          :aria-label="t('common.close')"
          @click="clearStatus"
        >✕</button>
      </div>
    </Transition>

    <main class="main" role="main" id="main-content">
      <RouterView />
    </main>
  </div>

  <ConfirmDialog />

  <Teleport to="body">
    <Transition name="popup">
      <div
        v-if="showThemePopup"
        class="theme-popup theme-popup-teleport"
        role="menu"
        :style="{ top: `${themePopupPos.top}px`, left: `${themePopupPos.left}px` }"
      >
        <button
          v-for="thm in THEMES"
          :key="thm.id"
          role="menuitem"
          :aria-label="$t(thm.labelKey)"
          :class="['theme-option', themeState.current === thm.id && 'active']"
          @click="pickTheme(thm.id)"
        >
          <span class="theme-swatch" :style="{ background: thm.swatch }"></span>
          {{ $t(thm.labelKey) }}
        </button>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.popup-enter-from, .popup-leave-to { opacity: 0; transform: translateY(6px); }
.popup-enter-to, .popup-leave-from { opacity: 1; transform: translateY(0); }
.popup-enter-active, .popup-leave-active { transition: opacity 0.15s, transform 0.15s; }

.fade-enter-from, .fade-leave-to { opacity: 0; }
.fade-enter-to, .fade-leave-from { opacity: 1; }
.fade-enter-active, .fade-leave-active { transition: opacity 0.2s ease; }

.drawer-enter-from, .drawer-leave-to { transform: translateX(100%); }
.drawer-enter-to, .drawer-leave-from { transform: translateX(0); }
.drawer-enter-active, .drawer-leave-active { transition: transform 0.25s ease; }

/* Dashboard top bar */
.dashboard-topbar {
  display: none;
}
@media (min-width: 769px) {
  .dashboard-topbar {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 12px 20px;
    background: var(--bg-sidebar);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    position: relative;
    z-index: 100;
    overflow: visible;
  }
  .topbar-actions { overflow: visible; }
  .topbar-menu-btn {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 8px 10px;
    border-radius: 8px;
    cursor: pointer;
    display: flex;
  }
  .topbar-menu-btn:hover { background: var(--nav-hover-bg); }
  .topbar-logo { display: flex; }
  .topbar-nav { display: flex; gap: 8px; align-items: center; }
  .topbar-link {
    padding: 8px 14px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    color: var(--nav-text);
    transition: background 0.15s, color 0.15s;
  }
  .topbar-link:hover { background: var(--nav-hover-bg); color: var(--nav-hover-text); }
  .topbar-link.active { background: var(--nav-active-bg); color: var(--nav-active-text); }
  .topbar-link-featured { color: var(--primary) !important; background: var(--primary-bg) !important; }
  .topbar-link-featured:hover { background: rgba(13, 148, 136, 0.18) !important; color: var(--primary) !important; }
  .topbar-link-featured.active { background: var(--primary-bg) !important; color: var(--primary) !important; }
  .topbar-spacer { flex: 1; min-width: 16px; }
  .topbar-actions { display: flex; align-items: center; gap: 12px; }
  .topbar-user { font-size: 13px; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .topbar-logout { padding: 6px 12px !important; font-size: 13px !important; }
  }
.theme-popup-teleport {
  position: fixed;
  bottom: auto;
  left: auto;
  min-width: 180px;
  height: fit-content;
  display: flex;
  flex-direction: column;
  z-index: 2000;
}
.layout.sidebar-collapsed {
  grid-template-columns: 0 1fr;
}
.layout.sidebar-collapsed .sidebar {
  width: 0;
  min-width: 0;
  padding: 0;
  overflow: hidden;
  border-right: none;
}
.sidebar.collapsed .nav,
.sidebar.collapsed .nav-section,
.sidebar.collapsed .sidebar-footer { display: none; }
.sidebar-footer {
  margin-top: auto;
  padding-top: 24px;
}
@media (min-width: 769px) {
  .sidebar-theme { display: none; }
  .sidebar .nav .nav-mobile-only { display: none !important; }
}

/* Featured nav item - kept for sidebar when expanded */
.nav-featured {
  display: flex !important;
  align-items: center;
  gap: 8px;
  padding: 12px 16px !important;
  font-size: 14px;
  font-weight: 500;
  color: var(--primary) !important;
  background: var(--primary-bg) !important;
}
.nav-featured:hover {
  background: rgba(13, 148, 136, 0.18) !important;
  color: var(--primary) !important;
}
.nav-featured.router-link-active {
  background: var(--primary-bg) !important;
  color: var(--primary) !important;
}

/* Theme Popup */
.theme-trigger {
  position: relative;
}

.theme-btn {
  width: 100%;
  background: none;
  border: none;
  padding: 12px 16px;
  text-align: left;
  color: var(--text-primary);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  border-radius: 6px;
  font-size: 14px;
  transition: background-color 0.2s;
}

.theme-btn:hover {
  background: var(--hover-bg);
}

.theme-popup {
  position: absolute;
  left: 100%;
  bottom: 0;
  margin-left: 12px;
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  width: 200px;
  z-index: 1000;
  padding: 8px;
}

.theme-popup button {
  width: 100%;
  background: none;
  border: none;
  padding: 8px 12px;
  text-align: left;
  cursor: pointer;
  border-radius: 6px;
  font-size: 14px;
  color: var(--text-primary);
  transition: background-color 0.2s;
}

.theme-popup button:hover {
  background: var(--hover-bg);
}

.theme-popup button.active {
  background: var(--primary);
  color: var(--on-primary);
}

/* RTL overrides */
[dir="rtl"] .llm-drawer {
  right: auto;
  left: 0;
  border-left: none;
  border-right: 1px solid var(--border);
  box-shadow: 4px 0 24px rgba(0, 0, 0, 0.12);
}

[dir="rtl"] .theme-popup {
  left: auto;
  right: 100%;
  margin-left: 0;
  margin-right: 12px;
}

[dir="rtl"] .theme-popup button {
  text-align: right;
}

[dir="rtl"] .llm-form-vision,
[dir="rtl"] .llm-form-extra-instructions {
  padding-left: 0;
  padding-right: 4px;
}

/* ── Status toast ───────────────────────────────────────────────────────── */
.status-toast {
  position: fixed;
  top: 12px;
  right: 12px;
  z-index: 1100;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  border-radius: 6px;
  font-size: 0.85rem;
  font-family: inherit;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
  max-width: min(420px, calc(100vw - 24px));
  word-break: break-word;
}

.status-toast--success {
  background: var(--color-success-bg, #1a2e1a);
  color: var(--color-success, #859900);
  border: 1px solid var(--color-success, #859900);
}

.status-toast--error {
  background: var(--color-error-bg, #2e1a1a);
  color: var(--color-error, #dc322f);
  border: 1px solid var(--color-error, #dc322f);
}

.status-toast--info {
  background: var(--color-info-bg, #1a2a2e);
  color: var(--color-info, #2aa198);
  border: 1px solid var(--color-info, #2aa198);
}

.status-toast__text {
  flex: 1;
}

.status-toast__close {
  background: none;
  border: none;
  color: inherit;
  cursor: pointer;
  font-size: 0.9rem;
  padding: 0 2px;
  opacity: 0.6;
  flex-shrink: 0;
}

.status-toast__close:hover {
  opacity: 1;
}

.status-toast-enter-from,
.status-toast-leave-to {
  opacity: 0;
  transform: translateX(20px);
}

.status-toast-enter-to,
.status-toast-leave-from {
  opacity: 1;
  transform: translateX(0);
}

.status-toast-enter-active,
.status-toast-leave-active {
  transition: opacity 0.2s, transform 0.2s;
}
</style>
