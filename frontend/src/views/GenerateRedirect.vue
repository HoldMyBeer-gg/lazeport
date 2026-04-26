<script setup>
/**
 * Smart redirect: takes user straight to the paste/generate flow.
 * If they have reports, go to the most recent report's findings page.
 * If not, go to Reports with ?new=1 to prompt creating one.
 */
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { request } from '../services/api'

const router = useRouter()
const error = ref(false)

async function loadAndRedirect() {
  error.value = false
  try {
    const reports = await request('/api/admin/reports')
    if (reports?.length > 0) {
      const latest = reports.sort((a, b) => new Date(b.updated_at || b.created_at) - new Date(a.updated_at || a.created_at))[0]
      router.replace({ path: `/dashboard/reports/${latest.id}/findings` })
    } else {
      router.replace({ path: '/dashboard/reports', query: { new: '1' } })
    }
  } catch {
    error.value = true
  }
}

onMounted(loadAndRedirect)
</script>

<template>
  <div class="generate-redirect">
    <p v-if="!error">{{ $t('common.loading') }}</p>
    <div v-else class="error-state" role="alert">
      <p class="error-message">{{ $t('reports.failedToLoad') }}</p>
      <div class="error-actions">
        <button type="button" class="btn-retry" @click="loadAndRedirect">{{ $t('reports.refresh') }}</button>
        <RouterLink to="/dashboard" class="link-dashboard">{{ $t('notFound.backToDashboard') }}</RouterLink>
      </div>
    </div>
  </div>
</template>

<style scoped>
.generate-redirect {
  padding: 2rem;
  text-align: center;
}
.error-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
}
.error-message {
  color: var(--text-secondary);
  margin: 0;
}
.error-actions {
  display: flex;
  gap: 1rem;
  align-items: center;
}
.btn-retry {
  padding: 8px 16px;
  background: var(--btn-primary-bg);
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
}
.btn-retry:hover {
  opacity: 0.9;
}
.link-dashboard {
  color: var(--primary);
}
</style>
