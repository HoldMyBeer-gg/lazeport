<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { acceptInvite } from '../services/api'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const token = ref(String(route.query.token || ''))
const name = ref('')
const password = ref('')
const confirm = ref('')
const error = ref('')
const success = ref('')

async function submit() {
  error.value = ''
  success.value = ''
  if (!token.value) {
    error.value = t('invite.tokenMissing')
    return
  }
  if (!password.value || password.value.length < 12) {
    error.value = t('invite.passwordTooShort')
    return
  }
  if (password.value !== confirm.value) {
    error.value = t('invite.passwordMismatch')
    return
  }
  try {
    await acceptInvite(token.value, password.value, name.value)
    success.value = t('invite.success')
    setTimeout(() => router.push('/login'), 1200)
  } catch (e) {
    error.value = e.message || t('invite.failed')
  }
}
</script>

<template>
  <div class="main">
    <div class="card" style="max-width:460px;margin:80px auto;">
      <h2>{{ $t('invite.title') }}</h2>
      <p class="muted">{{ $t('invite.subtitle') }}</p>
      <div class="grid">
        <div>
          <label>{{ $t('invite.nameLabel') }}</label>
          <input v-model="name" :placeholder="$t('invite.namePlaceholder')" />
        </div>
        <div>
          <label>{{ $t('invite.newPasswordLabel') }}</label>
          <input type="password" v-model="password" />
        </div>
        <div>
          <label>{{ $t('invite.confirmPasswordLabel') }}</label>
          <input type="password" v-model="confirm" />
        </div>
        <div class="actions">
          <button @click="submit">{{ $t('invite.submitButton') }}</button>
        </div>
        <p v-if="error" class="muted">{{ error }}</p>
        <p v-if="success" class="muted">{{ success }}</p>
      </div>
    </div>
  </div>
</template>
