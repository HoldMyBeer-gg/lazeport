<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request } from '../services/api'
import logoDarkPng from '../assets/logo-dark.png'
import logoDarkWebp from '../assets/logo-dark.webp'
import logoLightPng from '../assets/logo-light.png'
import logoLightWebp from '../assets/logo-light.webp'

const { t } = useI18n()
const router = useRouter()
const route = useRoute()

// Login state
const email = ref('')
const password = ref('')
const error = ref('')
const step = ref('choice') // 'choice' | 'sso_email' | 'password' | '2fa' | 'backup'

// 2FA state
const twofa_code = ref('')
const backup_code = ref('')

/* Pick the right logo for the active theme */
const activeTheme = ref(document.documentElement.getAttribute('data-theme') || 'dark')
let _observer = null
onMounted(() => {
  _observer = new MutationObserver(() => {
    activeTheme.value = document.documentElement.getAttribute('data-theme') || 'dark'
  })
  _observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
})
onUnmounted(() => { if (_observer) _observer.disconnect() })

const light = computed(() => ['light', 'solarized-light', 'accessibility'].includes(activeTheme.value))
const logoSrcPng = computed(() => light.value ? logoDarkPng : logoLightPng)
const logoSrcWebp = computed(() => light.value ? logoDarkWebp : logoLightWebp)

async function submitPassword() {
  error.value = ''
  try {
    const response = await request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: email.value.trim(), password: password.value })
    })
    
    if (response.requires_2fa) {
      step.value = '2fa'
    } else {
      router.push('/dashboard')
    }
  } catch (e) {
    if (e?.code === 'rate_limit') {
      const minutes = Math.ceil((e.secondsRemaining || 60) / 60)
      error.value = t('login.rateLimited', { minutes })
    } else {
      error.value = e.message || t('login.loginFailed')
    }
  }
}

async function submit2FA() {
  error.value = ''
  try {
    const response = await request('/auth/2fa/verify', {
      method: 'POST',
      body: JSON.stringify({ code: twofa_code.value })
    })
    
    if (response.success) {
      router.push('/dashboard')
    }
  } catch (e) {
    if (e?.code === 'rate_limit') {
      const minutes = Math.ceil((e.secondsRemaining || 60) / 60)
      error.value = t('login.rateLimited', { minutes })
    } else {
      error.value = e.message || t('twofa.loginInvalidCode')
    }
  }
}

async function submitBackupCode() {
  error.value = ''
  try {
    const response = await request('/auth/2fa/verify', {
      method: 'POST',
      body: JSON.stringify({ backup_code: backup_code.value })
    })
    
    if (response.success) {
      router.push('/dashboard')
    }
  } catch (e) {
    if (e?.code === 'rate_limit') {
      const minutes = Math.ceil((e.secondsRemaining || 60) / 60)
      error.value = t('login.rateLimited', { minutes })
    } else {
      error.value = e.message || t('twofa.loginInvalidBackupCode')
    }
  }
}

function goToBackup() {
  step.value = 'backup'
  error.value = ''
}

function goTo2FA() {
  step.value = '2fa'
  error.value = ''
}

function goBackToLogin() {
  step.value = 'password'
  twofa_code.value = ''
  backup_code.value = ''
  error.value = ''
}

function goToChoice() {
  step.value = 'choice'
  email.value = ''
  password.value = ''
  error.value = ''
}

function goToPassword() {
  step.value = 'password'
  error.value = ''
}

function goToSsoEmail() {
  step.value = 'sso_email'
  email.value = ''
  error.value = ''
}

async function submitSsoEmail() {
  error.value = ''
  if (!email.value.trim()) return
  try {
    const res = await request('/auth/oidc/email-check', {
      method: 'POST',
      body: JSON.stringify({ email: email.value.trim() }),
    })
    if (res.password_only) {
      error.value = t('login.ssoNoConfig')
    } else {
      const params = new URLSearchParams({
        org_id: res.org_id,
        provider_id: res.provider_id,
      })
      window.location.href = `/auth/oidc/login?${params}`
    }
  } catch {
    error.value = t('login.ssoNoConfig')
  }
}

onMounted(() => {
  const err = route.query.error
  if (err === 'no_account') error.value = t('login.oidcNoAccount')
  else if (err === 'oidc_failed') error.value = t('login.oidcFailed')
  if (err) step.value = 'choice'
})
</script>

<template>
  <div style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;">
    <div style="max-width:420px;width:100%;text-align:center;">
      <picture>
        <source :srcset="logoSrcWebp" type="image/webp" />
        <img :src="logoSrcPng" alt="Laze Report" class="login-logo" />
      </picture>
      
      <!-- Choice Step: SSO or Password -->
      <div v-if="step === 'choice'" class="card" style="margin-top:24px;">
        <h2>{{ $t('login.title') }}</h2>
        <p class="muted">{{ $t('login.subtitle') }}</p>
        <div class="grid">
          <button
            type="button"
            class="secondary"
            style="padding:12px 20px;font-size:16px;display:flex;align-items:center;justify-content:center;gap:8px"
            @click="goToSsoEmail"
          >
            {{ $t('login.signInWithSso') }}
          </button>
          <button
            type="button"
            class="secondary"
            style="padding:12px 20px;font-size:16px"
            @click="goToPassword"
          >
            {{ $t('login.signInWithPassword') }}
          </button>
          <p v-if="error" class="muted" style="color:var(--danger)">{{ error }}</p>
        </div>
      </div>

      <!-- SSO Email Step -->
      <div v-if="step === 'sso_email'" class="card" style="margin-top:24px;">
        <h2>{{ $t('login.signInWithSso') }}</h2>
        <p class="muted">{{ $t('login.ssoWorkEmailHint') }}</p>
        <div class="grid">
          <div>
            <label for="login-sso-email">{{ $t('login.ssoWorkEmailLabel') }}</label>
            <input id="login-sso-email" type="email" v-model="email" @keyup.enter="submitSsoEmail" />
          </div>
          <div class="actions">
            <button @click="submitSsoEmail">{{ $t('login.continue') }}</button>
          </div>
          <button type="button" @click="goToChoice" style="background:transparent;border:none;color:var(--text-muted);font-size:14px;cursor:pointer">
            ← {{ $t('login.backToChoice') }}
          </button>
          <p v-if="error" class="muted" style="color:var(--danger)">{{ error }}</p>
        </div>
      </div>

      <!-- Password Step -->
      <div v-if="step === 'password'" class="card" style="margin-top:24px;">
        <h2>{{ $t('login.title') }}</h2>
        <p class="muted">{{ $t('login.subtitle') }}</p>
        <div class="grid">
          <div>
            <label for="login-email-pw">{{ $t('login.emailLabel') }}</label>
            <input id="login-email-pw" type="email" v-model="email" @keyup.enter="submitPassword" />
          </div>
          <div>
            <label for="login-password">{{ $t('login.passwordLabel') }}</label>
            <input id="login-password" type="password" v-model="password" @keyup.enter="submitPassword" />
          </div>
          <div class="actions">
            <button @click="submitPassword">{{ $t('login.submitButton') }}</button>
          </div>
          <button type="button" @click="goToChoice" style="background:transparent;border:none;color:var(--text-muted);font-size:14px;cursor:pointer">
            ← {{ $t('login.backToChoice') }}
          </button>
          <p v-if="error" class="muted" style="color:var(--danger)">{{ error }}</p>
        </div>
      </div>
      
      <!-- 2FA Code Step -->
      <div v-if="step === '2fa'" class="card" style="margin-top:24px;">
        <h2>{{ $t('twofa.loginTitle') }}</h2>
        <p class="muted">{{ $t('twofa.loginDesc') }}</p>
        <div class="grid">
          <div>
            <input 
              id="twofa-code" 
              type="text" 
              v-model="twofa_code" 
              placeholder="000000"
              maxlength="6"
              style="text-align:center;font-size:24px;letter-spacing:8px;font-family:monospace"
              @keyup.enter="submit2FA"
              autofocus
            />
          </div>
          <div class="actions">
            <button @click="submit2FA" :disabled="twofa_code.length !== 6">{{ $t('twofa.loginVerifyButton') }}</button>
          </div>
          <button class="secondary" @click="goToBackup" style="margin-top:12px">{{ $t('twofa.loginUseBackup') }}</button>
          <button type="button" @click="goBackToLogin" style="background:transparent;border:none;color:var(--text-muted);font-size:14px;margin-top:8px;cursor:pointer">
            ← {{ $t('twofa.loginBackToLogin') }}
          </button>
          <p v-if="error" class="muted" style="color:var(--danger);margin-top:12px">{{ error }}</p>
        </div>
      </div>
      
      <!-- Backup Code Step -->
      <div v-if="step === 'backup'" class="card" style="margin-top:24px;">
        <h2>{{ $t('twofa.loginBackupTitle') }}</h2>
        <p class="muted">{{ $t('twofa.loginBackupDesc') }}</p>
        <div class="grid">
          <div>
            <input 
              id="backup-code" 
              type="text" 
              v-model="backup_code" 
              :placeholder="$t('twofa.loginBackupPlaceholder')"
              maxlength="9"
              style="text-align:center;font-size:20px;letter-spacing:4px;font-family:monospace;text-transform:uppercase"
              @keyup.enter="submitBackupCode"
              autofocus
            />
          </div>
          <div class="actions">
            <button @click="submitBackupCode" :disabled="backup_code.length < 8">{{ $t('twofa.loginVerifyButton') }}</button>
          </div>
          <button type="button" @click="goTo2FA" style="background:transparent;border:none;color:var(--text-muted);font-size:14px;margin-top:8px;cursor:pointer">
            ← {{ $t('twofa.loginBackToAuth') }}
          </button>
          <p v-if="error" class="muted" style="color:var(--danger);margin-top:12px">{{ error }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.login-logo {
  height: 80px;
  width: auto;
}
</style>
