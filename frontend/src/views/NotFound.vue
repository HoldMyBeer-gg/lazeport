<script setup>
import { useRouter } from 'vue-router'
</script>

<template>
  <main class="not-found">
    <h1 class="title">{{ $t('notFound.title') }}</h1>
    <p class="message">{{ $t('notFound.message') }}</p>
    <router-link to="/dashboard" class="back">{{ $t('notFound.backToDashboard') }}</router-link>
  </main>
</template>

<style scoped>
.not-found {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
  text-align: center;
}
.title {
  font-size: 2rem;
  font-weight: 700;
  margin: 0 0 0.5rem;
}
.message {
  font-size: 1.25rem;
  margin: 0 0 1rem;
  opacity: 0.7;
}
.back {
  color: var(--color-link, #0af);
}
</style>
