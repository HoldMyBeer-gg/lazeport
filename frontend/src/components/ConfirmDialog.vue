<script setup>
import { useI18n } from 'vue-i18n'
import { confirmState, resolveConfirm } from '../composables/useConfirm'

const { t } = useI18n()

function onConfirm() {
  resolveConfirm(true)
}
function onCancel() {
  resolveConfirm(false)
}
function onOverlay(e) {
  if (e.target === e.currentTarget) onCancel()
}
</script>

<template>
  <Teleport to="body">
    <Transition name="confirm-fade">
      <div v-if="confirmState.visible" class="confirm-overlay" @click="onOverlay">
        <div class="confirm-box" role="alertdialog" aria-modal="true">
          <h3 v-if="confirmState.title" class="confirm-title">{{ confirmState.title }}</h3>
          <p class="confirm-message">{{ confirmState.message }}</p>
          <div class="confirm-actions">
            <button
              v-if="confirmState.extraAction"
              class="confirm-btn confirm-extra"
              @click="confirmState.extraAction.handler()"
            >
              {{ confirmState.extraAction.label }}
            </button>
            <button class="confirm-btn confirm-cancel" @click="onCancel">
              {{ confirmState.cancelLabel || t('common.cancel') }}
            </button>
            <button
              :class="['confirm-btn', confirmState.danger ? 'confirm-danger' : 'confirm-primary']"
              @click="onConfirm"
              ref="confirmBtn"
            >
              {{ confirmState.confirmLabel || t('common.confirm') }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.confirm-overlay {
  position: fixed;
  inset: 0;
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.55);
  backdrop-filter: blur(4px);
  padding: 24px;
}

.confirm-box {
  background: var(--bg-card, #1e1e2e);
  border: 1px solid var(--border, #333);
  border-radius: 12px;
  padding: 28px 32px 24px;
  max-width: 420px;
  width: 100%;
  box-shadow: 0 16px 48px rgba(0, 0, 0, 0.35);
  animation: confirm-slide-up 0.2s ease-out;
}

@keyframes confirm-slide-up {
  from {
    opacity: 0;
    transform: translateY(12px) scale(0.97);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

.confirm-title {
  margin: 0 0 8px;
  font-size: 17px;
  font-weight: 600;
  color: var(--text-primary, #e0e0e0);
}

.confirm-message {
  margin: 0 0 24px;
  font-size: 14px;
  line-height: 1.55;
  color: var(--text-secondary, #aaa);
}

.confirm-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.confirm-btn {
  padding: 9px 20px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.15s, box-shadow 0.15s, transform 0.1s;
  border: 1px solid transparent;
  min-width: 90px;
}
.confirm-btn:active {
  transform: scale(0.97);
}

.confirm-extra {
  background: var(--bg-input, #2a2a3a);
  color: var(--text-secondary, #aaa);
  border-color: var(--border, #333);
  margin-right: auto;
}
.confirm-extra:hover {
  background: var(--bg-hover, #333);
  color: var(--text-primary, #e0e0e0);
}

.confirm-cancel {
  background: var(--bg-input, #2a2a3a);
  color: var(--text-secondary, #aaa);
  border-color: var(--border, #333);
}
.confirm-cancel:hover {
  background: var(--bg-hover, #333);
  color: var(--text-primary, #e0e0e0);
}

.confirm-primary {
  background: var(--primary, #0d9488);
  color: #fff;
}
.confirm-primary:hover {
  background: var(--btn-primary-hover, #0f766e);
  box-shadow: 0 2px 8px rgba(13, 148, 136, 0.3);
}

.confirm-danger {
  background: #ef4444;
  color: #fff;
}
.confirm-danger:hover {
  background: #dc2626;
  box-shadow: 0 2px 8px rgba(239, 68, 68, 0.3);
}

/* Transition */
.confirm-fade-enter-active,
.confirm-fade-leave-active {
  transition: opacity 0.15s ease;
}
.confirm-fade-enter-from,
.confirm-fade-leave-to {
  opacity: 0;
}
</style>
