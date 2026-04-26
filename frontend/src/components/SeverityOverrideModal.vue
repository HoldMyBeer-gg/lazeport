<template>
  <Modal :show="show" @close="$emit('close')" :title="t('severity.overrideTitle')">
    <div class="severity-override-modal">
      <div class="current-severity" v-if="currentSeverity">
        <label>{{ t('severity.current') }}</label>
        <span :class="['pill', currentSeverity.toLowerCase()]">{{ currentSeverity }}</span>
      </div>

      <div class="form-group">
        <label for="severity-select">{{ t('severity.newSeverity') }}</label>
        <select id="severity-select" v-model="selectedSeverity" class="severity-select">
          <option value="">{{ t('severity.selectSeverity') }}</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
      </div>

      <div class="form-group" v-if="selectedSeverity">
        <label for="severity-reason">
          {{ t('severity.justification') }}
          <span class="required">*</span>
        </label>
        <textarea
          id="severity-reason"
          v-model="reason"
          :placeholder="t('severity.justificationPlaceholder')"
          rows="4"
          class="reason-textarea"
        ></textarea>
        <p class="hint">{{ t('severity.justificationHint') }}</p>
      </div>

      <div class="modal-actions">
        <button @click="$emit('close')" class="btn-secondary">{{ t('common.cancel') }}</button>
        <button 
          @click="apply" 
          class="btn-primary" 
          :disabled="!selectedSeverity || (selectedSeverity !== currentSeverity && !reason.trim())"
        >
          {{ t('severity.apply') }}
        </button>
      </div>
    </div>
  </Modal>
</template>

<script setup>
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Modal from './Modal.vue'

const { t } = useI18n()

const props = defineProps({
  show: Boolean,
  currentSeverity: String,
})

const emit = defineEmits(['close', 'apply'])

const selectedSeverity = ref('')
const reason = ref('')

// Reset when modal opens/closes
watch(() => props.show, (isShown) => {
  if (isShown) {
    selectedSeverity.value = props.currentSeverity || ''
    reason.value = ''
  }
})

function apply() {
  if (!selectedSeverity.value) return
  if (selectedSeverity.value !== props.currentSeverity && !reason.value.trim()) return
  
  emit('apply', {
    severity: selectedSeverity.value,
    reason: reason.value.trim()
  })
  emit('close')
}
</script>

<style scoped>
.severity-override-modal {
  display: flex;
  flex-direction: column;
  gap: 20px;
  min-width: 400px;
}

.current-severity {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: var(--surface-secondary);
  border-radius: 6px;
}

.current-severity label {
  font-weight: 500;
  color: var(--text-secondary);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-weight: 500;
  color: var(--text);
}

.required {
  color: var(--error);
}

.severity-select {
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface);
  color: var(--text);
  font-size: 14px;
  font-family: inherit;
}

.severity-select:focus {
  outline: none;
  border-color: var(--primary);
}

.reason-textarea {
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface);
  color: var(--text);
  font-size: 14px;
  font-family: inherit;
  resize: vertical;
}

.reason-textarea:focus {
  outline: none;
  border-color: var(--primary);
}

.hint {
  font-size: 12px;
  color: var(--text-faint);
  margin: 0;
}

.modal-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  margin-top: 8px;
}

.pill {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
}

.pill.critical {
  background: var(--sev-critical-bg);
  color: var(--sev-critical-text);
}

.pill.high {
  background: var(--sev-high-bg);
  color: var(--sev-high-text);
}

.pill.medium {
  background: var(--sev-medium-bg);
  color: var(--sev-medium-text);
}

.pill.low {
  background: var(--sev-low-bg);
  color: var(--sev-low-text);
}

.pill.info {
  background: var(--sev-info-bg);
  color: var(--sev-info-text);
}
</style>
