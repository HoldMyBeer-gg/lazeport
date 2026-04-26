<template>
  <Modal :show="show" @close="$emit('close')" :title="t('confidence.title')">
    <div class="confidence-modal">
      <div class="current-confidence" v-if="currentConfidence">
        <label>{{ t('confidence.current') }}</label>
        <span class="confidence-value">{{ currentConfidence }}</span>
      </div>

      <div class="form-group">
        <label for="confidence-select">{{ t('confidence.select') }}</label>
        <select id="confidence-select" v-model="selectedConfidence" class="confidence-select">
          <option value="">{{ t('confidence.selectLevel') }}</option>
          <option v-for="level in levels" :key="level" :value="level">{{ level }}</option>
        </select>
      </div>

      <div class="form-group" v-if="selectedConfidence">
        <label for="confidence-notes">
          {{ t('confidence.notes') }}
        </label>
        <textarea
          id="confidence-notes"
          v-model="notes"
          :placeholder="t('confidence.notesPlaceholder')"
          rows="4"
          class="notes-textarea"
        ></textarea>
        <p class="hint">{{ t('confidence.notesHint') }}</p>
      </div>

      <div class="modal-actions">
        <button @click="$emit('close')" class="btn-secondary">{{ t('common.cancel') }}</button>
        <button 
          @click="apply" 
          class="btn-primary" 
          :disabled="!selectedConfidence"
        >
          {{ t('confidence.apply') }}
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
  currentConfidence: String,
  levels: {
    type: Array,
    default: () => ['Confirmed', 'Suspected', 'Tentative', 'False Positive']
  }
})

const emit = defineEmits(['close', 'apply'])

const selectedConfidence = ref('')
const notes = ref('')

// Reset when modal opens/closes
watch(() => props.show, (isShown) => {
  if (isShown) {
    selectedConfidence.value = props.currentConfidence || ''
    notes.value = ''
  }
})

function apply() {
  if (!selectedConfidence.value) return
  
  emit('apply', {
    confidence: selectedConfidence.value,
    notes: notes.value.trim()
  })
  emit('close')
}
</script>

<style scoped>
.confidence-modal {
  display: flex;
  flex-direction: column;
  gap: 20px;
  min-width: 400px;
}

.current-confidence {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: var(--surface-secondary);
  border-radius: 6px;
}

.current-confidence label {
  font-weight: 500;
  color: var(--text-secondary);
}

.confidence-value {
  font-weight: 600;
  color: var(--text);
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

.confidence-select {
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface);
  color: var(--text);
  font-size: 14px;
  font-family: inherit;
}

.confidence-select:focus {
  outline: none;
  border-color: var(--primary);
}

.notes-textarea {
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface);
  color: var(--text);
  font-size: 14px;
  font-family: inherit;
  resize: vertical;
}

.notes-textarea:focus {
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
</style>
