<script setup>
import { ref, watch, computed, onMounted, nextTick } from 'vue'
import { request } from '../services/api'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps({
  modelValue: { type: String, default: '' },
  placeholder: { type: String, default: '' },
})

const emit = defineEmits(['update:modelValue', 'close'])

const inputRef = ref(null)

const inputValue = ref('')
const suggestions = ref([])
const showDropdown = ref(false)
const loading = ref(false)
const focusedIndex = ref(-1)

let debounceTimer = null

const placeholderText = computed(() => props.placeholder || t('tagFilterPicker.placeholder'))

watch(() => props.modelValue, (v) => {
  if (v && !inputValue.value) inputValue.value = v
  if (!v) inputValue.value = ''
}, { immediate: true })

async function fetchSuggestions() {
  const q = inputValue.value.trim()
  if (!q) {
    suggestions.value = []
    showDropdown.value = false
    return
  }
  loading.value = true
  try {
    const list = await request(`/api/admin/tags?query=${encodeURIComponent(q)}`)
    suggestions.value = (list || []).slice(0, 50)
    focusedIndex.value = -1
    showDropdown.value = true
  } catch {
    suggestions.value = []
  } finally {
    loading.value = false
  }
}

function onInput() {
  emit('update:modelValue', '')
  clearTimeout(debounceTimer)
  debounceTimer = setTimeout(fetchSuggestions, 200)
}

function selectTag(tag) {
  const name = typeof tag === 'string' ? tag : (tag && tag.name)
  if (name) {
    emit('update:modelValue', name)
    inputValue.value = name
  }
  showDropdown.value = false
  suggestions.value = []
  emit('close')
}

function clearSelection() {
  emit('update:modelValue', '')
  inputValue.value = ''
  showDropdown.value = false
  suggestions.value = []
  emit('close')
}

function onFocus() {
  if (inputValue.value.trim()) fetchSuggestions()
}

function onBlur() {
  setTimeout(() => {
    showDropdown.value = false
    focusedIndex.value = -1
  }, 150)
}

function onKeydown(e) {
  if (e.key === 'Escape') {
    e.preventDefault()
    showDropdown.value = false
    focusedIndex.value = -1
    emit('close')
    return
  }
  if (!showDropdown.value || !suggestions.value.length) return
  if (e.key === 'ArrowDown') {
    e.preventDefault()
    focusedIndex.value = Math.min(focusedIndex.value + 1, suggestions.value.length - 1)
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    focusedIndex.value = Math.max(focusedIndex.value - 1, -1)
  } else if (e.key === 'Enter' && focusedIndex.value >= 0 && suggestions.value[focusedIndex.value]) {
    e.preventDefault()
    selectTag(suggestions.value[focusedIndex.value])
  }
}

onMounted(() => {
  nextTick(() => inputRef.value?.focus())
})
</script>

<template>
  <div class="tag-filter-picker">
    <div class="tag-filter-picker-input-wrap">
      <input
        ref="inputRef"
        v-model="inputValue"
        type="text"
        class="tag-filter-picker-input"
        :placeholder="placeholderText"
        :aria-label="t('tagFilterPicker.ariaLabel')"
        @input="onInput"
        @focus="onFocus"
        @blur="onBlur"
        @keydown="onKeydown"
      />
      <button
        v-if="modelValue"
        type="button"
        class="tag-filter-picker-clear"
        :aria-label="t('tagFilterPicker.clear')"
        @mousedown.prevent="clearSelection"
      >
        ×
      </button>
    </div>
    <div v-if="showDropdown" class="tag-filter-picker-dropdown">
      <button
        type="button"
        class="tag-filter-picker-option tag-filter-picker-option-all"
        @mousedown.prevent="clearSelection"
      >
        {{ t('tagFilterPicker.allTags') }}
      </button>
      <div
        v-for="(tag, i) in suggestions"
        :key="tag.id"
        :class="['tag-filter-picker-option', { 'tag-filter-picker-option-focused': i === focusedIndex }]"
        @mousedown.prevent="selectTag(tag)"
      >
        {{ tag.name }}
      </div>
      <div v-if="loading" class="tag-filter-picker-loading">{{ t('common.loading') }}</div>
      <div v-if="!loading && inputValue.trim() && !suggestions.length" class="tag-filter-picker-empty">
        {{ t('tagFilterPicker.noMatches') }}
      </div>
    </div>
  </div>
</template>

<style scoped>
.tag-filter-picker {
  position: relative;
  min-width: 160px;
}

.tag-filter-picker-input-wrap {
  display: flex;
  align-items: center;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-input);
}

.tag-filter-picker-input {
  flex: 1;
  min-width: 0;
  padding: 6px 8px;
  font-size: 0.9rem;
  color: var(--text-input);
  background: transparent;
  border: none;
  outline: none;
}

.tag-filter-picker-input::placeholder {
  color: var(--text-muted);
}

.tag-filter-picker-clear {
  flex-shrink: 0;
  padding: 2px 8px;
  font-size: 1.1rem;
  line-height: 1;
  color: var(--text-muted);
  background: none;
  border: none;
  cursor: pointer;
}

.tag-filter-picker-clear:hover {
  color: var(--text-primary);
}

.tag-filter-picker-dropdown {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  margin-top: 4px;
  max-height: 240px;
  overflow-y: auto;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  z-index: 100;
}

.tag-filter-picker-option,
.tag-filter-picker-option-all {
  display: block;
  width: 100%;
  padding: 8px 10px;
  font-size: 0.9rem;
  text-align: left;
  color: var(--text-primary);
  background: none;
  border: none;
  cursor: pointer;
}

.tag-filter-picker-option:hover,
.tag-filter-picker-option-focused,
.tag-filter-picker-option-all:hover {
  background: var(--bg-hover-solid);
}

.tag-filter-picker-option-all {
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
}

.tag-filter-picker-loading,
.tag-filter-picker-empty {
  padding: 8px 10px;
  font-size: 0.85rem;
  color: var(--text-muted);
}
</style>
