<script setup>
import { ref, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { request } from '../services/api'
import { showConfirm } from '../composables/useConfirm'

const { t } = useI18n()

const props = defineProps({
  entityType: { type: String, required: true },
  entityId:   { type: String, required: true },
  readonly:   { type: Boolean, default: false },
})

const emit = defineEmits(['tag-click', 'tags-changed'])

const tags = ref([])
const query = ref('')
const suggestions = ref([])
const showDropdown = ref(false)
const loading = ref(false)

let debounceTimer = null

async function loadTags() {
  if (!props.entityId) return
  try {
    tags.value = await request(`/api/admin/tags/entity/${props.entityType}/${props.entityId}`)
  } catch {
    tags.value = []
  }
}

async function fetchSuggestions() {
  const q = query.value.trim()
  if (!q) {
    suggestions.value = []
    showDropdown.value = false
    return
  }
  try {
    const all = await request(`/api/admin/tags?query=${encodeURIComponent(q)}`)
    // Exclude already-assigned tags
    const assignedIds = new Set(tags.value.map(t => t.id))
    suggestions.value = all.filter(t => !assignedIds.has(t.id))
    showDropdown.value = suggestions.value.length > 0 || q.length > 0
  } catch {
    suggestions.value = []
  }
}

function onInput() {
  clearTimeout(debounceTimer)
  debounceTimer = setTimeout(fetchSuggestions, 200)
}

function isValidTagName(name) {
  return /^[a-zA-Z0-9 .]+$/.test(name) && name.length <= 50
}

async function assignTag(tagName) {
  const name = (tagName || query.value).trim()
  if (!name || !isValidTagName(name)) return
  loading.value = true
  try {
    await request('/api/admin/tags/assign', {
      method: 'POST',
      body: JSON.stringify({
        tag_name: name,
        entity_type: props.entityType,
        entity_id: props.entityId,
      }),
    })
    query.value = ''
    suggestions.value = []
    showDropdown.value = false
    await loadTags()
    emit('tags-changed')
  } catch (e) {
    console.error('Failed to assign tag:', e)
  } finally {
    loading.value = false
  }
}

async function removeTag(tag) {
  const ok = await showConfirm({ message: t('common.removeTagConfirm', { name: tag.name }) })
  if (!ok) return
  loading.value = true
  try {
    await request('/api/admin/tags/assign', {
      method: 'DELETE',
      body: JSON.stringify({
        tag_id: tag.id,
        entity_type: props.entityType,
        entity_id: props.entityId,
      }),
    })
    await loadTags()
    emit('tags-changed')
  } catch (e) {
    console.error('Failed to remove tag:', e)
  } finally {
    loading.value = false
  }
}

function onKeydown(e) {
  if (e.key === 'Enter') {
    e.preventDefault()
    assignTag()
  } else if (e.key === 'Escape') {
    showDropdown.value = false
  }
}

function onBlur() {
  // Delay to allow click on suggestion
  setTimeout(() => { showDropdown.value = false }, 150)
}

function filterInput(e) {
  // Only allow alphanumeric, spaces, and periods
  const char = e.data
  if (char && !/^[a-zA-Z0-9 .]$/.test(char)) {
    query.value = query.value.replace(/[^a-zA-Z0-9 .]/g, '')
  }
}

watch(() => props.entityId, () => { loadTags() })

onMounted(loadTags)
</script>

<template>
  <div class="tag-input-wrapper">
    <div class="tag-pills">
      <span v-for="tag in tags" :key="tag.id" class="tag-pill">
        <span class="tag-name" @click.stop="emit('tag-click', tag.name)">{{ tag.name }}</span>
        <button
          v-if="!readonly"
          class="tag-remove"
          @click.stop="removeTag(tag)"
          :disabled="loading"
          :aria-label="t('tagInput.removeTag', { name: tag.name })"
        >&times;</button>
      </span>
      <div v-if="!readonly" class="tag-input-container">
        <input
          v-model="query"
          @input="onInput"
          @keydown="onKeydown"
          @focus="fetchSuggestions"
          @blur="onBlur"
          @beforeinput="filterInput"
          :placeholder="t('tagInput.placeholder')"
          class="tag-input"
          :disabled="loading"
          :aria-label="t('tagInput.ariaLabel')"
        />
        <div v-if="showDropdown" class="tag-dropdown">
          <div
            v-for="s in suggestions"
            :key="s.id"
            class="tag-suggestion"
            @mousedown.prevent="assignTag(s.name)"
          >
            {{ s.name }}
          </div>
          <div
            v-if="query.trim() && isValidTagName(query.trim()) && !suggestions.find(s => s.name.toLowerCase() === query.trim().toLowerCase())"
            class="tag-suggestion tag-suggestion-new"
            @mousedown.prevent="assignTag()"
          >
            {{ t('tagInput.createTag', { name: query.trim() }) }}
          </div>
          <div v-if="!suggestions.length && query.trim() && !isValidTagName(query.trim())" class="tag-hint">
            {{ t('tagInput.validationHint') }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tag-input-wrapper {
  position: relative;
}
.tag-pills {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px;
  min-height: 28px;
}
.tag-pill {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 0.8rem;
  background: var(--primary);
  color: var(--on-primary);
  white-space: nowrap;
  line-height: 1.4;
}
.tag-name {
  cursor: pointer;
  border-radius: 4px;
  transition: opacity 0.15s;
}
.tag-name:hover {
  opacity: 0.8;
  text-decoration: underline;
}
.tag-remove {
  all: unset;
  cursor: pointer;
  margin-left: 2px;
  font-size: 0.9rem;
  line-height: 1;
  opacity: 0.7;
  color: inherit;
}
.tag-remove:hover {
  opacity: 1;
}
.tag-input-container {
  position: relative;
  flex: 1;
  min-width: 100px;
}
.tag-input {
  all: unset;
  width: 100%;
  font-size: 0.85rem;
  padding: 2px 4px;
  color: var(--text-input);
  box-sizing: border-box;
}
.tag-input::placeholder {
  color: var(--text-muted);
}
.tag-dropdown {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  min-width: 180px;
  max-height: 200px;
  overflow-y: auto;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  z-index: 100;
  margin-top: 4px;
}
.tag-suggestion {
  padding: 6px 10px;
  cursor: pointer;
  font-size: 0.85rem;
  color: var(--text-input);
}
.tag-suggestion:hover {
  background: var(--bg-hover-solid);
}
.tag-suggestion-new {
  color: var(--primary);
  border-top: 1px solid var(--border);
}
.tag-hint {
  padding: 6px 10px;
  font-size: 0.8rem;
  color: var(--text-muted);
}
</style>
