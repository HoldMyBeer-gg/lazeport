<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'

const props = defineProps({
  show: { type: Boolean, default: true },
  title: { type: String, default: '' },
  wide: { type: Boolean, default: false },
  extraWide: { type: Boolean, default: false },
  closeOnBackdrop: { type: Boolean, default: true },
})
const emit = defineEmits(['close'])

const boxRef = ref(null)

function onKeydown(e) {
  if (e.key === 'Escape') {
    emit('close')
    return
  }
  if (e.key === 'Tab' && boxRef.value) {
    const focusable = boxRef.value.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    if (!focusable.length) return
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }
}

onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  nextTick(() => {
    const first = boxRef.value?.querySelector(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    first?.focus()
  })
})

onUnmounted(() => {
  document.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <div v-if="show" class="modal-overlay" @click.self="closeOnBackdrop && emit('close')" role="dialog" aria-modal="true" :aria-label="title">
    <div ref="boxRef" :class="['modal-box', wide && 'modal-wide', extraWide && 'modal-extra-wide']">
      <h3 v-if="title">{{ title }}</h3>
      <slot />
    </div>
  </div>
</template>
