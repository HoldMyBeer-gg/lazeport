import { ref, onMounted, onUnmounted } from 'vue'

export const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational']

const SEV_VAR_MAP = {
  Critical: '--sev-critical-solid',
  High: '--sev-high-solid',
  Medium: '--sev-medium-solid',
  Low: '--sev-low-solid',
  Informational: '--sev-info-solid',
}

function readSevColors() {
  const style = getComputedStyle(document.documentElement)
  const out = {}
  for (const [name, varName] of Object.entries(SEV_VAR_MAP)) {
    out[name] = style.getPropertyValue(varName).trim()
  }
  return out
}

/**
 * Returns a reactive `sevColors` map (severity name → resolved hex) that
 * automatically updates when the app theme changes.
 *
 * Colors are read from CSS variables (`--sev-*-solid`) defined in style.css,
 * which is the single source of truth for severity colors across all charts
 * and UI components.
 */
export function useSeverityColors() {
  const sevColors = ref(readSevColors())

  let observer

  onMounted(() => {
    // Re-read now that the component is in the DOM (catches any theme applied after module load)
    sevColors.value = readSevColors()

    observer = new MutationObserver(() => {
      sevColors.value = readSevColors()
    })
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    })
  })

  onUnmounted(() => observer?.disconnect())

  return { sevColors, SEV_ORDER }
}
