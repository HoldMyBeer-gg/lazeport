import { reactive } from 'vue'

/**
 * Global confirm dialog state & helpers.
 *
 * Usage in any component:
 *   import { showConfirm } from '../composables/useConfirm'
 *   const ok = await showConfirm({ message: 'Delete this item?' })
 *   if (!ok) return
 *
 * The <ConfirmDialog /> component (mounted once in DashboardLayout)
 * watches this state and renders the styled modal.
 */

export const confirmState = reactive({
  visible: false,
  title: '',
  message: '',
  confirmLabel: '',
  cancelLabel: '',
  danger: false,
  extraAction: null,
  _resolve: null,
})

/**
 * Show a styled confirmation dialog. Returns a Promise<boolean>.
 *
 * @param {Object} opts
 * @param {string} opts.message - Main message to display
 * @param {string} [opts.title] - Optional dialog title (defaults to "Confirm")
 * @param {string} [opts.confirmLabel] - Confirm button text (defaults to "Confirm")
 * @param {string} [opts.cancelLabel] - Cancel button text (defaults to "Cancel")
 * @param {boolean} [opts.danger] - If true, confirm button uses danger styling
 * @param {{ label: string, handler: Function }|null} [opts.extraAction] - Optional extra button (e.g. export backup)
 */
export function showConfirm({
  message,
  title = '',
  confirmLabel = '',
  cancelLabel = '',
  danger = false,
  extraAction = null,
} = {}) {
  return new Promise((resolve) => {
    confirmState.visible = true
    confirmState.title = title
    confirmState.message = message
    confirmState.confirmLabel = confirmLabel
    confirmState.cancelLabel = cancelLabel
    confirmState.danger = danger
    confirmState.extraAction = extraAction
    confirmState._resolve = resolve
  })
}

export function resolveConfirm(value) {
  if (confirmState._resolve) {
    confirmState._resolve(value)
    confirmState._resolve = null
  }
  confirmState.visible = false
  confirmState.extraAction = null
}
