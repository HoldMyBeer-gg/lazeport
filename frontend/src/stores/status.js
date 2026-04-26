import { reactive } from 'vue'

export const status = reactive({ text: '', type: 'info' })

let _timer = null

export function setStatus(text, type = 'info') {
  clearTimeout(_timer)
  status.text = text
  status.type = type
  if (type === 'success') {
    _timer = setTimeout(clearStatus, 4000)
  }
}

export function clearStatus() {
  clearTimeout(_timer)
  status.text = ''
  status.type = 'info'
}
