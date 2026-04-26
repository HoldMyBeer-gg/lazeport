<script setup>
import { onMounted, onUnmounted, ref, reactive, watch, computed, nextTick, inject } from 'vue'
import { useI18n } from 'vue-i18n'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { request } from '../services/api'
import { addCsrfHeader } from '../utils/csrf'
import { useRoute, useRouter } from 'vue-router'

const { t, locale } = useI18n()

/** Resolve error message for display: use i18n when API returns code, else message or fallback */
function formatApiError(e, fallbackKey) {
  return (e?.code ? t(`errors.${e.code}`) : null) || e?.message || t(fallbackKey)
}
import { setStatus } from '../stores/status'
import { showConfirm } from '../composables/useConfirm'
import { addBackgroundTask, finishBackgroundTask } from '../stores/backgroundTasks'
import { registerCompletionCallback, unregisterCompletionCallback, acknowledgeTask, nudge, trackTaskIds, getGenerationTasks } from '../stores/generationTaskStore'
import { getSessionUser } from '../services/api'
import Modal from '../components/Modal.vue'
import FindingWorkflow from '../components/FindingWorkflow.vue'
import TagInput from '../components/TagInput.vue'
import CvssCalculator from '../components/CvssCalculator.vue'
import SeverityOverrideModal from '../components/SeverityOverrideModal.vue'
import ConfidenceModal from '../components/ConfidenceModal.vue'

const route = useRoute()
const router = useRouter()
const reportId = route.params.id

/* ── Burp Import Workflow (session mode, survives navigation) ── */
const showWorkflow = ref(false)
const workflowSessionId = ref(null)
const workflowTasks = ref([])
const workflowFileName = ref('')

// Only close modals when actually navigating away from this report's findings page
watch(() => route.fullPath, (newPath) => {
  const onThisFindingsPage = newPath.includes(`/reports/${reportId}/findings`)
  if (!onThisFindingsPage) forceCloseModals()
})


const findings = ref([])
const findingTemplates = ref([])
const masterTemplates = ref([])
const masterTemplate = ref('')
const verificationLog = ref([])
const report = ref(null)
const client = ref(null)
const application = ref(null)
const userOrgRole = ref('readonly')

/** True if user can edit this report. Session override: readonly never sees edit UI regardless of API. */
const canEdit = computed(() => {
  if (userOrgRole.value === 'readonly') return false
  return report.value?.can_edit === true
})

// Summaries state
const summaries = ref({
  executive: '',
  technical: '',
  recommendations: ''
})
const showSummariesModal = ref(false)
const generatingSummaries = ref(false)
const consolidatingFindings = ref(false)
const summariesStale = ref(false)
const showStalePopover = ref(false)

const form = ref({
  title: '',
  content_json: '{}',
  notes: '',
  template_id: '',
})
const originalFormState = ref(null) // Track for unsaved changes
const useAi = ref(true)
const selfCheck = ref(false)
const severityOverride = ref('')
const severityReason = ref('')
const provider = ref('')
const providers = ref({ openai: true, ollama: true, openai_compatible: true })
const model = ref('')
const baseUrl = ref('')
const modelOptions = ref([])
const editId = ref(null)
const editForm = ref({
  title: '',
  template_id: '',
  sections: {}, // { "Vulnerability Summary": "...", "Remediation": "...", etc. }
  validation_guidance: '',
  show_validation: false,
})
const hasUnsavedEditChanges = ref(false)

/* ── Vision model state ── */
const showAdvanced = ref(false)
const showLlmConfig = ref(false)  // Collapsed by default
const visionModel = ref('')
const processingImage = ref(false)
const visionModels = ref([])
const ollamaVisionModels = ref([])

/* ── Provider presets (mirrors backend) ── */
const PROVIDER_PRESETS = {
  openai:      { baseUrl: '' },
  anthropic:   { baseUrl: 'https://api.anthropic.com/v1/' },
  gemini:      { baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai/' },
  groq:        { baseUrl: 'https://api.groq.com/openai/v1' },
  together:    { baseUrl: 'https://api.together.xyz/v1' },
  deepseek:    { baseUrl: 'https://api.deepseek.com/v1' },
  mistral:     { baseUrl: 'https://api.mistral.ai/v1' },
  ollama:      { baseUrl: 'http://localhost:11434' },
  openai_compatible: { baseUrl: '' },
}

/* ── Provider-specific settings cache ── */
const providerSettings = ref({})
let lastProvider_rf = ''

/* ── Legacy image processing variables (still needed for handlePaste) ── */
const imageQueue = ref([])
const activeImageTasks = ref(0)
const maxConcurrentVisionTasks = ref(2)
const localStatus = ref('')
const localStatusType = ref('')

/* ── Drag & Drop State ── */
const isDragging = ref(false)
const dragCounter = ref(0)
const showImageConfirm = ref(false)
const showDocumentConfirm = ref(false)
const pendingDocumentFile = ref(null)
const pendingDocumentCursorPos = ref(null)
const pendingImageFile = ref(null)
const pendingImageCursorPos = ref(null)
const showLlmRequiredModal = ref(false)
const notesTextareaRef = ref(null)

/* ── File Upload Queue ── */
const fileQueue = ref([])
const supportedFileTypes = {
  image: ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'],
  document: ['.pdf', '.docx', '.doc'],
  data: ['.xml', '.json', '.sarif', '.txt', '.html', '.htm',
         '.md', '.markdown', '.csv', '.tsv', '.log', '.yaml', '.yml',
         '.toml', '.ini', '.cfg', '.conf', '.env', '.sh', '.bash',
         '.py', '.js', '.ts', '.rb', '.go', '.rs', '.java', '.c', '.cpp',
         '.h', '.hpp', '.cs', '.swift', '.kt', '.sql', '.r', '.pl',
         '.lua', '.diff', '.patch', '.rst', '.tex', '.adoc', '.nessus']
}

/* ── Task queue: local tasks use background store so TaskQueue (in layout) shows them ── */
function addTask(title, type = 'info') {
  return addBackgroundTask({
    reportId: reportId || null,
    type: type === 'error' ? 'error' : 'info',
    title: title || t('findings.processing'),
  })
}

function updateTask(taskId, updates) {
  if (updates.status === 'completed' || updates.status === 'error') {
    finishBackgroundTask(taskId, {
      error: updates.status === 'error' ? (updates.title || t('findings.genericError')) : null,
      title: updates.title,
    })
  }
}

async function closeWorkflow() {
  showWorkflow.value = false
  workflowSessionId.value = null
  workflowTasks.value = []
  workflowFileName.value = ''
}

function onWorkflowFinished() {
  closeWorkflow()
  loadFindings()
  summariesStale.value = true
}

// Force close any stuck modals (state only - no DOM manipulation to avoid hiding main content)
function forceCloseModals() {
  showWorkflow.value = false
  showSummariesModal.value = false
  showReview.value = false
  showJiraModal.value = false
  workflowSessionId.value = null
  workflowTasks.value = []
  workflowFileName.value = ''
  pendingImageFile.value = null
  pendingImageCursorPos.value = null
}

/* ── Drag & Drop Handlers ── */
function handleDragOver(e) {
  e.preventDefault()
  e.dataTransfer.dropEffect = 'copy'
}

function handleDragEnter(e) {
  e.preventDefault()
  dragCounter.value++
  if (dragCounter.value === 1) {
    isDragging.value = true
  }
}

function handleDragLeave(e) {
  e.preventDefault()
  dragCounter.value--
  if (dragCounter.value === 0) {
    isDragging.value = false
  }
}

async function handleDrop(e) {
  e.preventDefault()
  isDragging.value = false
  dragCounter.value = 0
  
  const files = Array.from(e.dataTransfer?.files || [])
  if (!files.length) {
    setStatus(t('findings.uploadFailed'), 'error')
    return
  }
  
  const textarea = notesTextareaRef.value || e.currentTarget?.querySelector('textarea')
  if (!textarea) {
    setStatus(t('findings.uploadFailed'), 'error')
    return
  }
  
  const cursorPos = Number.isInteger(textarea.selectionStart) ? textarea.selectionStart : form.value.notes.length
  
  for (const file of files) {
    try {
      await processDroppedFile(file, cursorPos)
    } catch (error) {
      setStatus(t('findings.failedProcessFile', { message: error?.message || t('findings.unknownError') }), 'error')
    }
  }
}

async function processDroppedFile(file, cursorPos) {
  const fileExt = '.' + file.name.split('.').pop().toLowerCase()
  const fileType = getFileType(fileExt)
  
  switch (fileType) {
    case 'image':
      pendingImageFile.value = file
      pendingImageCursorPos.value = cursorPos
      showImageConfirm.value = true
      break
      
    case 'data':
      if (fileExt === '.xml') {
        await processXmlFile(file)
      } else if (fileExt === '.nessus') {
        await processNessusFile(file)
      } else if (fileExt === '.json' || fileExt === '.sarif') {
        await processJsonFile(file, cursorPos)
      } else if (fileExt === '.csv' || fileExt === '.tsv') {
        await processCsvFile(file)
      } else if (fileExt === '.html' || fileExt === '.htm') {
        await processHtmlFile(file, cursorPos)
      } else {
        await processTextFile(file, cursorPos)
      }
      break
      
    case 'document':
      if (fileExt === '.pdf') {
        await processPdfFile(file, cursorPos)
      } else {
        pendingDocumentFile.value = file
        pendingDocumentCursorPos.value = cursorPos
        showDocumentConfirm.value = true
      }
      break
      
    default:
      if (isLikelyTextFile(file)) {
        await processTextFile(file, cursorPos)
      } else {
        const taskId = addTask(t('findings.unsupportedFileType', { ext: fileExt }), 'error')
        finishBackgroundTask(taskId, {
          error: t('findings.unsupportedFileType', { ext: fileExt }),
        })
      }
  }
}

function getFileType(extension) {
  for (const [type, extensions] of Object.entries(supportedFileTypes)) {
    if (extensions.includes(extension)) {
      return type
    }
  }
  return 'unknown'
}

function isLikelyTextFile(file) {
  if (file.type && file.type.startsWith('text/')) return true
  if (file.type === 'application/json' || file.type === 'application/xml'
      || file.type === 'application/x-yaml' || file.type === 'application/toml') return true
  return false
}

async function processImageFile(file, cursorPos) {
  // Simple image processing - add inline to report without confirmation
  const taskId = addTask(t('findings.addingImage'), 'info')  
  try {
    await addInlineImage(file, cursorPos)
    updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.imageAdded') })
  } catch (error) {
    updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedAddImage', { message: error.message }) })
  }
}

/** @param {'ai'|'ocr'|'insert'} mode - ai = vision API, ocr = local Tesseract, insert = embed image only */
async function confirmImageProcessing(mode) {
  const file = pendingImageFile.value
  const cursorPos = pendingImageCursorPos.value

  if (mode === 'ai') {
    const visionProvider = getVisionProvider(visionModel.value)
    if (!visionModel.value || !visionProvider) {
      showLlmRequiredModal.value = true
      await loadVisionModels()
      return
    }
    const taskId = addTask(t('findings.processingImageAi'), 'info')
    try {
      await processImageWithAI(file, cursorPos)
      updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.imageProcessedAi') })
    } catch (error) {
      updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedProcessImage', { message: error.message }) })
    }
  } else if (mode === 'ocr') {
    const taskId = addTask(t('findings.processingImageOcr'), 'info')
    try {
      await processImageWithOCR(file, cursorPos)
      updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.imageProcessedOcr') })
    } catch (error) {
      updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedProcessImage', { message: error.message }) })
    }
  } else {
    // insert: include inline in report
    const taskId = addTask(t('findings.addingImage'), 'info')
    try {
      await addInlineImage(file, cursorPos)
      updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.imageAdded') })
    } catch (error) {
      updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedAddImage', { message: error.message }) })
    }
  }

  showImageConfirm.value = false
  pendingImageFile.value = null
  pendingImageCursorPos.value = null
}

async function confirmDocumentProcessing(useAI) {
  const file = pendingDocumentFile.value
  const cursorPos = pendingDocumentCursorPos.value
  if (!file) return

  if (useAI) {
    const taskId = addTask(t('findings.processingPdfAi'), 'info')
    try {
      await processDocumentFile(file, cursorPos)
      updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.pdfProcessedAi') })
    } catch (error) {
      updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedProcessPdf', { message: error.message }) })
    }
  } else {
    await processDocumentFile(file, cursorPos)
  }

  showDocumentConfirm.value = false
  pendingDocumentFile.value = null
  pendingDocumentCursorPos.value = null
}

async function processImageWithAI(file, cursorPos) {
  const base64 = await fileToBase64(file)
  const base64Data = base64.split(',')[1]
  const visionProvider = getVisionProvider(visionModel.value)
  const llm = getCurrentLlmSettingsForRequest()

  // Store cursor position — needed when async callback fires after navigation
  pendingVisionCursorPos.value = cursorPos

  const data = await request('/api/vision/extract-text/async', {
    method: 'POST',
    body: JSON.stringify({
      image_base64: base64Data,
      image_mime_type: file.type || 'image/png',
      vision_model: visionModel.value,
      provider: visionProvider,
      base_url: visionProvider === 'ollama' ? (baseUrl.value || null) : null,
      llm_timeout: llm.timeout || null,
      sampling_params: llm.samplingParams || null,
      report_id: reportId,
    })
  })
  const taskId = data.task_id
  nudge()  // Immediate poll + reset to fast-poll mode
  registerCompletionCallback(taskId, (task) => {
    if (task.status === 'completed' && task.result_json) {
      try {
        const result = JSON.parse(task.result_json)
        const extractedText = result.text || ''
        if (extractedText.trim()) {
          insertTextAtPosition(extractedText, pendingVisionCursorPos.value)
        }
      } catch {}
    }
    pendingVisionCursorPos.value = null
    acknowledgeTask(taskId)
  })
}

async function processImageWithOCR(file, cursorPos) {
  const base64 = await fileToBase64(file)
  const base64Data = base64.split(',')[1]

  const result = await request('/api/vision/extract-text', {
    method: 'POST',
    body: JSON.stringify({
      image_base64: base64Data,
      image_mime_type: file.type || 'image/png',
      use_ocr: true,
    })
  })

  const extractedText = result.text || ''
  if (extractedText.trim()) {
    insertTextAtPosition(extractedText, cursorPos)
  }
}

async function addInlineImage(file, cursorPos) {
  // Convert image to base64 and add to notes
  const reader = new FileReader()
  
  return new Promise((resolve, reject) => {
    reader.onload = (e) => {
      const base64 = e.target.result
      const imageText = `\n\n[IMAGE: ${file.name}]\n${base64}\n\n`
      insertTextAtPosition(imageText, cursorPos)
      resolve()
    }
    
    reader.onerror = () => reject(new Error(t('findings.failedReadImage')))
    reader.readAsDataURL(file)
  })
}

async function processXmlFile(file) {
  const taskId = addTask(t('findings.parsingBurpFile'), 'info')
  try {
    const formData = new FormData()
    formData.append('file', file)
    const url = `${import.meta.env.VITE_API_BASE || ''}/api/admin/findings/upload-burp${reportId ? `?report_id=${reportId}` : ''}`
    const response = await fetch(url, { method: 'POST', credentials: 'include', body: formData })
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: t('findings.uploadFailed') }))
      throw new Error(err.detail)
    }
    const data = await response.json()
    
    // Handle different scenarios with appropriate messaging
    if (data.already_imported && data.completed_count > 0 && data.pending_count === 0) {
      // All tasks from this import are already completed
      updateTask(taskId, { 
        status: 'completed', 
        type: 'info', 
        title: t('findings.allFindingsAlreadyGenerated', { count: data.completed_count, file: file.name }), 
        dismissAfterMs: 6000 
      })
      return  // Don't open workflow modal
    }
    
    updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.foundFromBurp', { count: data.total }), dismissAfterMs: 8000 })
    if (data.findings && data.findings.length > 0) {
      // Close any existing workflow to avoid confusion with old imports
      if (showWorkflow.value) {
        showWorkflow.value = false
        await new Promise(resolve => setTimeout(resolve, 100))
      }
      
      workflowSessionId.value = data.session_id || null
      workflowFileName.value = file.name || ''
      
      // If this is a resume (already_imported=true), load actual session tasks
      // Otherwise, use the freshly parsed findings from the upload response
      if (data.already_imported && data.session_id && reportId) {
        const queueData = await request(`/api/admin/reports/${reportId}/import-queue`)
        const sess = queueData.sessions?.find((s) => s.session_id === data.session_id)
        workflowTasks.value = sess?.tasks || data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
      } else {
        workflowTasks.value = data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
      }
      showWorkflow.value = true
    }
  } catch (error) {
    updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedProcessFile', { message: error.message }) })
  }
}

async function processNessusFile(file) {
  const taskId = addTask(t('findings.parsingNessusFile'), 'info')
  try {
    const formData = new FormData()
    formData.append('file', file)
    const url = `${import.meta.env.VITE_API_BASE || ''}/api/admin/findings/upload-nessus${reportId ? `?report_id=${reportId}` : ''}`
    const response = await fetch(url, { method: 'POST', credentials: 'include', body: formData })
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: t('findings.uploadFailed') }))
      throw new Error(err.detail)
    }
    const data = await response.json()

    if (data.already_imported && data.completed_count > 0 && data.pending_count === 0) {
      updateTask(taskId, {
        status: 'completed',
        type: 'info',
        title: t('findings.allFindingsAlreadyGenerated', { count: data.completed_count, file: file.name }),
        dismissAfterMs: 6000,
      })
      return
    }

    updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.foundFromNessus', { count: data.total }), dismissAfterMs: 8000 })
    if (!data.findings || data.findings.length === 0) {
      setStatus(t('findings.foundFromNessus', { count: data.total || 0 }), 'info')
      return
    }

    if (showWorkflow.value) {
      showWorkflow.value = false
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    workflowSessionId.value = data.session_id || null
    workflowFileName.value = file.name || ''

    if (data.already_imported && data.session_id && reportId) {
      const queueData = await request(`/api/admin/reports/${reportId}/import-queue`)
      const sess = queueData.sessions?.find((s) => s.session_id === data.session_id)
      workflowTasks.value = sess?.tasks || data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
    } else {
      workflowTasks.value = data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
    }
    showWorkflow.value = true
  } catch (error) {
    updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedProcessFile', { message: error.message }) })
  }
}

async function processJsonFile(file, cursorPos) {
  const reader = new FileReader()
  
  return new Promise((resolve, reject) => {
    reader.onload = async (e) => {
      try {
        const jsonText = e.target.result
        const jsonData = JSON.parse(jsonText)
        
        // Check if this is a SARIF file (by schema or runs array)
        const isSarif = (jsonData.$schema && jsonData.$schema.includes('sarif')) || 
                       (Array.isArray(jsonData.runs) && jsonData.version)
        
        if (isSarif) {
          // Route to SARIF import workflow (like Burp XML)
          await processSarifFile(file, jsonData)
          resolve()
        } else {
          // Regular JSON - insert into notes
          const formattedJson = JSON.stringify(jsonData, null, 2)
          const insertText = `\n\nJSON Data from ${file.name}:\n\`\`\`json\n${formattedJson}\n\`\`\`\n\n`
          insertTextAtPosition(insertText, cursorPos)
          resolve()
        }
      } catch (error) {
        reject(new Error(t('findings.invalidJsonFile')))
      }
    }
    
    reader.onerror = () => reject(new Error(t('findings.failedReadJson')))
    reader.readAsText(file)
  })
}

async function processSarifFile(file) {
  const taskId = addTask(t('findings.parsingSarifFile'), 'info')
  try {
    const formData = new FormData()
    formData.append('file', file)
    const url = `${import.meta.env.VITE_API_BASE || ''}/api/admin/findings/upload-sarif${reportId ? `?report_id=${reportId}` : ''}`
    const response = await fetch(url, { method: 'POST', credentials: 'include', body: formData })
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: t('findings.uploadFailed') }))
      throw new Error(err.detail)
    }
    const data = await response.json()
    
    // Handle different scenarios with appropriate messaging
    if (data.already_imported && data.completed_count > 0 && data.pending_count === 0) {
      // All tasks from this import are already completed
      updateTask(taskId, { 
        status: 'completed', 
        type: 'info', 
        title: t('findings.allFindingsAlreadyGenerated', { count: data.completed_count, file: file.name }), 
        dismissAfterMs: 6000 
      })
      return  // Don't open workflow modal
    }
    
    updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.foundFromSarif', { count: data.total }), dismissAfterMs: 8000 })
    if (!data.findings || data.findings.length === 0) {
      setStatus(t('findings.foundFromSarif', { count: data.total || 0 }), 'info')
      return
    }
    if (data.findings && data.findings.length > 0) {
      // Close any existing workflow to avoid confusion with old imports
      if (showWorkflow.value) {
        showWorkflow.value = false
        await new Promise(resolve => setTimeout(resolve, 100))
      }
      
      workflowSessionId.value = data.session_id || null
      workflowFileName.value = file.name || ''
      
      // If this is a resume (already_imported=true), load actual session tasks
      // Otherwise, use the freshly parsed findings from the upload response
      if (data.already_imported && data.session_id && reportId) {
        const queueData = await request(`/api/admin/reports/${reportId}/import-queue`)
        const sess = queueData.sessions?.find((s) => s.session_id === data.session_id)
        workflowTasks.value = sess?.tasks || data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
      } else {
        workflowTasks.value = data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
      }
      showWorkflow.value = true
    }
  } catch (error) {
    updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedProcessFile', { message: error.message }) })
  }
}

async function processCsvFile(file) {
  const taskId = addTask(t('findings.parsingCsvFile'), 'info')
  try {
    const formData = new FormData()
    formData.append('file', file)
    const url = `${import.meta.env.VITE_API_BASE || ''}/api/admin/findings/upload-csv${reportId ? `?report_id=${reportId}` : ''}`
    const response = await fetch(url, { method: 'POST', credentials: 'include', body: formData })
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: t('findings.uploadFailed') }))
      throw new Error(err.detail)
    }
    const data = await response.json()

    if (data.already_imported && data.completed_count > 0 && data.pending_count === 0) {
      updateTask(taskId, {
        status: 'completed',
        type: 'info',
        title: t('findings.allFindingsAlreadyGenerated', { count: data.completed_count, file: file.name }),
        dismissAfterMs: 6000,
      })
      return
    }

    updateTask(taskId, { status: 'completed', type: 'success', title: t('findings.foundFromCsv', { count: data.total }), dismissAfterMs: 8000 })
    if (!data.findings || data.findings.length === 0) {
      setStatus(t('findings.foundFromCsv', { count: data.total || 0 }), 'info')
      return
    }

    if (showWorkflow.value) {
      showWorkflow.value = false
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    workflowSessionId.value = data.session_id || null
    workflowFileName.value = file.name || ''

    if (data.already_imported && data.session_id && reportId) {
      const queueData = await request(`/api/admin/reports/${reportId}/import-queue`)
      const sess = queueData.sessions?.find((s) => s.session_id === data.session_id)
      workflowTasks.value = sess?.tasks || data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
    } else {
      workflowTasks.value = data.findings.map((f, i) => ({ index: i, status: 'pending', finding: f }))
    }
    showWorkflow.value = true
  } catch (error) {
    updateTask(taskId, { status: 'error', type: 'error', title: t('findings.failedProcessFile', { message: error.message }) })
  }
}

async function processTextFile(file, cursorPos) {
  const reader = new FileReader()
  
  return new Promise((resolve, reject) => {
    reader.onload = (e) => {
      const text = e.target.result
      const header = t('findings.contentFromFile', { name: file.name })
      const insertText = `\n\n${header}\n${text}\n\n`
      insertTextAtPosition(insertText, cursorPos)
      resolve()
    }
    
    reader.onerror = () => reject(new Error(t('findings.failedReadText')))
    reader.readAsText(file)
  })
}

async function processHtmlFile(file, cursorPos) {
  const reader = new FileReader()

  return new Promise((resolve, reject) => {
    reader.onload = (e) => {
      try {
        const html = e.target.result
        const doc = new DOMParser().parseFromString(html, 'text/html')
        doc.querySelectorAll('script, style, noscript').forEach(el => el.remove())
        const text = (doc.body?.textContent || '').replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim()
        if (!text) {
          reject(new Error(t('findings.htmlNoText')))
          return
        }
        const header = t('findings.contentFromFile', { name: file.name })
        const insertText = `\n\n${header}\n${text}\n\n`
        insertTextAtPosition(insertText, cursorPos)
        resolve()
      } catch {
        reject(new Error(t('findings.failedReadHtml')))
      }
    }

    reader.onerror = () => reject(new Error(t('findings.failedReadHtml')))
    reader.readAsText(file)
  })
}

const processingPdf = ref(false)

async function processPdfFile(file, cursorPos) {
  processingPdf.value = true
  const taskId = addTask(t('findings.parsingFile', { name: file.name }), 'info')
  try {
    const formData = new FormData()
    formData.append('file', file)

    const result = await request('/api/admin/parse-pdf', {
      method: 'POST',
      body: formData,
      rawBody: true,  // skip JSON.stringify
    })

    if (result.markdown && result.markdown.trim()) {
      const header = `## ${file.name}\n\n`
      const insertText = `\n\n${header}${result.markdown.trim()}\n\n`
      insertTextAtPosition(insertText, cursorPos)
      updateTask(taskId, {
        status: 'completed',
        type: 'success',
        title: t('findings.parsedPages', { name: file.name, pages: result.pages, chars: (result.chars / 1000).toFixed(1) }),
      })
    } else {
      updateTask(taskId, {
        status: 'completed',
        type: 'warning',
        title: t('findings.parsedNoText', { name: file.name }),
      })
      const insertText = `\n\n${t('findings.pdfNoTextInsert', { name: file.name })}\n\n`
      insertTextAtPosition(insertText, cursorPos)
    }
  } catch (error) {
    updateTask(taskId, {
      status: 'error',
      type: 'error',
      title: t('findings.failedParsePdf', { name: file.name, message: error.message || t('findings.unknownError') }),
    })
  } finally {
    processingPdf.value = false
  }
}

async function processDocumentFile(file, cursorPos) {
  // For DOCX/DOC: just add a reference for now
  const insertText = `\n\n${t('findings.documentReferenceInsert', { name: file.name })}\n\n`
  insertTextAtPosition(insertText, cursorPos)
}

function insertTextAtPosition(text, position) {
  const before = form.value.notes.substring(0, position)
  const after = form.value.notes.substring(position)
  form.value.notes = before + text + after
}

/* ── Review modal state ── */
const showReview = ref(false)
const reviewData = ref({})
const reviewTitle = ref('')
const reviewingTaskId = ref(null)  // Track which task opened the review modal for acknowledgement

const regeneratingFindingId = ref(null)
const pendingRegenFindings = reactive(new Set())  // findings with unreviewed regeneration results
const generatingFindingTaskId = ref(null)   // task_id when async generation in flight (locks form)
const pendingVisionCursorPos = ref(null)     // cursor pos stored when vision enqueued

/* ── CVSS calculator modal state ── */
const showCvssCalculator = ref(false)
const cvssEditingFindingId = ref(null)

/* ── Validation Guidance Modal ── */
const showValidationGuidance = ref(false)
const validationGuidance = ref('')
const validationGuidanceFindingTitle = ref('')
const validationGuidanceFinding = ref(null)
const generatingGuidance = ref(false)

/* ── Inline meta editing state ── */
const editingMetaField = ref(null) // { findingId, key, value }
const EDITABLE_META_KEYS = ['Severity', 'CWE', 'OWASP', 'Affected Roles', 'CVSS v3.1', 'Confidence']

/* ── Severity override modal state ── */
const showSeverityOverride = ref(false)
const severityEditingFindingId = ref(null)
const currentEditingSeverity = ref('')

/* ── Confidence modal state ── */
const showConfidenceModal = ref(false)
const confidenceEditingFindingId = ref(null)
const currentEditingConfidence = ref('')
const confidenceLevels = ref(['Confirmed', 'Suspected', 'Tentative', 'False Positive'])

function startEditingMeta(findingId, key, currentValue) {
  if (key === 'CVSS v3.1') {
    openCvssCalculator(findingId)
    return
  }
  if (key === 'Severity') {
    openSeverityOverride(findingId, currentValue)
    return
  }
  if (key === 'Confidence') {
    openConfidenceModal(findingId, currentValue)
    return
  }
  const sentinelValue = 'Not provided in evidence'
  editingMetaField.value = {
    findingId,
    key,
    value: (currentValue === sentinelValue || !currentValue) ? '' : currentValue
  }
}

function openSeverityOverride(findingId, currentSeverity) {
  severityEditingFindingId.value = findingId
  currentEditingSeverity.value = currentSeverity || ''
  showSeverityOverride.value = true
}

async function applySeverityOverride({ severity, reason }) {
  if (!severityEditingFindingId.value) return
  
  // If in edit mode, update editForm instead of saving immediately
  if (editId.value === severityEditingFindingId.value) {
    if (!editForm.value.sections._meta) {
      editForm.value.sections._meta = {}
    }
    editForm.value.sections._meta['Severity'] = severity
    
    // Update Justification in prose sections if reason provided
    if (reason) {
      const currentJust = editForm.value.sections['Justification'] || ''
      const severityNote = `Severity is rated ${severity} because ${reason}.`
      editForm.value.sections['Justification'] = currentJust ? `${severityNote}\n\n${currentJust}` : severityNote
    }
    
    hasUnsavedEditChanges.value = true
    closeSeverityOverride()
    setStatus(t('severity.updated'), 'success')
    return
  }
  
  const finding = findings.value.find(f => f.id === severityEditingFindingId.value)
  if (!finding) return
  
  try {
    const content = parseContent(finding.content_json)
    content['Severity'] = severity
    
    // Update Justification field with reason
    if (reason) {
      const justKey = 'Justification'
      const currentJust = content[justKey] || ''
      const severityNote = `Severity is rated ${severity} because ${reason}.`
      content[justKey] = currentJust ? `${severityNote}\n\n${currentJust}` : severityNote
    }
    
    await request(`/api/admin/findings/${finding.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        title: finding.title,
        content_json: JSON.stringify(content),
        notes: finding.notes || '',
        template: finding.template || '',
      }),
    })
    
    closeSeverityOverride()
    // Reload findings to reflect the update
    await loadFindings()
    setStatus(t('severity.saved'), 'success')
  } catch (e) {
    setStatus(e.message || t('severity.saveFailed'), 'error')
  }
}

function closeSeverityOverride() {
  showSeverityOverride.value = false
  severityEditingFindingId.value = null
  currentEditingSeverity.value = ''
}

/* ── Confidence Modal ── */
function openConfidenceModal(findingId, currentConfidence) {
  confidenceEditingFindingId.value = findingId
  currentEditingConfidence.value = currentConfidence || ''
  showConfidenceModal.value = true
}

async function applyConfidence({ confidence, notes }) {
  if (!confidenceEditingFindingId.value) return
  
  // If in edit mode, update editForm instead of saving immediately
  if (editId.value === confidenceEditingFindingId.value) {
    if (!editForm.value.sections._meta) {
      editForm.value.sections._meta = {}
    }
    editForm.value.sections._meta['Confidence'] = confidence
    
    // Append notes to Justification if provided
    if (notes) {
      const currentJust = editForm.value.sections['Justification'] || ''
      const confidenceNote = `Confidence is rated "${confidence}" because ${notes}.`
      editForm.value.sections['Justification'] = currentJust ? `${confidenceNote}\n\n${currentJust}` : confidenceNote
    }
    
    hasUnsavedEditChanges.value = true
    closeConfidenceModal()
    setStatus(t('confidence.updated'), 'success')
    return
  }
  
  const finding = findings.value.find(f => f.id === confidenceEditingFindingId.value)
  if (!finding) return
  
  try {
    const content = parseContent(finding.content_json)
    content['Confidence'] = confidence
    
    // Append notes to Justification field if provided
    if (notes) {
      const justKey = 'Justification'
      const currentJust = content[justKey] || ''
      const confidenceNote = `Confidence is rated "${confidence}" because ${notes}.`
      content[justKey] = currentJust ? `${confidenceNote}\n\n${currentJust}` : confidenceNote
    }
    
    await request(`/api/admin/findings/${finding.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        title: finding.title,
        content_json: JSON.stringify(content),
        notes: finding.notes || '',
        template: finding.template || '',
      }),
    })
    
    closeConfidenceModal()
    await loadFindings()
    setStatus(t('confidence.saved'), 'success')
  } catch (e) {
    setStatus(t('confidence.saveFailed'), 'error')
  }
}

function closeConfidenceModal() {
  showConfidenceModal.value = false
  confidenceEditingFindingId.value = null
  currentEditingConfidence.value = ''
}


async function fetchConfidenceLevels() {
  try {
    const response = await request('/api/admin/confidence-levels')
    confidenceLevels.value = response.levels || ['Confirmed', 'Suspected', 'Tentative', 'False Positive']
  } catch (error) {
    // Use defaults if fetch fails
    confidenceLevels.value = ['Confirmed', 'Suspected', 'Tentative', 'False Positive']
  }
}

function cancelEditingMeta() {
  editingMetaField.value = null
}

async function saveMetaField() {
  if (!editingMetaField.value) return
  
  const { findingId, key, value } = editingMetaField.value
  
  // If in edit mode, update editForm instead of saving immediately
  if (editId.value === findingId) {
    if (!editForm.value.sections._meta) {
      editForm.value.sections._meta = {}
    }
    editForm.value.sections._meta[key] = value.trim()
    hasUnsavedEditChanges.value = true
    editingMetaField.value = null
    setStatus(t('findings.fieldUpdated', { field: key }), 'success')
    return
  }
  
  // Not in edit mode - save immediately to backend
  const finding = findings.value.find(f => f.id === findingId)
  if (!finding) return
  
  try {
    const content = parseContent(finding.content_json)
    content[key] = value.trim()
    
    await request(`/api/admin/findings/${finding.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        title: finding.title,
        content_json: JSON.stringify(content),
        notes: finding.notes || '',
        template: finding.template || '',
      }),
    })
    
    editingMetaField.value = null
    // Reload findings to reflect the update
    await loadFindings()
    setStatus(t('findings.updated'), 'success')
  } catch (e) {
    setStatus(e.message || t('findings.updateFailed'), 'error')
  }
}

/* ── Findings accordion ── */
const expandedId = ref(null)
function toggleExpand(id) {
  expandedId.value = expandedId.value === id ? null : id
}

/* ── Bulk selection mode ── */
const selectionMode = ref(false)
const selectedFindings = ref(new Set())

function toggleSelectionMode() {
  selectionMode.value = !selectionMode.value
  if (!selectionMode.value) {
    selectedFindings.value.clear()
  }
}

function toggleSelection(findingId) {
  const newSet = new Set(selectedFindings.value)
  if (newSet.has(findingId)) {
    newSet.delete(findingId)
  } else {
    newSet.add(findingId)
  }
  selectedFindings.value = newSet
}

function selectAll() {
  selectedFindings.value = new Set(findings.value.map(f => f.id))
}

function clearSelection() {
  selectedFindings.value = new Set()
}

const selectedCount = computed(() => selectedFindings.value.size)

async function bulkDelete() {
  if (selectedCount.value === 0) return
  const ok = await showConfirm({ 
    message: t('findings.bulkDeleteConfirm', { count: selectedCount.value }),
    danger: true 
  })
  if (!ok) return
  
  setStatus(t('findings.deletingFindings'), 'info')
  try {
    const deleteCount = selectedCount.value
    
    // Delete all selected findings in parallel
    await Promise.all(
      Array.from(selectedFindings.value).map(id =>
        request(`/api/admin/findings/${id}`, { method: 'DELETE' })
      )
    )
    
    // Clear import sessions to prevent stale cache on re-upload
    if (reportId) {
      await request(`/api/admin/reports/${reportId}/import-sessions`, { method: 'DELETE' })
    }
    
    await loadFindings()
    selectionMode.value = false
    selectedFindings.value.clear()
    setStatus(t('findings.findingsDeleted', { count: deleteCount }), 'success')
  } catch (error) {
    setStatus(error.message || t('findings.failedDeleteFindings'), 'error')
  }
}

async function bulkRegenerate() {
  if (selectedCount.value === 0) return

  const selected = findings.value.filter(f => selectedFindings.value.has(f.id))
  const withNotes = selected.filter(f => f.notes && f.notes.trim())
  const skipped = selected.length - withNotes.length

  if (withNotes.length === 0) {
    setStatus(t('findings.bulkRegenerateNoNotes'), 'error')
    return
  }

  if (skipped > 0) {
    setStatus(t('findings.bulkRegenerateSkipped', { count: skipped }), 'info')
  }

  const llm = getCurrentLlmSettingsForRequest()
  const taskIds = []

  for (const finding of withNotes) {
    const tpl = findingTemplates.value.find(ft => ft.name === finding.template)
    try {
      const data = await request('/api/generate/structured/async', {
        method: 'POST',
        body: JSON.stringify({
          report_id: reportId,
          notes: finding.notes,
          template: tpl?.content || '',
          finding_id: finding.id,
          llm_provider: llm.provider || null,
          llm_model: llm.model || null,
          llm_base_url: llm.baseUrl || null,
          llm_timeout: llm.timeout || null,
          sampling_params: llm.samplingParams || null,
          locale: locale.value || null,
          title_hint: finding.title || null,
        }),
      })
      taskIds.push(data.task_id)
    } catch (e) {
      setStatus(t('findings.failedGenerateFinding'), 'error')
    }
  }

  if (taskIds.length > 0) {
    trackTaskIds(taskIds)
    nudge()

    let completed = 0
    let failed = 0
    const total = taskIds.length

    for (const taskId of taskIds) {
      registerCompletionCallback(taskId, (fullTask) => {
        if (fullTask.status === 'completed') {
          completed++
        } else {
          failed++
        }
        // Regenerate tasks need review — don't auto-acknowledge
        if (completed + failed === total) {
          loadFindings()
          if (failed === 0) {
            setStatus(t('findings.bulkRegenerateComplete', { count: completed }), 'success')
          } else {
            setStatus(t('findings.validateAllPartial', { completed, failed }), 'error')
          }
        }
      })
    }
  }

  selectionMode.value = false
  selectedFindings.value = new Set()
}

async function bulkRevalidate() {
  if (selectedCount.value === 0) return

  const selected = findings.value.filter(f => selectedFindings.value.has(f.id))
  const llm = getCurrentLlmSettingsForRequest()

  try {
    const data = await request('/api/generate/validation-guidance/bulk/async', {
      method: 'POST',
      body: JSON.stringify({
        report_id: reportId,
        finding_ids: selected.map(f => f.id),
        regenerate: true,
        llm_provider: llm.provider || null,
        llm_model: llm.model || null,
        llm_base_url: llm.baseUrl || null,
        llm_timeout: llm.timeout || null,
      })
    })

    trackTaskIds(data.task_ids)
    nudge()  // Immediate poll + reset to fast-poll mode

    let completed = 0
    let failed = 0
    const total = data.task_ids.length

    for (const taskId of data.task_ids) {
      registerCompletionCallback(taskId, (fullTask) => {
        if (fullTask.status === 'completed' && fullTask.result_json) {
          try {
            const result = JSON.parse(fullTask.result_json)
            const idx = findings.value.findIndex(f => String(f.id) === String(fullTask.finding_id))
            if (idx !== -1) {
              findings.value[idx] = { ...findings.value[idx], validation_guidance: result.guidance || '' }
            }
          } catch {
            // Parse error — task still completed in TaskBar
          }
          completed++
        } else {
          failed++
        }
        acknowledgeTask(taskId)

        if (completed + failed === total) {
          if (failed === 0) {
            setStatus(t('findings.bulkRevalidateComplete', { count: completed }), 'success')
          } else {
            setStatus(t('findings.validateAllPartial', { completed, failed }), 'error')
          }
        }
      })
    }
  } catch (error) {
    setStatus(t('findings.validationFailed'), 'error')
  }

  selectionMode.value = false
  selectedFindings.value = new Set()
}

/* ── Jira integration ── */
const jiraEnabled = ref(false)
const showJiraModal = ref(false)
const jiraProjects = ref([])
const jiraProjectSearch = ref('')
const selectedProject = ref(null)
const selectedFinding = ref(null)
const creatingJiraIssue = ref(false)

async function checkJiraConnector() {
  try {
    const connectors = await request('/api/admin/connectors')
    jiraEnabled.value = connectors.some(c => c.type === 'jira' && c.enabled)
  } catch {
    jiraEnabled.value = false
  }
}

async function openJiraModal(finding) {
  selectedFinding.value = finding
  showJiraModal.value = true
  // Load projects
  try {
    const result = await request('/api/admin/connectors/jira/projects')
    jiraProjects.value = result.projects || []
  } catch (e) {
    setStatus(e.message || t('findings.failedLoadJiraProjects'), 'error')
  }
}

const filteredProjects = computed(() => {
  if (!jiraProjectSearch.value) return jiraProjects.value
  const q = jiraProjectSearch.value.toLowerCase()
  return jiraProjects.value.filter(p =>
    p.key.toLowerCase().includes(q) ||
    p.name.toLowerCase().includes(q)
  )
})

async function createJiraIssue() {
  if (creatingJiraIssue.value) return
  if (!selectedProject.value) {
    setStatus(t('findings.pleaseSelectProject'), 'error')
    return
  }
  creatingJiraIssue.value = true
  setStatus(t('findings.creatingJiraIssue'), 'info')

  try {
    const result = await request('/api/admin/connectors/jira/create-issue', {
      method: 'POST',
      body: JSON.stringify({
        finding_id: selectedFinding.value.id,
        project_key: selectedProject.value.key,
        issue_type: 'Bug',
      })
    })

    // Update local finding state with issue key and URL
    const finding = findings.value.find(f => f.id === selectedFinding.value.id)
    if (finding && result.issue_key) {
      finding.jira_issue_key = result.issue_key
      finding.jira_issue_url = result.issue_url
    }

    showJiraModal.value = false
    setStatus(result.message, 'success')
  } catch (e) {
    setStatus(e.message || t('findings.failedCreateJiraIssue'), 'error')
  } finally {
    creatingJiraIssue.value = false
  }
}

async function unlinkJiraTicket(finding) {
  const ok = await showConfirm({ 
    message: t('findings.confirmUnlinkJira') || 'Unlink Jira ticket from this finding?',
    danger: false 
  })
  if (!ok) return
  
  try {
    await request(`/api/admin/connectors/jira/unlink/${finding.id}`, {
      method: 'DELETE'
    })
    
    // Update local state
    finding.jira_issue_key = ''
    finding.jira_issue_url = ''
    
    setStatus(t('findings.jiraUnlinked') || 'Jira ticket unlinked', 'success')
  } catch (e) {
    setStatus(e.message || t('findings.failedUnlinkJira') || 'Failed to unlink Jira ticket', 'error')
  }
}

/* ── Org LLM settings (injected from DashboardLayout) ── */
const orgLlmSettings = inject('orgLlmSettings', ref({}))
const refetchOrgLlmSettings = inject('refetchOrgLlmSettings', () => Promise.resolve())
const VISION_STORAGE_KEY = 'lazeport_vision_model'

function getCurrentLlmSettingsForRequest() {
  const s = orgLlmSettings.value || {}
  // Use the local reactive refs (provider.value, model.value, baseUrl.value) which are
  // seeded from org settings by _applyOrgLlmSettings. This allows the local provider
  // dropdown to override the org default within the session.
  return {
    provider: provider.value || null,
    model: model.value || null,
    baseUrl: baseUrl.value || null,
    timeout: s.timeout ?? null,
    samplingParams: s.sampling_params || null,
  }
}

function saveVisionModel() {
  try {
    localStorage.setItem(VISION_STORAGE_KEY, visionModel.value)
  } catch { /* ignore */ }
}

function saveLlmPrefs() {
  try {
    const p = provider.value
    if (p) {
      const prev = providerSettings.value[p] || {}
      providerSettings.value = { ...providerSettings.value, [p]: { ...prev, baseUrl: baseUrl.value } }
    }
  } catch { /* ignore */ }
}

function saveLlmRequiredAndClose() {
  showLlmRequiredModal.value = false
  const file = pendingImageFile.value
  const cursorPos = pendingImageCursorPos.value
  if (file && cursorPos !== null && visionModel.value && getVisionProvider(visionModel.value)) {
    processImageWithAI(file, cursorPos).catch(err => setLocalStatus(err.message || t('findings.visionExtractionFailed'), 'error'))
    showImageConfirm.value = false
    pendingImageFile.value = null
    pendingImageCursorPos.value = null
  }
}

function loadVisionModel() {
  try {
    const saved = localStorage.getItem(VISION_STORAGE_KEY)
    if (saved && visionModels.value.includes(saved)) {
      visionModel.value = saved
    } else if (visionModels.value.length > 0) {
      visionModel.value = visionModels.value[0]
    }
  } catch { /* ignore */ }
}

async function loadVisionModels() {
  // Load vision models from the API
  try {
    const params = new URLSearchParams()
    if (provider.value) params.append('provider', provider.value)
    if (baseUrl.value) params.append('base_url', baseUrl.value)
    const data = await request(`/api/providers/vision-models?${params}`)
    visionModels.value = data.models || []
    ollamaVisionModels.value = provider.value === 'ollama' ? visionModels.value : []
  } catch {
    visionModels.value = []
    ollamaVisionModels.value = []
  }

  // Update selected vision model if needed
  loadVisionModel()
}

// Determine provider from vision model name
function getVisionProvider(modelName) {
  if (!modelName) return null

  // OpenAI models
  if (modelName.startsWith('gpt-')) {
    return 'openai'
  }

  // Ollama vision models by name pattern (llava, bakllava, etc.) so we don't depend on list being loaded
  const lower = modelName.toLowerCase()
  if (lower.includes('llava') || lower.includes('bakllava') || lower.includes('vision')) {
    return 'ollama'
  }

  if (ollamaVisionModels.value.includes(modelName)) {
    return 'ollama'
  }

  return null
}

/* ── Data loaders ── */
async function loadReport() {
  try {
    report.value = await request(`/api/admin/reports/${reportId}`)
    if (report.value) {
      summaries.value = {
        executive: report.value.summary_executive || '',
        technical: report.value.summary_technical || '',
        recommendations: report.value.summary_recommendations || ''
      }
      // Load vision settings for the org
      await loadVisionSettings()
      // Load client and app lists for breadcrumb lookups
      try {
        const [clientsData, appsData] = await Promise.all([
          request('/api/admin/clients'),
          request('/api/admin/applications')
        ])
        if (report.value.client_id) {
          client.value = clientsData.find(t => String(t.id) === String(report.value.client_id))
        }
        if (report.value.application_id) {
          application.value = appsData.find(a => String(a.id) === String(report.value.application_id))
        }
      } catch {}
    }
  } catch (error) {
    // Invalid or non-existent report ID - redirect to reports list
    setStatus(t('findings.reportNotFound') || 'Report not found', 'error')
    router.push('/dashboard/reports')
  }
}

async function loadUserOrgRole() {
  try {
    const user = await getSessionUser()
    userOrgRole.value = user?.org_role || 'readonly'
    if (user?.role === 'admin') userOrgRole.value = user.org_role || 'org_owner'
  } catch {
    userOrgRole.value = 'readonly'
  }
}

async function loadVisionSettings() {
  if (!report.value?.organization_id) return
  try {
    const data = await request(`/api/orgs/${report.value.organization_id}/vision-settings`)
    maxConcurrentVisionTasks.value = data.max_concurrent_tasks || 2
  } catch {
    // Use default if settings can't be loaded
    maxConcurrentVisionTasks.value = 2
  }
}

async function loadFindings() {
  try {
    findings.value = await request(`/api/admin/findings?report_id=${reportId}`)
  } catch (error) {
    // If report doesn't exist, loadReport() will handle redirect
    // If findings fetch fails for another reason, show empty list
    findings.value = []
  }
}

// Check for unsaved changes in the form
const hasUnsavedChanges = computed(() => {
  if (!originalFormState.value || !editId.value) return false
  const orig = originalFormState.value
  const curr = form.value
  return orig.title !== curr.title || 
         orig.notes !== curr.notes || 
         orig.content_json !== curr.content_json
})


async function loadFindingTemplates() {
  const [templates, profileData] = await Promise.all([
    request('/api/admin/finding-templates'),
    request('/api/admin/profile').catch(() => ({})),
  ])
  findingTemplates.value = templates
  if (!form.value.template_id && findingTemplates.value.length) {
    const defaultName = profileData.default_finding_template || ''
    const preferred = defaultName
      ? findingTemplates.value.find(t => t.name === defaultName)
      : null
    form.value.template_id = String((preferred || findingTemplates.value[0]).id)
  }
}

async function loadMasterTemplates() {
  masterTemplates.value = await request('/api/master-templates')
  if (!masterTemplate.value && masterTemplates.value.length) {
    masterTemplate.value = masterTemplates.value.includes('master') ? 'master' : masterTemplates.value[0]
  }
}

async function loadProviders() {
  const h = await request('/api/health')
  providers.value = h.providers || providers.value
  _applyOrgLlmSettings(orgLlmSettings.value)
}

function _applyOrgLlmSettings(s) {
  if (!s || !s.provider) return
  provider.value = s.provider
  model.value = s.model || ''
  baseUrl.value = s.base_url || ''
  if (s.vision_model) visionModel.value = s.vision_model
  lastProvider_rf = s.provider
  loadModelOptions()
  loadVisionModels()
}

async function onProviderChange() {
  const newProvider = provider.value

  // Cache the outgoing provider's base URL
  if (lastProvider_rf) {
    providerSettings.value[lastProvider_rf] = { baseUrl: baseUrl.value }
  }

  // Restore cached URL for the new provider, or apply its preset default
  const cached = providerSettings.value[newProvider]
  const preset = PROVIDER_PRESETS[newProvider]
  if (cached?.baseUrl) {
    baseUrl.value = cached.baseUrl
  } else if (preset?.baseUrl) {
    baseUrl.value = preset.baseUrl
  } else {
    baseUrl.value = ''
  }

  lastProvider_rf = newProvider
  model.value = ''
  modelOptions.value = []
  await loadModelOptions()
  saveLlmPrefs()
  // Update vision models when provider changes
  await loadVisionModels()
}

async function loadModelOptions() {
  if (provider.value) {
    try {
      const params = new URLSearchParams({ provider: provider.value })
      if (baseUrl.value) params.append('base_url', baseUrl.value)
      const data = await request(`/api/providers/models?${params}`)
      modelOptions.value = data.models || []
    } catch {
      modelOptions.value = []
    }
  } else {
    modelOptions.value = []
  }
  if (modelOptions.value.length) {
    const current = model.value || ''
    if (!current || !modelOptions.value.includes(current)) {
      model.value = modelOptions.value[0]
      saveLlmPrefs()
    }
  }
}

watch(model, saveLlmPrefs)
watch(baseUrl, () => {
  loadModelOptions()
  loadVisionModels()
  saveLlmPrefs()
})
watch(visionModel, saveVisionModel)

watch(orgLlmSettings, (s) => _applyOrgLlmSettings(s), { immediate: true })

/* ── Local status helpers ── */
function setLocalStatus(message, type = 'info') {
  localStatus.value = message
  localStatusType.value = type
  // Auto-clear success messages after 3 seconds
  if (type === 'success') {
    setTimeout(() => {
      if (localStatus.value === message) {
        localStatus.value = ''
      }
    }, 3000)
  }
}

/* ── Image paste handler with queue ── */
async function handlePaste(event) {
  const items = event.clipboardData?.items
  if (!items) return

  for (const item of items) {
    if (item.type.startsWith('image/')) {
      event.preventDefault()

      // Check if vision model is configured
      if (!visionModel.value) {
        setLocalStatus(t('findings.visionModelRequired'), 'error')
        return
      }

      const file = item.getAsFile()
      if (!file) continue

      // Capture cursor position at paste time
      const textarea = event.target
      const cursorPos = textarea?.selectionStart ?? null
      const currentText = form.value.notes

      // Add to queue with cursor position and timestamp
      imageQueue.value.push({
        file,
        id: Date.now() + Math.random(),
        cursorPos,
        textSnapshot: currentText,
        startTime: Date.now()
      })
      updateQueueStatus()

      // Start processing queue
      processImageQueue()
    }
  }
}

function updateQueueStatus() {
  const queueLength = imageQueue.value.length
  const processing = activeImageTasks.value

  if (queueLength > 0 || processing > 0) {
    const parts = []
    if (processing > 0) parts.push(t('findings.processingImages', { count: processing }))
    if (queueLength > 0) parts.push(t('findings.inQueue', { count: queueLength }))
    setLocalStatus(parts.join(', '), 'info')
  }
}

async function processImageQueue() {
  // Only start if we have capacity and items in queue
  if (activeImageTasks.value >= maxConcurrentVisionTasks.value || imageQueue.value.length === 0) {
    return
  }

  const item = imageQueue.value.shift()
  if (!item) return

  activeImageTasks.value++
  updateQueueStatus()

  try {
    // Convert image to base64
    const base64 = await fileToBase64(item.file)
    const base64Data = base64.split(',')[1] // Remove data:image/...;base64, prefix

    // Determine provider from selected vision model
    const visionProvider = getVisionProvider(visionModel.value)

    // Call vision API
    const llm = getCurrentLlmSettingsForRequest()
    const result = await request('/api/vision/extract-text', {
      method: 'POST',
      body: JSON.stringify({
        image_base64: base64Data,
        image_mime_type: item.file.type,
        vision_model: visionModel.value,
        provider: visionProvider,
        // Only send base_url for Ollama
        base_url: visionProvider === 'ollama' ? (baseUrl.value || null) : null,
        sampling_params: llm.samplingParams || null,
      })
    })

    // Calculate processing time
    const processingTime = ((Date.now() - item.startTime) / 1000).toFixed(1)

    // Insert extracted text at cursor position or append
    const extractedText = result.text || ''
    if (extractedText) {
      const separator = '\n\n---\n\n'

      // If we have a cursor position and the text hasn't changed much, insert at cursor
      if (item.cursorPos !== null && item.textSnapshot === form.value.notes) {
        // Insert at original cursor position
        const before = form.value.notes.substring(0, item.cursorPos)
        const after = form.value.notes.substring(item.cursorPos)
        const prefix = before && !before.endsWith('\n\n') ? separator : ''
        const suffix = after && !after.startsWith('\n\n') ? separator : ''
        form.value.notes = before + prefix + extractedText + suffix + after
      } else {
        // Text changed or no cursor position - append to end
        const prefix = form.value.notes.trim() ? separator : ''
        form.value.notes += prefix + extractedText
      }

      // Show success briefly with timing
      if (imageQueue.value.length === 0 && activeImageTasks.value === 1) {
        setLocalStatus(t('findings.textExtractedIn', { time: processingTime }), 'success')
      }
    } else {
      setLocalStatus(t('findings.noTextInImage'), 'error')
    }
  } catch (e) {
    setLocalStatus(formatApiError(e, 'findings.failedExtractText'), 'error')
  } finally {
    activeImageTasks.value--
    updateQueueStatus()

    // If queue still empty and no active tasks, clear status
    if (imageQueue.value.length === 0 && activeImageTasks.value === 0) {
      setTimeout(() => {
        if (imageQueue.value.length === 0 && activeImageTasks.value === 0) {
          localStatus.value = ''
        }
      }, 2000)
    }

    // Continue processing queue
    processImageQueue()
  }
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result)
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

/* ── Template content helper ── */
function getSelectedTemplateContent() {
  const tpl = findingTemplates.value.find(t => String(t.id) === String(form.value.template_id))
  return (tpl && tpl.content) ? tpl.content : ''
}

/* ── Parse structured JSON into a usable object ── */
function parseContent(jsonStr) {
  try { return JSON.parse(jsonStr || '{}') } catch { return {} }
}

/* Known section keys for ordered display */
const META_KEYS = ['Severity', 'CVSS v3.1', 'CWE', 'CVE', 'OWASP', 'Affected Roles', 'Confidence']
const PROSE_KEYS = [
  'Vulnerability Summary', 'Summary', 'Justification', 'Rationale',
  'Root Cause', 'Details', 'Remediation', 'Additional Notes', 'References'
]
const SKIP_KEYS = new Set([...META_KEYS, ...PROSE_KEYS, 'Finding Title', 'Title', 'title', 'severity'])

function getProseEntries(data) {
  const entries = []
  for (const key of PROSE_KEYS) {
    const val = String(data[key] ?? '').trim()
    if (val) entries.push({ key, val })
  }
  // Any leftover keys
  for (const [key, val] of Object.entries(data)) {
    if (!SKIP_KEYS.has(key) && !META_KEYS.includes(key) && val != null && String(val).trim()) {
      entries.push({ key, val: String(val).trim() })
    }
  }
  return entries
}

function getProseEntriesForFinding(finding) {
  const data = parseContent(finding.content_json)
  const entries = getProseEntries(data)
  const validation = String(finding.validation_guidance ?? '').trim()
  if (validation) {
    entries.push({ key: t('findings.validationTab'), val: validation })
  }
  return entries
}

function getMetaEntries(data) {
  const entries = []
  for (const key of META_KEYS) {
    const val = String(data[key] ?? '').trim()
    // Always show editable fields even if empty (so [modify] link is visible)
    if (val || EDITABLE_META_KEYS.includes(key)) {
      entries.push({ key, val: val || '' })
    }
  }
  return entries
}

/* ── Hyperlink identifiers (CWE, OWASP, CVSS) ── */
const OWASP_2021 = {
  '1': 'A01_2021-Broken_Access_Control',
  '2': 'A02_2021-Cryptographic_Failures',
  '3': 'A03_2021-Injection',
  '4': 'A04_2021-Insecure_Design',
  '5': 'A05_2021-Security_Misconfiguration',
  '6': 'A06_2021-Vulnerable_and_Outdated_Components',
  '7': 'A07_2021-Identification_and_Authentication_Failures',
  '8': 'A08_2021-Software_and_Data_Integrity_Failures',
  '9': 'A09_2021-Security_Logging_and_Monitoring_Failures',
  '10': 'A10_2021-Server-Side_Request_Forgery_%28SSRF%29',
}
const OWASP_2017 = {
  '1': 'A1_2017-Injection',
  '2': 'A2_2017-Broken_Authentication',
  '3': 'A3_2017-Sensitive_Data_Exposure',
  '4': 'A4_2017-XML_External_Entities_%28XXE%29',
  '5': 'A5_2017-Broken_Access_Control',
  '6': 'A6_2017-Security_Misconfiguration',
  '7': 'A7_2017-Cross-Site_Scripting_%28XSS%29',
  '8': 'A8_2017-Insecure_Deserialization',
  '9': 'A9_2017-Using_Components_with_Known_Vulnerabilities',
  '10': 'A10_2017-Insufficient_Logging%26Monitoring',
}

/* ── URL builders for identifiers ── */
function cweToUrl(id) {
  return `https://cwe.mitre.org/data/definitions/${id}.html`
}
function cveToUrl(id) {
  return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`
}
function owaspToUrl(num, year) {
  const n = String(parseInt(num, 10))
  if (year === '2017' && OWASP_2017[n]) return `https://owasp.org/www-project-top-ten/2017/${OWASP_2017[n]}`
  if ((!year || year === '2021') && OWASP_2021[n]) return `https://owasp.org/Top10/${OWASP_2021[n]}/`
  return `https://owasp.org/Top10/`
}
function cvssVectorToUrl(vector) {
  const v = vector.startsWith('CVSS:3') ? vector : `CVSS:3.1/${vector}`
  return `https://www.first.org/cvss/calculator/3.1#${v}`
}

/* ── Hyperlink meta values (CWE, CVE, OWASP, CVSS) ── */
function hyperlinkMetaParts(key, val) {
  const text = String(val || '')
  if (!text.trim()) return [{ text: '' }]

  if (key === 'CWE') {
    const m = text.match(/CWE-(\d+)/i)
    if (m && /^\d+$/.test(m[1])) {
      return [{ text, href: cweToUrl(m[1]) }]
    }
  }

  if (key === 'CVE') {
    const m = text.match(/CVE-\d{4}-\d{4,7}/i)
    if (m) {
      return [{ text, href: cveToUrl(m[0]) }]
    }
  }

  if (key === 'OWASP') {
    const m = text.match(/A(\d{1,2})(?::?(20\d{2}))?/i)
    if (m) {
      const num = m[1]
      const year = m[2]
      const url = owaspToUrl(num, year)
      return [{ text, href: url }]
    }
  }

  if (key === 'CVSS v3.1') {
    const fullVector = text.match(/CVSS:3\.\d\/(?:[A-Z]+:[A-Z]+\/?)+/i)?.[0]
    const shorthandVector = text.match(/AV:[A-Z]\/AC:[A-Z]\/PR:[A-Z]\/UI:[A-Z]\/S:[A-Z]\/C:[A-Z]\/I:[A-Z]\/A:[A-Z]/i)?.[0]
    const vector = fullVector || shorthandVector
    if (vector) {
      const url = cvssVectorToUrl(vector)
      const idx = text.indexOf(vector)
      if (idx >= 0) {
        const parts = []
        if (idx > 0) parts.push({ text: text.slice(0, idx) })
        parts.push({ text: vector, href: url })
        if (idx + vector.length < text.length) parts.push({ text: text.slice(idx + vector.length) })
        return parts
      }
      return [{ text, href: url }]
    }
  }

  return [{ text }]
}

/* ── Markdown prose: render LLM markdown as sanitized HTML ── */
// Remaps heading levels down (h1→h4, h2→h5, h3→h6) so they don't conflict
// with the page heading hierarchy, then sanitizes with DOMPurify.
function renderMarkdown(text) {
  if (!text || !String(text).trim()) return ''
  let html = marked(String(text), { breaks: true, gfm: true })
  html = html
    .replace(/<(\/?)h1(\s|>)/gi, '<$1h4$2')
    .replace(/<(\/?)h2(\s|>)/gi, '<$1h5$2')
    .replace(/<(\/?)h3(\s|>)/gi, '<$1h6$2')
  return DOMPurify.sanitize(html)
}

/* ── Linkify prose: split text on CVE/CWE/OWASP/CVSS and return parts with hrefs ── */
const IDENTIFIER_RE = /(CVE-\d{4}-\d{4,7}|CWE-\d{1,5}|A\d{1,2}(?::20\d{2})?|CVSS:3\.\d\/(?:[A-Z]+:[A-Z]+\/?)+|AV:[A-Z]\/AC:[A-Z]\/PR:[A-Z]\/UI:[A-Z]\/S:[A-Z]\/C:[A-Z]\/I:[A-Z]\/A:[A-Z])/gi
function linkifyProse(text) {
  if (!text || !String(text).trim()) return []
  const str = String(text)
  const parts = []
  let last = 0
  let m
  const re = new RegExp(IDENTIFIER_RE.source, 'gi')
  while ((m = re.exec(str)) !== null) {
    if (m.index > last) parts.push({ text: str.slice(last, m.index) })
    const token = m[0]
    let href = null
    if (/^CVE-/i.test(token)) href = cveToUrl(token)
    else if (/^CWE-/i.test(token)) href = cweToUrl(token.replace(/\D/g, ''))
    else if (/^A\d/i.test(token)) {
      const ym = token.match(/A(\d{1,2})(?::(20\d{2}))?/i)
      if (ym) href = owaspToUrl(ym[1], ym[2])
    } else if (/^CVSS:3|^AV:[A-Z]/i.test(token)) href = cvssVectorToUrl(token)
    parts.push(href ? { text: token, href } : { text: token })
    last = m.index + token.length
  }
  if (last < str.length) parts.push({ text: str.slice(last) })
  return parts.length ? parts : [{ text: str }]
}

/* ── Generate ── */
async function generateFinding() {
  const notes = form.value.notes || ''
  const template = getSelectedTemplateContent()
  if (!notes.trim()) {
    setStatus(t('findings.pleaseEnterNotes'), 'error')
    return
  }
  const llm = getCurrentLlmSettingsForRequest()
  const titleHint = form.value.title || notes.trim().slice(0, 60)
  try {
    const data = await request('/api/generate/structured/async', {
      method: 'POST',
      body: JSON.stringify({
        report_id: reportId,
        notes,
        template,
        llm_provider: llm.provider || null,
        llm_model: llm.model || null,
        llm_base_url: llm.baseUrl || null,
        llm_timeout: llm.timeout || null,
        sampling_params: llm.samplingParams || null,
        locale: locale.value || null,
        title_hint: titleHint,
        finding_id: editId.value || null,
      }),
    })
    const taskId = data.task_id
    generatingFindingTaskId.value = taskId
    nudge()  // Immediate poll + reset to fast-poll mode
    registerCompletionCallback(taskId, async (task) => {
      generatingFindingTaskId.value = null
      if (task.status === 'completed') {
        await loadFindings()
        if (!editId.value) {
          form.value = { title: '', content_json: '{}', notes: '', template_id: '' }
          verificationLog.value = []
        } else {
          resetForm()
        }
      }
      acknowledgeTask(taskId)
    })
  } catch (e) {
    const msg = formatApiError(e, 'findings.failedGenerateFinding')
    setStatus(msg, 'error')
  }
}

/* ── Review modal actions ── */
function _ackReviewTask() {
  if (reviewingTaskId.value) {
    acknowledgeTask(reviewingTaskId.value)
    reviewingTaskId.value = null
  }
}

async function reviewSave() {
  if (editId.value) {
    editForm.value.title = reviewTitle.value
  } else {
    form.value.title = reviewTitle.value
  }
  const savedFindingId = editId.value
  showReview.value = false
  _ackReviewTask()
  if (savedFindingId) pendingRegenFindings.delete(savedFindingId)
  if (editId.value) {
    await saveEdit()
  } else {
    await addFinding()
  }
}

function reviewDiscard() {
  const discardedFindingId = editId.value
  showReview.value = false
  _ackReviewTask()
  if (discardedFindingId) pendingRegenFindings.delete(discardedFindingId)
  form.value.content_json = '{}'
  form.value.title = ''
  verificationLog.value = []
  cancelEdit()
  setStatus(t('findings.findingDiscarded'), 'info')
}

function reviewClose() {
  // Keep the data in the form but close the modal (user can still manually save).
  // Do NOT acknowledge the task — it stays in the TaskBar with "Review →"
  // so the user can reopen it. Only save/discard should dismiss the task.
  if (!editId.value) {
    form.value.title = reviewTitle.value
  }
  showReview.value = false
  reviewingTaskId.value = null
}

/* ── Regenerate finding (reuses review modal like normal generate) ── */
function _structuredToEditSections(content) {
  const sections = {}
  for (const key of PROSE_KEYS) {
    if (content[key]) sections[key] = content[key]
  }
  sections._meta = {}
  for (const key of META_KEYS) {
    if (content[key] !== undefined) sections._meta[key] = content[key]
  }
  sections._other = {}
  for (const [key, val] of Object.entries(content)) {
    if (!PROSE_KEYS.includes(key) && !META_KEYS.includes(key) && !key.startsWith('_')) {
      sections._other[key] = val
    }
  }
  return sections
}

async function regenerateFinding(finding) {
  if (!finding.notes || !finding.notes.trim()) {
    setStatus(t('findings.regenerateNoNotes'), 'error')
    return
  }
  const llm = getCurrentLlmSettingsForRequest()
  const tpl = findingTemplates.value.find(ft => ft.name === finding.template)
  const templateContent = tpl?.content || ''
  try {
    const data = await request('/api/generate/structured/async', {
      method: 'POST',
      body: JSON.stringify({
        report_id: reportId,
        notes: finding.notes,
        template: templateContent,
        finding_id: finding.id,
        llm_provider: llm.provider || null,
        llm_model: llm.model || null,
        llm_base_url: llm.baseUrl || null,
        llm_timeout: llm.timeout || null,
        sampling_params: llm.samplingParams || null,
        locale: locale.value || null,
        title_hint: finding.title || '',
      }),
    })
    const taskId = data.task_id
    regeneratingFindingId.value = finding.id
    pendingRegenFindings.add(finding.id)
    nudge()  // Immediate poll + reset to fast-poll mode
    registerCompletionCallback(taskId, (task) => {
      regeneratingFindingId.value = null
      if (task.status === 'completed' && task.result_json) {
        // If a review modal is already open, don't stomp it — leave this task
        // in the TaskBar with "Review →" so the user can click it after.
        if (showReview.value) return
        try {
          const structured = JSON.parse(task.result_json)
          const aiTitle = structured['Finding Title'] || structured['title'] || structured['Title'] || finding.title || ''
          reviewData.value = structured
          reviewTitle.value = aiTitle
          editId.value = finding.id
          // Populate editForm so reviewSave() → saveEdit() saves AI content correctly
          const tpl = findingTemplates.value.find(ft => ft.name === finding.template)
          editForm.value = {
            title: aiTitle,
            template_id: tpl ? String(tpl.id) : '',
            sections: _structuredToEditSections(structured),
            notes: finding.notes || '',
            validation_guidance: finding.validation_guidance || '',
            show_validation: !!finding.validation_guidance,
          }
          reviewingTaskId.value = taskId
          showReview.value = true
        } catch {
          pendingRegenFindings.delete(finding.id)
          setStatus(t('findings.failedGenerateFinding'), 'error')
        }
      } else {
        // Task failed — unlock the finding for regeneration
        pendingRegenFindings.delete(finding.id)
      }
    })
  } catch (e) {
    regeneratingFindingId.value = null
    pendingRegenFindings.delete(finding.id)
    const msg = formatApiError(e, 'findings.failedGenerateFinding')
    setStatus(msg, 'error')
  }
}

/* ── CVSS calculator modal actions ── */
function openCvssCalculator(findingId) {
  cvssEditingFindingId.value = findingId
  showCvssCalculator.value = true
}

async function applyCvssValue(formattedValue) {
  if (!cvssEditingFindingId.value) return
  
  // If in edit mode, update editForm instead of saving immediately
  if (editId.value === cvssEditingFindingId.value) {
    if (!editForm.value.sections._meta) {
      editForm.value.sections._meta = {}
    }
    editForm.value.sections._meta['CVSS v3.1'] = formattedValue
    hasUnsavedEditChanges.value = true
    closeCvssCalculator()
    setStatus(t('cvss.updated'), 'success')
    return
  }
  
  const finding = findings.value.find(f => f.id === cvssEditingFindingId.value)
  if (!finding) return
  
  try {
    // Parse existing content_json and update CVSS v3.1 field
    const content = parseContent(finding.content_json)
    content['CVSS v3.1'] = formattedValue
    
    // Save to backend
    await request(`/api/admin/findings/${finding.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        title: finding.title,
        content_json: JSON.stringify(content),
        notes: finding.notes || '',
        template: finding.template || '',
      }),
    })
    
    closeCvssCalculator()
    // Reload findings to reflect the update
    await loadFindings()
    setStatus(t('cvss.saved'), 'success')
  } catch (e) {
    setStatus(e.message || t('cvss.saveFailed'), 'error')
  }
}

function closeCvssCalculator() {
  showCvssCalculator.value = false
  cvssEditingFindingId.value = null
}

/* ── Save ── */
async function addFinding() {
  if (!form.value.title.trim()) {
    setStatus(t('findings.titleRequired'), 'error')
    return
  }
  setStatus(t('findings.savingFinding'), 'info')
  
  const tpl = findingTemplates.value.find(t => String(t.id) === String(form.value.template_id))
  const content = JSON.parse(form.value.content_json || '{}')
  
  // Apply severity override if specified
  if (severityOverride.value && severityReason.value.trim()) {
    content['Severity'] = severityOverride.value
    
    // Inject reason into Justification field
    const justKey = 'Justification'
    const currentJust = content[justKey] || ''
    const severityNote = `Severity is rated ${severityOverride.value} because ${severityReason.value.trim()}.`
    content[justKey] = currentJust ? `${severityNote}\n\n${currentJust}` : severityNote
  }
  
  await request('/api/admin/findings', {
    method: 'POST',
    body: JSON.stringify({
      report_id: reportId,
      title: form.value.title,
      content: content,
      notes: form.value.notes,
      template: tpl ? tpl.name : '',
    }),
  })
  resetForm()
  await loadFindings()
  summariesStale.value = true
  setStatus(t('findings.findingSaved'), 'success')
}

async function generateAndSave() {
  await generateFinding()
  // If the review modal is showing, don't auto-save - let user review first
  // The modal's "Save" button handles saving
}

function resetForm() {
  form.value = { title: '', content_json: '{}', notes: '', template_id: form.value.template_id }
  editId.value = null
  originalFormState.value = null
  severityOverride.value = ''
  severityReason.value = ''
  verificationLog.value = []
  reviewData.value = {}
  showReview.value = false
}

/* ── Breadcrumb navigation with unsaved changes warning ── */
async function navigateToTeams() {
  if (hasUnsavedChanges.value) {
    const ok = await showConfirm({ 
      message: t('findings.unsavedChangesWarning'),
      danger: true 
    })
    if (!ok) return
  }
  router.push('/dashboard/clients')
}

async function navigateToReports() {
  if (hasUnsavedChanges.value) {
    const ok = await showConfirm({ 
      message: t('findings.unsavedChangesWarning'),
      danger: true 
    })
    if (!ok) return
  }
  router.push('/dashboard/reports')
}

/* ── Edit / Delete ── */
function startEdit(finding) {
  editId.value = finding.id
  expandedId.value = finding.id  // Ensure the row is expanded
  const tpl = findingTemplates.value.find(t => t.name === finding.template)
  
  // Parse structured content into editable sections
  const sections = {}
  try {
    const content = JSON.parse(finding.content_json || '{}')
    
    // Extract prose sections (the ones that appear as paragraphs in the report)
    for (const key of PROSE_KEYS) {
      if (content[key]) {
        sections[key] = content[key]
      }
    }
    // Store meta fields separately (they have their own inline editors)
    sections._meta = {}
    for (const key of META_KEYS) {
      if (content[key] !== undefined) {
        sections._meta[key] = content[key]
      }
    }
    // Store any other fields
    sections._other = {}
    for (const [key, val] of Object.entries(content)) {
      if (!PROSE_KEYS.includes(key) && !META_KEYS.includes(key) && !key.startsWith('_')) {
        sections._other[key] = val
      }
    }
  } catch (e) {
    console.error('Failed to parse content_json:', e)
  }
  
  editForm.value = {
    title: finding.title || '',
    template_id: tpl ? String(tpl.id) : '',
    sections,
    validation_guidance: finding.validation_guidance || '',
    show_validation: Boolean(String(finding.validation_guidance || '').trim()),
  }
}

async function saveEdit() {
  if (!editForm.value.title.trim()) {
    setStatus(t('findings.titleRequiredShort'), 'error')
    return
  }
  if (!editId.value) return
  
  setStatus(t('findings.savingChanges'), 'info')
  const tpl = findingTemplates.value.find(t => String(t.id) === String(editForm.value.template_id))
  
  // Rebuild content_json from edited sections
  const content = {}
  
  // Add prose sections
  for (const [key, val] of Object.entries(editForm.value.sections)) {
    if (key === '_meta' || key === '_other') continue
    if (val && String(val).trim()) {
      content[key] = String(val).trim()
    }
  }
  
  // Add meta fields (preserve existing values)
  if (editForm.value.sections._meta) {
    Object.assign(content, editForm.value.sections._meta)
  }
  
  // Add other fields
  if (editForm.value.sections._other) {
    Object.assign(content, editForm.value.sections._other)
  }
  
  try {
    await request(`/api/admin/findings/${editId.value}`, {
      method: 'PUT',
      body: JSON.stringify({
        title: editForm.value.title,
        notes: (editForm.value.notes != null && editForm.value.notes !== undefined) ? editForm.value.notes : '',
        content_json: JSON.stringify(content),
        template: tpl ? tpl.name : '',
        validation_guidance: editForm.value.show_validation ? (editForm.value.validation_guidance || '') : null,
      }),
    })
    
    hasUnsavedEditChanges.value = false
    cancelEdit()
    await loadFindings()
    summariesStale.value = true
    setStatus(t('findings.changesSaved'), 'success')
  } catch (error) {
    setStatus(t('findings.failedToSave'), 'error')
  }
}

function cancelEdit() {
  editId.value = null
  editForm.value = { title: '', template_id: '', sections: {}, validation_guidance: '', show_validation: false, notes: '' }
  hasUnsavedEditChanges.value = false
}

async function removeFinding(id) {
  const ok = await showConfirm({ message: t('findings.deleteConfirm'), danger: true })
  if (!ok) return
  setStatus(t('findings.deletingFinding'), 'info')
  await request(`/api/admin/findings/${id}`, { method: 'DELETE' })
  if (expandedId.value === id) expandedId.value = null
  await loadFindings()
  
  // Check if all findings are now deleted - if so, clear import sessions
  if (findings.value.length === 0 && reportId) {
    try {
      await request(`/api/admin/reports/${reportId}/import-sessions`, { method: 'DELETE' })
    } catch (e) {
      // Non-critical, just log
      console.warn('Failed to clear import sessions:', e)
    }
  }
  
  summariesStale.value = true
  setStatus(t('findings.findingDeleted'), 'success')
}

async function generateValidationGuidance(finding, forceRegenerate = false) {
  generatingGuidance.value = true
  validationGuidanceFindingTitle.value = finding.title || t('findings.untitled')
  validationGuidanceFinding.value = finding
  showValidationGuidance.value = true
  validationGuidance.value = t('findings.generatingValidation')

  const llm = getCurrentLlmSettingsForRequest()
  try {
    const data = await request('/api/generate/validation-guidance/async', {
      method: 'POST',
      body: JSON.stringify({
        report_id: reportId,
        finding_id: finding.id,
        regenerate: forceRegenerate,
        llm_provider: llm.provider || null,
        llm_model: llm.model || null,
        llm_base_url: llm.baseUrl || null,
        llm_timeout: llm.timeout || null,
        title_hint: finding.title || null,
      })
    })

    // Pre-register so TaskBar shows the task even if polling catches it after completion
    trackTaskIds([data.task_id])
    nudge()  // Immediate poll + reset to fast-poll mode

    // Register completion callback to populate the modal
    registerCompletionCallback(data.task_id, (fullTask) => {
      generatingGuidance.value = false
      if (fullTask.status === 'completed' && fullTask.result_json) {
        try {
          const result = JSON.parse(fullTask.result_json)
          validationGuidance.value = result.guidance || ''
          const idx = findings.value.findIndex(f => f.id === finding.id)
          if (idx !== -1) {
            findings.value[idx] = { ...findings.value[idx], validation_guidance: result.guidance || '' }
          }
        } catch {
          validationGuidance.value = t('findings.validationError', { error: 'Failed to parse result' })
        }
      } else {
        validationGuidance.value = t('findings.validationError', { error: fullTask.error || 'Unknown error' })
      }
      acknowledgeTask(data.task_id)
    })
  } catch (error) {
    generatingGuidance.value = false
    validationGuidance.value = t('findings.validationError', { error: error.message || error })
    setStatus(t('findings.validationFailed'), 'error')
  }
}

async function validateAll() {
  if (!findings.value.length) {
    setStatus(t('findings.addFindingsFirst'), 'error')
    return
  }

  // Send all findings — the Celery task handles cache-skip for findings
  // that already have guidance (regenerate=false), completing instantly.
  setStatus(t('findings.validatingCount', { count: findings.value.length }), 'info')

  const llm = getCurrentLlmSettingsForRequest()
  try {
    const data = await request('/api/generate/validation-guidance/bulk/async', {
      method: 'POST',
      body: JSON.stringify({
        report_id: reportId,
        finding_ids: findings.value.map(f => f.id),
        regenerate: false,
        llm_provider: llm.provider || null,
        llm_model: llm.model || null,
        llm_base_url: llm.baseUrl || null,
        llm_timeout: llm.timeout || null,
      })
    })

    // Pre-register so TaskBar shows tasks even if polling catches them after completion
    trackTaskIds(data.task_ids)
    nudge()  // Immediate poll + reset to fast-poll mode

    // Register completion callbacks for each task
    let completed = 0
    let failed = 0
    const total = data.task_ids.length

    for (const taskId of data.task_ids) {
      registerCompletionCallback(taskId, (fullTask) => {
        if (fullTask.status === 'completed' && fullTask.result_json) {
          try {
            const result = JSON.parse(fullTask.result_json)
            const idx = findings.value.findIndex(f => String(f.id) === String(fullTask.finding_id))
            if (idx !== -1) {
              findings.value[idx] = { ...findings.value[idx], validation_guidance: result.guidance || '' }
            }
          } catch {
            // Parse error — task still completed in TaskBar
          }
          completed++
        } else {
          failed++
        }
        acknowledgeTask(taskId)

        // Status update when all tasks are done
        if (completed + failed === total) {
          if (failed === 0) {
            setStatus(t('findings.validateAllComplete', { count: completed }), 'success')
          } else {
            setStatus(t('findings.validateAllPartial', { completed, failed }), 'error')
          }
        }
      })
    }
  } catch (error) {
    setStatus(t('findings.validationFailed'), 'error')
  }
}

async function copyValidationGuidance() {
  try {
    await navigator.clipboard.writeText(validationGuidance.value)
    setStatus(t('findings.validationCopied'), 'success')
  } catch (error) {
    setStatus(t('findings.validationCopyFailed'), 'error')
  }
}

/* ── Summaries ── */
async function generateSummariesAI() {
  if (!findings.value.length) {
    setStatus(t('findings.addFindingsFirst'), 'error')
    return
  }
  const llm = getCurrentLlmSettingsForRequest()
  generatingSummaries.value = true
  try {
    const data = await request('/api/generate/summaries/async', {
      method: 'POST',
      body: JSON.stringify({
        report_id: reportId,
        llm_provider: llm.provider || null,
        llm_model: llm.model || null,
        llm_base_url: llm.baseUrl || null,
        llm_timeout: llm.timeout || null,
        sampling_params: llm.samplingParams || null,
        locale: locale.value || null,
      }),
    })
    const taskId = data.task_id
    nudge()  // Immediate poll + reset to fast-poll mode
    registerCompletionCallback(taskId, (task) => {
      generatingSummaries.value = false
      if (task.status === 'completed' && task.result_json) {
        try {
          const result = JSON.parse(task.result_json)
          summaries.value = {
            executive: result.summary_executive || '',
            technical: result.summary_technical || '',
            recommendations: result.summary_recommendations || ''
          }
          reviewingTaskId.value = taskId
          showSummariesModal.value = true
          summariesStale.value = false
        } catch {
          setStatus(t('findings.failedGenerateSummaries'), 'error')
        }
      } else if (task.status === 'failed') {
        setStatus(task.error || t('findings.failedGenerateSummaries'), 'error')
      }
    })
  } catch (e) {
    generatingSummaries.value = false
    setStatus(formatApiError(e, 'findings.failedGenerateSummaries'), 'error')
  }
}

async function saveSummaries() {
  setStatus(t('findings.savingSummaries'), 'info')
  try {
    await request(`/api/admin/reports/${reportId}/summaries`, {
      method: 'PATCH',
      body: JSON.stringify({
        summary_executive: summaries.value.executive,
        summary_technical: summaries.value.technical,
        summary_recommendations: summaries.value.recommendations,
      }),
    })
    showSummariesModal.value = false
    _ackReviewTask()
    summariesStale.value = false
    await loadReport()
    setStatus(t('findings.summariesSaved'), 'success')
  } catch (e) {
    setStatus(formatApiError(e, 'findings.failedSaveSummaries'), 'error')
  }
}

function openSummariesModal() {
  showSummariesModal.value = true
}

async function consolidateSimilar() {
  if (findings.value.length < 2) {
    setStatus(t('findings.needTwoFindings'), 'error')
    return
  }

  const ok = await showConfirm({
    title: t('findings.consolidateConfirmTitle'),
    message: t('findings.consolidateConfirmMessage'),
    confirmLabel: t('findings.consolidateConfirmAction'),
    danger: true,
    extraAction: {
      label: t('findings.exportSarif'),
      handler: exportSarif,
    },
  })
  if (!ok) return

  consolidatingFindings.value = true
  setStatus(t('findings.analyzingConsolidating'), 'info')
  const llm = getCurrentLlmSettingsForRequest()
  try {
    const data = await request('/api/generate/consolidate', {
      method: 'POST',
      body: JSON.stringify({
        report_id: reportId,
        llm_provider: llm.provider || null,
        llm_model: llm.model || null,
        llm_base_url: llm.baseUrl || null,
        llm_timeout: llm.timeout || null,
        sampling_params: llm.samplingParams || null,
        locale: locale.value || null,
      }),
    })
    await loadFindings()
    expandedId.value = null
    summariesStale.value = true
    setStatus(data.message || t('findings.consolidatedCount', { count: data.merged_count || 0 }), 'success')
  } catch (e) {
    setStatus(formatApiError(e, 'findings.failedConsolidate'), 'error')
  } finally {
    consolidatingFindings.value = false
  }
}

/* ── Master DOCX ── */
function generateMaster() {
  if (!masterTemplate.value) return
  const hasSummaries = summaries.value.executive || summaries.value.technical || summaries.value.recommendations
  if (summariesStale.value && hasSummaries) {
    showStalePopover.value = true
    return
  }
  doGenerateMaster()
}

async function doGenerateMaster() {
  showStalePopover.value = false
  setStatus(t('findings.generatingMasterDocx'), 'info')
  try {
    const headers = await addCsrfHeader({ 'Content-Type': 'application/json' })

    const res = await fetch(`${import.meta.env.VITE_API_BASE || ''}/api/admin/master-docx`, {
      method: 'POST',
      credentials: 'include',
      headers,
      body: JSON.stringify({ report_id: reportId, template_name: masterTemplate.value }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    const blob = await res.blob()
    const filename = res.headers.get('Content-Disposition')?.match(/filename="?([^";]+)"?/)?.[1] || 'master.docx'
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = filename
    a.click()
    URL.revokeObjectURL(a.href)
    setStatus(t('findings.masterDocxDownloaded'), 'success')
  } catch (e) {
    setStatus(formatApiError(e, 'findings.failedGenerateMaster'), 'error')
    throw e
  }
}

function exportSarif() {
  window.open(`${import.meta.env.VITE_API_BASE || ''}/api/export/reports/${reportId}/sarif`, '_blank')
}

/* ── Helpers ── */
function severity(finding) {
  try {
    const c = JSON.parse(finding.content_json || '{}')
    let sev = (c.Severity || c.severity || '').toLowerCase().trim()
    // Normalize Burp's "information" to "informational"
    if (sev === 'information') sev = 'informational'
    return sev
  } catch { return '' }
}

function excerpt(finding) {
  try {
    const c = JSON.parse(finding.content_json || '{}')
    const summary = c['Vulnerability Summary'] || c['vulnerability_summary'] || c.summary || c['Summary'] || ''
    return summary.length > 80 ? summary.slice(0, 80) + '…' : summary
  } catch { return '' }
}

/* ── Tag filter for findings ── */
const findingTagMap = ref({})  // { findingId: ['tagA', 'tagB'] }
const filterFindingTag = ref('')
const findingTagOptions = computed(() => {
  const tagSet = new Set()
  for (const tags of Object.values(findingTagMap.value)) {
    for (const t of tags) tagSet.add(t)
  }
  return [...tagSet].sort()
})

async function loadFindingTags() {
  if (!findings.value.length) { findingTagMap.value = {}; return }
  const ids = findings.value.map(f => f.id).join(',')
  try {
    const tagMap = await request(`/api/admin/tags/entity-bulk/finding?ids=${encodeURIComponent(ids)}`)
    findingTagMap.value = tagMap || {}
  } catch { findingTagMap.value = {} }
}

// Re-fetch tags whenever findings list changes
watch(() => findings.value.length, () => { loadFindingTags() })

function onFindingTagClick(tagName) {
  filterFindingTag.value = filterFindingTag.value === tagName ? '' : tagName
}

// Computed property to sort findings by severity (highest to lowest)
const sortedFindings = computed(() => {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }
  let list = [...findings.value]
  if (filterFindingTag.value) {
    list = list.filter(f => (findingTagMap.value[f.id] || []).includes(filterFindingTag.value))
  }
  return list.sort((a, b) => {
    const sevA = severity(a) || 'informational'
    const sevB = severity(b) || 'informational'
    return (severityOrder[sevA] ?? 999) - (severityOrder[sevB] ?? 999)
  })
})

onMounted(async () => {
  forceCloseModals()
  await refetchOrgLlmSettings()
  await loadUserOrgRole()
  await loadReport()
  await loadFindings()
  loadFindingTags()
  loadFindingTemplates()
  loadMasterTemplates()
  await loadProviders()
  await loadVisionModels()
  await fetchConfidenceLevels()
  checkJiraConnector()

  // If navigated here with ?finding=UUID (e.g. from Trends), expand it and scroll/highlight
  const targetFinding = route.query.finding
  if (targetFinding && findings.value.some((f) => String(f.id) === String(targetFinding))) {
    expandedId.value = targetFinding
    await nextTick()
    await nextTick()
    setTimeout(() => {
      const el = document.getElementById(`finding-row-${targetFinding}`)
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' })
        el.style.transition = 'background 0.3s'
        el.style.background = 'rgba(13, 148, 136, 0.15)'
        setTimeout(() => { el.style.background = '' }, 2000)
      }
    }, 250)
  }
})
// When TaskBar "Review →" is clicked, navigate here with ?reviewTask=<id>
// and open the appropriate modal with the stored result.
watch(() => route.query.reviewTask, async (taskId) => {
  if (!taskId) return
  try {
    const task = await request(`/api/tasks/${taskId}`)
    if (!task || task.status !== 'completed' || !task.result_json) return
    if (task.task_type === 'regenerate_finding') {
      const structured = JSON.parse(task.result_json)
      const originalFinding = findings.value.find(f => String(f.id) === String(task.finding_id))
      const aiTitle = structured['Finding Title'] || structured['title'] || structured['Title'] || originalFinding?.title || ''
      reviewData.value = structured
      reviewTitle.value = aiTitle
      editId.value = task.finding_id || null
      // Populate editForm so reviewSave() → saveEdit() saves AI content with correct
      // template/notes; without this saveEdit() would overwrite the finding with empty sections.
      if (originalFinding) {
        const tpl = findingTemplates.value.find(ft => ft.name === originalFinding.template)
        editForm.value = {
          title: aiTitle,
          template_id: tpl ? String(tpl.id) : '',
          sections: _structuredToEditSections(structured),
          notes: originalFinding.notes || '',
          validation_guidance: originalFinding.validation_guidance || '',
          show_validation: !!originalFinding.validation_guidance,
        }
      }
      reviewingTaskId.value = taskId
      showReview.value = true
    } else if (task.task_type === 'generate_summaries') {
      const result = JSON.parse(task.result_json)
      summaries.value = {
        executive: result.summary_executive || '',
        technical: result.summary_technical || '',
        recommendations: result.summary_recommendations || ''
      }
      reviewingTaskId.value = taskId
      showSummariesModal.value = true
    }
    // Clear query param so back-navigation doesn't re-open the modal
    router.replace({ query: { ...route.query, reviewTask: undefined } })
  } catch (e) {
    setStatus(formatApiError(e, 'findings.failedGenerateFinding'), 'error')
  }
}, { immediate: true })

// When TaskBar "View →" is clicked for a validate_guidance task, navigate here with ?viewValidation=<findingId>
// and open the validation guidance modal for that finding.
watch(() => route.query.viewValidation, async (findingId) => {
  if (!findingId) return
  const finding = findings.value.find(f => String(f.id) === String(findingId))
  if (finding && finding.validation_guidance) {
    validationGuidanceFindingTitle.value = finding.title || t('findings.untitled')
    validationGuidanceFinding.value = finding
    validationGuidance.value = finding.validation_guidance
    generatingGuidance.value = false
    showValidationGuidance.value = true
  }
  router.replace({ query: { ...route.query, viewValidation: undefined } })
}, { immediate: true })


// When TaskBar "View →" is clicked for a generated/imported finding, scroll to and highlight it.
watch(() => route.query.finding, async (findingId) => {
  if (!findingId) return
  // Ensure findings are loaded (may have just been created)
  if (!findings.value.some(f => String(f.id) === String(findingId))) {
    await loadFindings()
  }
  if (findings.value.some(f => String(f.id) === String(findingId))) {
    expandedId.value = findingId
    await nextTick()
    await nextTick()
    setTimeout(() => {
      const el = document.getElementById(`finding-row-${findingId}`)
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' })
        el.style.transition = 'background 0.3s'
        el.style.background = 'rgba(13, 148, 136, 0.15)'
        setTimeout(() => { el.style.background = '' }, 2000)
      }
    }, 250)
  }
  router.replace({ query: { ...route.query, finding: undefined } })
}, { immediate: true })

// Auto-reload findings when import_finding tasks complete in the TaskBar.
// The old importQueuePolling was removed when TaskBar took over task visibility,
// but nothing replaced the loadFindings() call that fired when imports completed.
const _importCompletedCount = ref(0)
watch(
  () => {
    const tasks = getGenerationTasks()
    return tasks.filter(
      t => t.task_type === 'import_finding' && t.report_id === reportId && t.status === 'completed'
    ).length
  },
  (newCount) => {
    if (newCount > _importCompletedCount.value) {
      _importCompletedCount.value = newCount
      loadFindings()
    }
  }
)

onUnmounted(() => {
  // Unregister any in-flight completion callbacks — worker continues, result visible in TaskBar
  if (generatingFindingTaskId.value) {
    unregisterCompletionCallback(generatingFindingTaskId.value)
  }
  if (pendingVisionCursorPos.value !== null) {
    // Can't unregister by cursor pos alone — store task IDs if needed in future
  }
})
</script>

<template>
  <div class="report-findings-page" aria-labelledby="rf-page-title" aria-describedby="rf-page-desc">
  <header class="org-hero">
    <div class="org-title">
      <p class="kicker" id="rf-kicker">{{ $t('findings.reportKicker') }}</p>
      <h1 id="rf-page-title">{{ $t('findings.title') }}</h1>
      <p class="subtitle" id="rf-page-desc">{{ $t('findings.subtitle') }}</p>
    </div>
  </header>

  <!-- Breadcrumbs -->
  <nav v-if="report" class="breadcrumbs" aria-label="Breadcrumb">
    <button @click="navigateToReports" class="breadcrumb-link">
      {{ $t('findings.reports') }}
    </button>
    <span class="breadcrumb-separator">/</span>
    <span class="breadcrumb-current">{{ report.name }}</span>
    <span v-if="report" class="breadcrumb-meta">
      <span class="breadcrumb-meta-item">{{ client ? client.name : (report.client_id ? $t('reports.unknown') : $t('reports.unassigned')) }}</span>
      <span class="breadcrumb-meta-separator">·</span>
      <span class="breadcrumb-meta-item">{{ application ? application.name : (report.application_id ? $t('reports.unknown') : $t('reports.unassigned')) }}</span>
    </span>
  </nav>


  <!-- AI Disclaimer - always visible -->
  <div class="ai-disclaimer-banner" role="note" aria-label="AI content disclaimer">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="ai-disclaimer-icon">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
    <span>{{ $t('importQueue.aiDisclaimer') }}</span>
  </div>

  <!-- Hero: Paste area (primary) + Options (secondary) – golden-ratio hierarchy. Hidden for readonly. -->
  <section v-if="canEdit" class="report-findings-hero card" aria-labelledby="rf-hero-label">
    <p id="rf-hero-label" class="visually-hidden">Paste notes and generate findings</p>

    <div class="report-findings-hero-paste">
      <label for="finding-notes" class="hero-label-text">{{ $t('findings.pasteLabel') }}</label>
      <p class="muted hero-subtext">{{ $t('findings.pasteSubtext') }}</p>
      <div
        class="drop-zone drop-zone-hero"
        :class="{ 'drop-active': isDragging, 'drop-processing': processingPdf }"
        @dragover.prevent="handleDragOver"
        @dragenter.prevent="handleDragEnter"
        @dragleave.prevent="handleDragLeave"
        @drop.prevent="handleDrop"
        role="region"
        :aria-label="$t('findings.dropZoneAriaLabel')"
      >
        <div v-if="isDragging" class="drop-zone-overlay">{{ $t('findings.dropZoneText') }}</div>
        <textarea
          id="finding-notes"
          ref="notesTextareaRef"
          v-model="form.notes"
          @paste="handlePaste"
          rows="10"
          :placeholder="$t('findings.notesPlaceholder')"
          :aria-label="$t('findings.notesAriaLabel')"
          aria-describedby="finding-notes-hint"
          :disabled="processingPdf"
        ></textarea>
        <div v-if="processingPdf" class="drop-zone-processing">
          <div class="processing-spinner"></div>
          <span>{{ $t('findings.parsingPdf') }}</span>
        </div>
      </div>
      <p id="finding-notes-hint" class="hint">{{ $t('findings.notesHint') }}</p>
    </div>

    <div class="report-findings-hero-options">
      <div class="hero-options-inner">
        <label for="finding-template">{{ $t('findings.templateLabel') }}</label>
        <select id="finding-template" v-model="form.template_id" :aria-label="$t('findings.templateAriaLabel')">
          <option value="">{{ $t('findings.templateNone') }}</option>
          <option v-for="t in findingTemplates" :key="t.id" :value="String(t.id)">{{ t.name }}</option>
        </select>
        <p class="hint" v-if="!findingTemplates.length">{{ $t('findings.noTemplatesHint') }} <RouterLink to="/dashboard/templates" class="link-primary">{{ $t('dashboard.navTemplates') }}</RouterLink></p>

        <label for="finding-title">{{ $t('findings.titleOptional') }}</label>
        <input id="finding-title" v-model="form.title" :placeholder="$t('findings.titlePlaceholder')" :aria-label="$t('findings.titleAriaLabel')" />

        <label for="severity-override">{{ $t('severity.overrideLabel') }}</label>
        <select id="severity-override" v-model="severityOverride" :aria-label="$t('severity.overrideLabel')">
          <option value="">{{ $t('severity.autoDetect') }}</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>

        <template v-if="severityOverride">
          <label for="severity-reason">
            {{ $t('severity.justification') }}
            <span style="color: var(--error);">*</span>
          </label>
          <textarea
            id="severity-reason"
            v-model="severityReason"
            :placeholder="$t('severity.justificationPlaceholder')"
            rows="3"
            :aria-label="$t('severity.justification')"
          ></textarea>
          <p class="hint">{{ $t('severity.justificationHint') }}</p>
        </template>

        <div class="row hero-checkboxes">
          <label for="use-ai" class="inline">
            <input id="use-ai" type="checkbox" v-model="useAi" :aria-label="$t('findings.useAiAriaLabel')" />
            {{ $t('findings.useAi') }}
          </label>
          <label for="self-check" class="inline">
            <input id="self-check" type="checkbox" v-model="selfCheck" :aria-label="$t('findings.selfCheckAriaLabel')" />
            {{ $t('findings.selfCheck') }}
          </label>
        </div>

        <div class="actions hero-actions">
          <button @click="generateFinding" class="btn-primary" :disabled="!useAi || !!generatingFindingTaskId" :aria-label="$t('findings.generateAriaLabel')" :title="!useAi ? $t('findings.generateRequiresAi') : undefined">{{ $t('findings.generateButton') }}</button>
          <button class="secondary" @click="addFinding">{{ $t('findings.saveManual') }}</button>
        </div>
      </div>
    </div>
  </section>

  <!-- Verification log -->
  <section v-if="verificationLog.length" class="card report-findings-secondary" aria-labelledby="verification-log-heading">
    <h2 id="verification-log-heading" class="section-header">{{ $t('findings.verificationLog') }}</h2>
    <div v-for="(entry, idx) in verificationLog" :key="idx" class="verification-entry">
      <strong>{{ $t('findings.verificationPass', { n: idx + 1 }) }}</strong> {{ entry }}
    </div>
  </section>

  <!-- Findings section with tabs -->
  <section class="findings-section" aria-labelledby="findings-heading">
    <h2 id="findings-heading" class="visually-hidden">Findings list and preview</h2>
    <div class="findings-toolbar">
      <div v-if="findings.length" style="flex:1;min-width:0;display:flex;align-items:center">
        <span class="findings-count">{{ $t('findings.tabList', { count: findings.length }) }}</span>
      </div>
      <div class="findings-toolbar-actions">
        <button
          v-if="findings.length && canEdit"
          :class="['secondary', selectionMode && 'active']"
          @click="toggleSelectionMode"
          :aria-label="$t('findings.selectModeAriaLabel')"
        >
          {{ selectionMode ? $t('findings.exitSelect') : $t('findings.select') }}
        </button>
        <RouterLink
          v-if="findings.length && !selectionMode"
          :to="`/dashboard/reports/${reportId}/read`"
          class="secondary reader-link"
          target="_blank"
          :title="$t('findings.readerViewTitle')"
          :aria-label="$t('findings.readerViewAriaLabel')"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
          {{ $t('findings.readerView') }}
        </RouterLink>
        <button
          v-if="!selectionMode && canEdit"
          class="secondary"
          :disabled="findings.length < 2 || consolidatingFindings"
          @click="consolidateSimilar"
          :title="$t('findings.consolidateTitle')"
          :aria-label="$t('findings.consolidateAriaLabel')"
        >
          <span v-if="consolidatingFindings" class="btn-spinner" aria-hidden="true"></span>
          {{ consolidatingFindings ? $t('findings.consolidating') : $t('findings.consolidateSimilar') }}
        </button>
        <button
          v-if="findings.length && !selectionMode && canEdit"
          class="secondary"
          @click="validateAll"
          :title="$t('findings.validateAllTitle')"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 11l3 3L22 4"/>
            <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
          </svg>
          {{ $t('findings.validateAll') }}
        </button>
      </div>
    </div>

    <!-- Tag filter bar (only when tags exist) -->
    <div v-if="findingTagOptions.length" class="findings-tag-filter">
      <span class="findings-tag-filter-label">{{ $t('findings.filterByTag') }}</span>
      <button
        v-for="tagName in findingTagOptions"
        :key="tagName"
        :class="['findings-tag-chip', filterFindingTag === tagName && 'findings-tag-chip-active']"
        @click="onFindingTagClick(tagName)"
      >{{ tagName }}</button>
      <button v-if="filterFindingTag" class="findings-tag-clear" @click="filterFindingTag = ''">{{ $t('common.reset') }}</button>
    </div>

    <!-- Findings list -->
    <div id="panel-list" class="card findings-panel" tabindex="0">
      <div class="table-wrapper" v-if="findings.length">
        <table class="table">
          <thead>
            <tr>
              <th v-if="selectionMode" style="width:40px">
                <input 
                  type="checkbox" 
                  :checked="selectedCount === findings.length && findings.length > 0"
                  @change="selectedCount === findings.length ? clearSelection() : selectAll()"
                  :aria-label="$t('findings.selectAllAriaLabel')"
                  class="bulk-checkbox"
                />
              </th>
              <th v-else></th>
              <th>{{ $t('findings.tableTitle') }}</th>
              <th>{{ $t('findings.tableSeverity') }}</th>
              <th>{{ $t('findings.tableSummary') }}</th>
              <th style="width:180px">{{ $t('findings.tableActions') }}</th>
            </tr>
          </thead>
          <tbody v-for="finding in sortedFindings" :key="finding.id" :id="`finding-row-${finding.id}`">
          <tr class="clickable" :class="{ 'selected': selectionMode && selectedFindings.has(finding.id) }" @click="selectionMode ? toggleSelection(finding.id) : toggleExpand(finding.id)">
            <td v-if="selectionMode" style="width:40px;padding-right:0" @click.stop>
              <input 
                type="checkbox" 
                :checked="selectedFindings.has(finding.id)"
                @change="toggleSelection(finding.id)"
                :aria-label="$t('findings.selectFindingAriaLabel', { title: finding.title })"
                class="bulk-checkbox"
              />
            </td>
            <td v-else style="width:24px;padding-right:0">
              <span :class="['chevron', expandedId === finding.id && 'open']">&#9654;</span>
            </td>
            <td>{{ finding.title || $t('findings.untitled') }}</td>
            <td><span v-if="severity(finding)" :class="['pill', severity(finding)]">{{ severity(finding) }}</span></td>
            <td class="muted">{{ excerpt(finding) }}</td>
            <td @click.stop>
              <div class="actions">
                <a v-if="finding.jira_issue_key" 
                   :href="finding.jira_issue_url" 
                   target="_blank" 
                   rel="noopener noreferrer"
                   class="jira-link"
                   style="display:inline-flex;align-items:center;gap:4px;padding:6px 10px;background:var(--background-secondary);border-radius:4px;text-decoration:none;color:var(--text);font-size:0.9em;border:1px solid var(--border)"
                   :title="$t('findings.viewJiraTicket')">
                  {{ finding.jira_issue_key }}
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3"/>
                  </svg>
                  <button v-if="canEdit" @click.prevent="unlinkJiraTicket(finding)" class="unlink-btn" :title="$t('findings.unlinkJira')" style="margin-left:4px;padding:2px 4px;background:transparent;border:none;cursor:pointer;color:var(--text-muted);font-size:16px">&times;</button>
                </a>
                <button v-else-if="jiraEnabled && canEdit" class="secondary" @click="openJiraModal(finding)" :title="$t('findings.createJiraTicket')">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2L2 12h3v8h6v-6h2v6h6v-8h3L12 2z"/>
                  </svg>
                  {{ $t('findings.jira') }}
                </button>
                <button v-if="canEdit" class="secondary" @click="startEdit(finding)">{{ $t('common.edit') }}</button>
                <button v-if="canEdit" class="secondary" @click="generateValidationGuidance(finding)" :title="$t('findings.generateValidationTitle')">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M9 11l3 3L22 4"/>
                    <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
                  </svg>
                  {{ $t('findings.validate') }}
                </button>
                <button
                  v-if="canEdit"
                  class="secondary"
                  :disabled="regeneratingFindingId === finding.id || pendingRegenFindings.has(finding.id)"
                  @click.stop="regenerateFinding(finding)"
                  :title="pendingRegenFindings.has(finding.id) ? $t('findings.regeneratePendingReview') : $t('findings.regenerateTitle')"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 4v6h6"/>
                    <path d="M3.51 15a9 9 0 105.68-9.19L1 10"/>
                  </svg>
                  {{ regeneratingFindingId === finding.id ? $t('findings.regenerating') : $t('findings.regenerateButton') }}
                </button>
                <button v-if="canEdit" class="danger" @click="removeFinding(finding.id)">{{ $t('common.delete') }}</button>
              </div>
            </td>
          </tr>
          <tr v-if="expandedId === finding.id && !selectionMode" class="expand-row">
            <td colspan="5">
              <div class="expand-content">
                <div style="margin-bottom:10px">
                  <TagInput entityType="finding" :entityId="finding.id" :readonly="!canEdit" @tag-click="onFindingTagClick" @tags-changed="loadFindingTags" />
                </div>
                
                <!-- In-place edit form (when editId === finding.id) -->
                <div v-if="editId === finding.id" class="inline-edit-form">
                  <div class="form-section">
                    <label for="edit-title">{{ $t('findings.findingTitle') }}</label>
                    <input 
                      id="edit-title" 
                      v-model="editForm.title" 
                      type="text"
                      class="edit-input"
                      :placeholder="$t('findings.titlePlaceholder')"
                    />
                  </div>
                  
                  <div class="form-section">
                    <label for="edit-template">{{ $t('findings.template') }}</label>
                    <select id="edit-template" v-model="editForm.template_id" class="edit-select">
                      <option value="">{{ $t('findings.noTemplate') }}</option>
                      <option v-for="tpl in findingTemplates" :key="tpl.id" :value="String(tpl.id)">
                        {{ tpl.name }}
                      </option>
                    </select>
                  </div>
                  
                  <!-- Meta fields with specialized editors -->
                  <div class="meta-fields-section">
                    <h4>{{ $t('findings.metaFields') }}</h4>
                    <div class="meta-display">
                      <div v-for="metaKey in META_KEYS" :key="metaKey" class="meta-field-row">
                        <span class="meta-label">{{ metaKey }}:</span>
                        <span class="meta-value">
                          <!-- Inline editing for non-modal fields -->
                          <template v-if="editingMetaField && editingMetaField.findingId === finding.id && editingMetaField.key === metaKey">
                            <input 
                              v-model="editingMetaField.value" 
                              @keyup.enter="saveMetaField"
                              @keyup.esc="cancelEditingMeta"
                              @blur="saveMetaField"
                              class="inline-edit-input"
                              autofocus
                            />
                          </template>
                          <!-- Display mode -->
                          <template v-else>
                            <span v-if="metaKey === 'Severity' && editForm.sections._meta && editForm.sections._meta[metaKey]" :class="['pill', editForm.sections._meta[metaKey].toLowerCase()]">
                              {{ editForm.sections._meta[metaKey] }}
                            </span>
                            <span v-else-if="editForm.sections._meta && editForm.sections._meta[metaKey]">
                              {{ editForm.sections._meta[metaKey] }}
                            </span>
                            <span v-else class="muted">{{ $t('findings.notProvided') }}</span>
                            <button 
                              @click.stop="startEditingMeta(finding.id, metaKey, editForm.sections._meta ? editForm.sections._meta[metaKey] : '')"
                              class="link-btn modify-btn"
                            >
                              [modify]
                            </button>
                          </template>
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <!-- Editable structured sections -->
                  <div v-for="sectionKey in PROSE_KEYS" :key="sectionKey" class="form-section">
                    <label :for="'edit-' + sectionKey">{{ sectionKey }}</label>
                    <textarea 
                      :id="'edit-' + sectionKey"
                      v-model="editForm.sections[sectionKey]"
                      rows="4"
                      class="edit-textarea"
                      :placeholder="'Enter ' + sectionKey.toLowerCase() + '...'"
                    ></textarea>
                  </div>

                  <div v-if="editForm.show_validation" class="form-section">
                    <label for="edit-validation-guidance">{{ $t('findings.validationTab') }}</label>
                    <textarea
                      id="edit-validation-guidance"
                      v-model="editForm.validation_guidance"
                      rows="4"
                      class="edit-textarea"
                      :placeholder="$t('findings.notesPlaceholder')"
                    ></textarea>
                  </div>
                  
                  <!-- Unsaved changes warning -->
                  <div v-if="hasUnsavedEditChanges" class="unsaved-changes-banner">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; margin-right: 8px;">
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="12" y1="8" x2="12" y2="12"/>
                      <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    {{ $t('findings.unsavedChanges') }}
                  </div>
                  
                  <div class="edit-actions">
                    <button type="button" @click="cancelEdit" class="btn-secondary">{{ $t('common.cancel') }}</button>
                    <button type="button" @click="saveEdit" class="btn-primary" :class="{ 'btn-pulse': hasUnsavedEditChanges }">
                      {{ $t('common.save') }}
                      <span v-if="hasUnsavedEditChanges" class="unsaved-indicator">●</span>
                    </button>
                  </div>
                </div>
                
                <!-- Structured preview (grayed out when editing) -->
                <div class="finding-preview" v-if="parseContent(finding.content_json)" :class="{ 'preview-dimmed': editId === finding.id }">
                  <div class="fp-title">{{ finding.title }}</div>
                  <div class="fp-meta" v-if="getMetaEntries(parseContent(finding.content_json)).length">
                    <template v-for="m in getMetaEntries(parseContent(finding.content_json))" :key="m.key">
                      <span class="fp-meta-key">{{ m.key }}</span>
                      <span class="fp-meta-val">
                        <!-- Inline editing for editable meta fields -->
                        <template v-if="editingMetaField && editingMetaField.findingId === finding.id && editingMetaField.key === m.key">
                          <input 
                            v-model="editingMetaField.value" 
                            @keyup.enter="saveMetaField"
                            @keyup.esc="cancelEditingMeta"
                            @blur="saveMetaField"
                            class="inline-edit-input"
                            ref="metaEditInput"
                            autofocus
                          />
                        </template>
                        <!-- Display mode -->
                        <template v-else>
                          <span v-if="m.key === 'Severity'">
                            <span :class="['pill', m.val.toLowerCase()]">{{ m.val }}</span>
                            <button 
                              v-if="editId === finding.id"
                              @click.stop="startEditingMeta(finding.id, m.key, m.val)"
                              class="link-btn modify-btn"
                            >
                              [modify]
                            </button>
                          </span>
                          <span v-else-if="!m.val && EDITABLE_META_KEYS.includes(m.key) && editId === finding.id">
                            <button 
                              @click.stop="startEditingMeta(finding.id, m.key, m.val)"
                              class="link-btn"
                            >
                              [modify]
                            </button>
                          </span>
                          <span v-else-if="m.val">
                            <template v-for="(part, idx) in hyperlinkMetaParts(m.key, m.val)" :key="idx">
                              <a v-if="part.href" :href="part.href" target="_blank" rel="noopener noreferrer">{{ part.text }}</a>
                              <span v-else>{{ part.text }}</span>
                            </template>
                            <!-- [modify] link for editable fields with values -->
                            <button 
                              v-if="EDITABLE_META_KEYS.includes(m.key) && editId === finding.id"
                              @click.stop="startEditingMeta(finding.id, m.key, m.val)"
                              class="link-btn modify-btn"
                            >
                              [modify]
                            </button>
                          </span>
                        </template>
                      </span>
                    </template>
                  </div>
                  <div
                    v-for="s in getProseEntriesForFinding(finding)"
                    :key="s.key"
                    class="fp-section"
                  >
                    <div class="fp-section-title">{{ s.key }}</div>
                    <div v-if="s.key === $t('findings.validationTab')" class="fp-section-body markdown-prose" v-html="renderMarkdown(s.val)"></div>
                    <div v-else class="fp-section-body">
                      <template v-for="(part, pidx) in linkifyProse(s.val)" :key="pidx">
                        <a v-if="part.href" :href="part.href" target="_blank" rel="noopener noreferrer">{{ part.text }}</a>
                        <span v-else>{{ part.text }}</span>
                      </template>
                    </div>
                  </div>
                  <p v-if="!getProseEntriesForFinding(finding).length && !getMetaEntries(parseContent(finding.content_json)).length" class="muted">
                    {{ $t('findings.noStructuredContent') }}
                  </p>
                </div>
              </div>
            </td>
          </tr>
        </tbody>
        </table>
      </div>
      <p v-else class="muted">{{ $t('findings.noFindingsYet') }}</p>
    </div>

    <!-- Bulk actions toolbar (floating, appears when selections made) -->
    <Transition name="slide-up">
      <div v-if="selectionMode && selectedCount > 0" class="bulk-actions-bar">
        <div class="bulk-actions-info">
          <span class="bulk-count">{{ $t('findings.selectedCount', { count: selectedCount }) }}</span>
          <button class="link-btn" @click="selectAll">{{ $t('findings.selectAll') }}</button>
          <button class="link-btn" @click="clearSelection">{{ $t('findings.clearSelection') }}</button>
        </div>
        <div class="bulk-actions-buttons">
          <button v-if="canEdit" class="secondary" @click="bulkRegenerate" :aria-label="$t('findings.bulkRegenerateAriaLabel', { count: selectedCount })">
            {{ $t('findings.bulkRegenerate', { count: selectedCount }) }}
          </button>
          <button v-if="canEdit" class="secondary" @click="bulkRevalidate" :aria-label="$t('findings.bulkRevalidateAriaLabel', { count: selectedCount })">
            {{ $t('findings.bulkRevalidate', { count: selectedCount }) }}
          </button>
          <button class="danger" @click="bulkDelete">
            {{ $t('findings.deleteSelected', { count: selectedCount }) }}
          </button>
        </div>
      </div>
    </Transition>
  </section>

  <!-- Summaries -->
  <section class="card report-findings-secondary" aria-labelledby="summaries-heading">
    <h2 id="summaries-heading" class="section-header">{{ $t('findings.summariesHeading') }}</h2>
    <p class="muted" style="margin:0 0 16px">{{ $t('findings.summariesDesc') }}</p>

    <div v-if="canEdit" class="actions">
      <button @click="generateSummariesAI" :disabled="!findings.length || generatingSummaries">
        {{ generatingSummaries ? $t('findings.generatingSummaries') : $t('findings.generateSummaries') }}
      </button>
      <button v-if="summaries.executive || summaries.technical || summaries.recommendations"
              class="secondary" @click="openSummariesModal">
        {{ $t('findings.viewEditSummaries') }}
      </button>
    </div>

    <div v-if="summaries.executive || summaries.technical || summaries.recommendations"
         style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
      <div style="display:grid;gap:12px;font-size:13px">
        <div v-if="summaries.executive">
          <strong class="muted">{{ $t('findings.executiveSummaryLabel') }}</strong>
          <p style="margin:4px 0 0;color:var(--text-secondary)">{{ summaries.executive.slice(0, 150) }}{{ summaries.executive.length > 150 ? '...' : '' }}</p>
        </div>
        <div v-if="summaries.technical">
          <strong class="muted">{{ $t('findings.technicalSummaryLabel') }}</strong>
          <p style="margin:4px 0 0;color:var(--text-secondary)">{{ summaries.technical.slice(0, 150) }}{{ summaries.technical.length > 150 ? '...' : '' }}</p>
        </div>
        <div v-if="summaries.recommendations">
          <strong class="muted">{{ $t('findings.recommendationsLabel') }}</strong>
          <p style="margin:4px 0 0;color:var(--text-secondary)">{{ summaries.recommendations.slice(0, 150) }}{{ summaries.recommendations.length > 150 ? '...' : '' }}</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Master DOCX export -->
  <section class="card report-findings-secondary" aria-labelledby="master-export-heading">
    <h2 id="master-export-heading" class="section-header">{{ $t('findings.exportMasterHeading') }}</h2>
    <div v-if="canEdit" class="row">
      <div>
        <label for="master-template">{{ $t('findings.masterTemplateLabel') }}</label>
        <select id="master-template" v-model="masterTemplate" :aria-label="$t('findings.masterTemplateAriaLabel')">
          <option value="">{{ $t('findings.masterSelect') }}</option>
          <option v-for="name in masterTemplates" :key="name" :value="name">{{ name }}</option>
        </select>
      </div>
      <div class="actions" style="align-items:flex-end;position:relative">
        <button @click="generateMaster" :disabled="!masterTemplate" :aria-label="$t('findings.exportMasterAriaLabel')">{{ $t('findings.exportMasterDocx') }}</button>
        <Transition name="popover">
          <div v-if="showStalePopover" class="stale-popover" role="alertdialog" :aria-label="$t('findings.stalePopoverAriaLabel')">
            <div class="stale-popover-arrow"></div>
            <div class="stale-popover-body">
              <p class="stale-popover-msg">{{ $t('findings.stalePopoverMsg') }}</p>
              <div class="stale-popover-actions">
                <button @click="showStalePopover = false; generateSummariesAI()" class="btn-primary stale-popover-btn">{{ $t('findings.updateSummaries') }}</button>
                <button @click="doGenerateMaster()" class="secondary stale-popover-btn">{{ $t('findings.exportAnyway') }}</button>
                <button @click="showStalePopover = false" class="ghost stale-popover-btn">{{ $t('common.cancel') }}</button>
              </div>
            </div>
          </div>
        </Transition>
      </div>
    </div>
  </section>

  <!-- Programmatic Export -->
  <section class="card report-findings-secondary" aria-labelledby="sarif-export-heading">
    <h2 id="sarif-export-heading" class="section-header">{{ $t('findings.programmaticExportHeading') }}</h2>
    <div class="row">
      <div style="flex: 1">
        <p class="muted" style="margin: 0">{{ $t('findings.programmaticExportDesc') }}</p>
      </div>
      <div class="actions" style="align-items:flex-end">
        <button class="secondary" @click="exportSarif">{{ $t('findings.exportSarif') }}</button>
      </div>
    </div>
  </section>

  <!-- ── Review modal (post-generation) ── -->
  <Modal v-if="showReview" :title="$t('findings.reviewModalTitle')" :wide="true" @close="reviewClose">
    <div class="finding-preview">
      <!-- Editable title -->
      <div style="margin-bottom:16px">
        <label for="review-title">{{ $t('findings.tableTitle') }}</label>
        <input id="review-title" v-model="reviewTitle" style="font-size:16px;font-weight:600" :aria-label="$t('findings.titleAriaLabel')" />
      </div>

      <!-- Metadata -->
      <div class="fp-meta" v-if="getMetaEntries(reviewData).length">
        <template v-for="m in getMetaEntries(reviewData)" :key="m.key">
          <span class="fp-meta-key">{{ m.key }}</span>
          <span class="fp-meta-val">
            <span v-if="m.key === 'Severity'" :class="['pill', m.val.toLowerCase()]">{{ m.val }}</span>
            <span v-else>
              <template v-for="(part, idx) in hyperlinkMetaParts(m.key, m.val)" :key="idx">
                <a v-if="part.href" :href="part.href" target="_blank" rel="noopener noreferrer">{{ part.text }}</a>
                <span v-else>{{ part.text }}</span>
              </template>
            </span>
          </span>
        </template>
      </div>

      <!-- Prose sections -->
      <div
        v-for="s in getProseEntries(reviewData)"
        :key="s.key"
        class="fp-section"
      >
        <div class="fp-section-title">{{ s.key }}</div>
        <div class="fp-section-body">
          <template v-for="(part, pidx) in linkifyProse(s.val)" :key="pidx">
            <a v-if="part.href" :href="part.href" target="_blank" rel="noopener noreferrer">{{ part.text }}</a>
            <span v-else>{{ part.text }}</span>
          </template>
        </div>
      </div>

      <!-- Verification log inside modal -->
      <div v-if="verificationLog.length" style="margin-top:16px;padding-top:12px;border-top:1px solid #1e293b">
        <div class="fp-section-title" style="margin-bottom:8px">{{ $t('findings.verificationLog') }}</div>
        <div v-for="(entry, idx) in verificationLog" :key="idx" style="margin-bottom:6px;font-size:12px;color:#ddebff">
          <strong>{{ $t('findings.verificationPass', { n: idx + 1 }) }}</strong> {{ entry }}
        </div>
      </div>
    </div>

    <!-- Actions -->
    <div class="actions" style="margin-top:20px;justify-content:flex-end;padding-top:16px;border-top:1px solid #1e293b">
      <button class="danger" @click="reviewDiscard">{{ $t('findings.discard') }}</button>
      <button class="secondary" @click="reviewClose">{{ $t('findings.closeKeepInForm') }}</button>
      <button @click="reviewSave">{{ $t('findings.saveToReport') }}</button>
    </div>
  </Modal>

  <!-- ── Summaries modal ── -->
  <Modal v-if="showSummariesModal" :title="$t('findings.summariesModalTitle')" :wide="true" @close="showSummariesModal = false">
    <div style="display:grid;gap:20px">
      <div>
        <label for="summary-executive">{{ $t('reportReader.executiveSummary') }}</label>
        <textarea id="summary-executive" v-model="summaries.executive" rows="6"
                  :placeholder="$t('findings.executiveSummaryPlaceholder')"
                  :aria-label="$t('findings.executiveSummaryAriaLabel')"></textarea>
        <p class="hint">{{ $t('findings.executiveSummaryHint') }}</p>
      </div>

      <div>
        <label for="summary-technical">{{ $t('reportReader.technicalSummary') }}</label>
        <textarea id="summary-technical" v-model="summaries.technical" rows="6"
                  :placeholder="$t('findings.technicalSummaryPlaceholder')"
                  :aria-label="$t('findings.technicalSummaryAriaLabel')"></textarea>
        <p class="hint">{{ $t('findings.technicalSummaryHint') }}</p>
      </div>

      <div>
        <label for="summary-recommendations">{{ $t('reportReader.recommendations') }}</label>
        <textarea id="summary-recommendations" v-model="summaries.recommendations" rows="6"
                  :placeholder="$t('findings.recommendationsPlaceholder')"
                  :aria-label="$t('findings.recommendationsAriaLabel')"></textarea>
        <p class="hint">{{ $t('findings.recommendationsHint') }}</p>
      </div>
    </div>

    <div class="actions" style="margin-top:20px;justify-content:flex-end;padding-top:16px;border-top:1px solid #1e293b">
      <button class="secondary" @click="showSummariesModal = false; _ackReviewTask()" :aria-label="$t('findings.cancelEditingSummariesAriaLabel')">{{ $t('common.cancel') }}</button>
      <button @click="saveSummaries" :aria-label="$t('findings.saveSummariesAriaLabel')">{{ $t('findings.saveSummariesButton') }}</button>
    </div>
  </Modal>

  <!-- ── Jira modal ── -->
  <Modal v-if="showJiraModal" :title="$t('findings.jiraModalTitle')" @close="showJiraModal = false">
    <div style="display:grid;gap:16px">
      <div>
        <label for="jira-finding">{{ $t('findings.jiraFindingLabel') }}</label>
        <input id="jira-finding" :value="selectedFinding?.title || $t('findings.untitled')" disabled style="background:var(--bg-input);opacity:0.7" :aria-label="$t('findings.titleAriaLabel')" />
      </div>

      <div>
        <label for="jira-project">{{ $t('findings.jiraProjectLabel') }}</label>
        <input
          id="jira-project"
          v-model="jiraProjectSearch"
          :placeholder="$t('findings.jiraProjectPlaceholder')"
          :aria-label="$t('findings.jiraProjectAriaLabel')"
          @input="selectedProject = null"
        />
        <div v-if="jiraProjectSearch && filteredProjects.length"
             style="margin-top:8px;max-height:200px;overflow-y:auto;border:1px solid var(--border);border-radius:8px">
          <button
            v-for="project in filteredProjects"
            :key="project.id"
            @click="selectedProject = project; jiraProjectSearch = `${project.key} - ${project.name}`"
            style="display:block;width:100%;text-align:left;padding:10px 12px;border:none;background:transparent;color:var(--text-primary);cursor:pointer;transition:background 0.15s"
            :style="selectedProject?.id === project.id ? 'background:var(--bg-hover-solid)' : ''"
            @mouseover="e => e.target.style.background = 'var(--bg-hover-solid)'"
            @mouseout="e => { if (selectedProject?.id !== project.id) e.target.style.background = 'transparent' }"
          >
            <strong>{{ project.key }}</strong> - {{ project.name }}
          </button>
        </div>
        <p class="hint">{{ $t('findings.jiraProjectHint') }}</p>
      </div>

      <div v-if="selectedProject" style="padding:12px;background:var(--bg-meta);border-radius:8px;border:1px solid var(--border)">
        <div style="font-size:13px;color:var(--text-muted)">{{ $t('findings.selectedProject') }}</div>
        <div style="font-weight:600;margin-top:4px">{{ selectedProject.key }} - {{ selectedProject.name }}</div>
      </div>
    </div>

    <div class="actions" style="margin-top:20px;justify-content:flex-end;padding-top:16px;border-top:1px solid var(--border)">
      <button class="secondary" @click="showJiraModal = false" :aria-label="$t('findings.cancelJiraAriaLabel')">{{ $t('common.cancel') }}</button>
      <button @click="createJiraIssue" :disabled="!selectedProject || creatingJiraIssue" :aria-label="$t('findings.createJiraTicketAriaLabel')">
        {{ creatingJiraIssue ? $t('findings.creatingJira') : $t('findings.createTicket') }}
      </button>
    </div>
  </Modal>

  <!-- Finding Workflow Modal (session mode, survives navigation) -->
  <finding-workflow 
    :show="showWorkflow"
    :session-id="workflowSessionId"
    :report-id="reportId"
    :tasks="workflowTasks"
    :fileName="workflowFileName"
    @close="closeWorkflow"
    @finished="onWorkflowFinished"
  />

  <!-- Image Processing Confirmation Modal -->
  <Modal
    v-if="showImageConfirm"
    @close="() => { showImageConfirm = false; pendingImageFile = null; pendingImageCursorPos = null }"
    :title="$t('findings.processImageTitle')"
    size="medium"
  >
    <div class="image-confirm-content">
      <p>{{ $t('findings.processImageQuestion') }}</p>
      <div class="image-options">
        <div class="option-card">
          <h4>🔤 {{ $t('findings.useOcrOption') }}</h4>
          <p>{{ $t('findings.useOcrOptionDesc') }}</p>
          <button @click="confirmImageProcessing('ocr')" class="primary">
            {{ $t('findings.extractWithOcr') }}
          </button>
        </div>
        <div class="option-card">
          <h4>🤖 {{ $t('findings.useAiOption') }}</h4>
          <p>{{ $t('findings.useAiOptionDesc') }}</p>
          <button @click="confirmImageProcessing('ai')" class="secondary">
            {{ $t('findings.processWithAi') }}
          </button>
        </div>
        <div class="option-card">
          <h4>📎 {{ $t('findings.insertWithoutAi') }}</h4>
          <p>{{ $t('findings.insertWithoutAiDesc') }}</p>
          <button @click="confirmImageProcessing('insert')" class="secondary">
            {{ $t('findings.insertImage') }}
          </button>
        </div>
      </div>
    </div>
  </Modal>

  <!-- Configure AI (when Process with AI chosen but provider/vision not set) -->
  <Modal
    v-if="showLlmRequiredModal"
    :title="$t('findings.configureAiTitle')"
    size="medium"
    @close="showLlmRequiredModal = false"
  >
    <div class="llm-required-content">
      <p class="llm-required-warning">
        {{ $t('findings.configureAiWarning') }}
      </p>
      <div class="llm-required-fields">
        <div>
          <label for="llm-required-provider">{{ $t('findings.providerLabel') }}</label>
          <select
            id="llm-required-provider"
            v-model="provider"
            :aria-label="$t('findings.providerAriaLabel')"
            @change="onProviderChange"
          >
            <optgroup :label="$t('llmConfig.cloudProviders')">
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="gemini">Google Gemini</option>
              <option value="groq">Groq</option>
              <option value="together">Together AI</option>
              <option value="deepseek">DeepSeek</option>
              <option value="mistral">Mistral</option>
            </optgroup>
            <optgroup :label="$t('llmConfig.selfHosted')">
              <option value="ollama">Ollama</option>
              <option value="openai_compatible">OpenAI-Compatible</option>
            </optgroup>
          </select>
        </div>
        <div v-if="provider && provider !== 'openai'">
          <label for="llm-required-baseurl">{{ $t('findings.baseUrlLabel') }}</label>
          <input
            id="llm-required-baseurl"
            v-model="baseUrl"
            :placeholder="PROVIDER_PRESETS[provider]?.baseUrl || 'https://api.example.com/v1'"
            :aria-label="$t('findings.baseUrlAriaLabel')"
            @change="() => { loadModelOptions(); loadVisionModels() }"
          />
        </div>
        <div>
          <label for="llm-required-vision">{{ $t('findings.visionModelLabel') }}</label>
          <select
            id="llm-required-vision"
            v-model="visionModel"
            :aria-label="$t('findings.visionModelAriaLabel')"
          >
            <option value="">{{ $t('findings.selectModel') }}</option>
            <option v-for="vm in visionModels" :key="vm" :value="vm">{{ vm }}</option>
          </select>
          <p v-if="!visionModels.length && provider === 'ollama'" class="hint">{{ $t('findings.noVisionModelsHint', { command: 'ollama pull llava' }) }}</p>
        </div>
      </div>
    </div>
    <div class="actions" style="margin-top:16px;justify-content:flex-end;padding-top:16px;border-top:1px solid var(--border)">
      <button class="secondary" @click="showLlmRequiredModal = false">{{ $t('common.cancel') }}</button>
      <button
        class="primary"
        :disabled="!visionModel"
        @click="saveLlmRequiredAndClose"
      >
        {{ $t('findings.saveAndProcessImage') }}
      </button>
    </div>
  </Modal>

  <!-- Document Processing Confirmation Modal (DOCX/DOC only - PDFs are parsed directly) -->
  <Modal
    v-if="showDocumentConfirm"
    @close="() => { showDocumentConfirm = false; pendingDocumentFile = null; pendingDocumentCursorPos = null }"
    :title="$t('findings.processDocumentTitle')"
    size="medium"
  >
    <div class="image-confirm-content">
      <p>{{ $t('findings.processDocumentQuestion', { fileName: pendingDocumentFile?.name }) }}</p>
      <div class="image-options">
        <div class="option-card">
          <h4>📎 {{ $t('findings.insertReference') }}</h4>
          <p>{{ $t('findings.insertReferenceDesc') }}</p>
          <button @click="confirmDocumentProcessing(false)" class="secondary">
            {{ $t('findings.insertReference') }}
          </button>
        </div>
      </div>
      <p class="hint" style="margin-top:12px">{{ $t('findings.documentTip') }}</p>
    </div>
  </Modal>

  <!-- ── CVSS Calculator modal ── -->
  <CvssCalculator 
    v-if="showCvssCalculator"
    :show="showCvssCalculator" 
    @close="closeCvssCalculator"
    @apply="applyCvssValue"
  />
  
  <!-- ── Severity Override modal ── -->
  <SeverityOverrideModal
    v-if="showSeverityOverride"
    :show="showSeverityOverride"
    :currentSeverity="currentEditingSeverity"
    @close="closeSeverityOverride"
    @apply="applySeverityOverride"
  />

  <!-- ── Confidence Modal ── -->
  <ConfidenceModal
    v-if="showConfidenceModal"
    :show="showConfidenceModal"
    :currentConfidence="currentEditingConfidence"
    :levels="confidenceLevels"
    @close="closeConfidenceModal"
    @apply="applyConfidence"
  />

  <!-- ── Validation Guidance Modal ── -->
  <Modal v-if="showValidationGuidance" :title="$t('findings.validationGuidanceTitle', { title: validationGuidanceFindingTitle })" :wide="true" @close="showValidationGuidance = false">
    <div style="margin-bottom:20px">
      <p class="muted" style="margin:0 0 16px">{{ $t('findings.validationGuidanceDesc') }}</p>
      
      <div v-if="generatingGuidance" style="text-align:center;padding:40px 20px">
        <div class="spinner" style="margin:0 auto 16px"></div>
        <p class="muted">{{ $t('findings.generatingValidation') }}</p>
      </div>
      
      <div v-else class="fp-section-body markdown-prose" style="max-height:500px;overflow-y:auto" v-html="renderMarkdown(validationGuidance)"></div>
    </div>
    
    <div class="actions" style="margin-top:20px;justify-content:space-between;padding-top:16px;border-top:1px solid var(--border)">
      <div style="display:flex;gap:8px">
        <button 
          v-if="!generatingGuidance && validationGuidance && !validationGuidance.includes('Failed')"
          @click="generateValidationGuidance(validationGuidanceFinding, true)" 
          class="secondary"
          :title="$t('findings.regenerateValidationTitle')"
        >
          {{ $t('findings.regenerateValidation') }}
        </button>
        <button 
          v-if="!generatingGuidance && validationGuidance && !validationGuidance.includes('Failed')"
          @click="copyValidationGuidance" 
          class="secondary"
          :title="$t('findings.copyValidationTitle')"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
          </svg>
          {{ $t('findings.copyValidation') }}
        </button>
      </div>
      <button class="secondary" @click="showValidationGuidance = false">{{ $t('common.close') }}</button>
    </div>
  </Modal>
  </div>
</template>

<style scoped>
/* Drop Zone Styles */
.drop-zone {
  position: relative;
  transition: all 0.2s ease;
  border-radius: 6px;
}

.drop-zone.drop-active {
  background: rgba(13, 148, 136, 0.05);
  border: 2px dashed var(--primary);
}

.drop-zone-overlay {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  background: var(--primary);
  color: white;
  padding: 8px 16px;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  pointer-events: none;
  z-index: 10;
}

.drop-zone textarea {
  width: 100%;
  min-height: 120px;
  transition: all 0.2s ease;
}

.drop-zone.drop-active textarea,
.drop-zone.drop-processing textarea {
  opacity: 0.3;
}

.drop-zone-processing {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  background: rgba(0, 0, 0, 0.1);
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  color: var(--text-primary);
  z-index: 10;
  pointer-events: none;
}

.processing-spinner {
  width: 18px;
  height: 18px;
  border: 2px solid var(--border);
  border-top-color: var(--primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Image Confirmation Modal */
.image-confirm-content {
  padding: 8px 0;
}

.image-options {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-top: 16px;
}

.option-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
  transition: all 0.2s;
}

.option-card:hover {
  border-color: var(--primary);
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.option-card h4 {
  margin: 0 0 8px 0;
  font-size: 16px;
  color: var(--text-primary);
}

.option-card p {
  margin: 0 0 16px 0;
  font-size: 14px;
  color: var(--text-muted);
  line-height: 1.4;
}

.option-card button {
  width: 100%;
}

.llm-required-content {
  padding: 4px 0;
}
.llm-required-warning {
  margin: 0 0 16px 0;
  padding: 12px;
  background: var(--banner-bg);
  border: 1px solid var(--banner-border);
  border-radius: 8px;
  font-size: 14px;
  line-height: 1.5;
  color: var(--text-primary);
}
.llm-required-fields {
  display: grid;
  gap: 12px;
}
.llm-required-fields label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 4px;
}
.llm-required-fields select,
.llm-required-fields input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 14px;
}
.llm-required-fields .hint {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
  margin-bottom: 0;
}

/* Mobile responsive */
@media (max-width: 640px) {
  .image-options {
    grid-template-columns: 1fr;
  }
}

/* Reader View link */
.reader-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  text-decoration: none;
  white-space: nowrap;
}

.findings-count {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-muted);
}

.findings-toolbar-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-shrink: 0;
}

/* Tag filter bar */
.findings-tag-filter {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 0;
  flex-wrap: wrap;
}
.findings-tag-filter-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  margin-right: 4px;
}
.findings-tag-chip {
  display: inline-flex;
  align-items: center;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  background: var(--bg-input);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  cursor: pointer;
  transition: background 0.15s, color 0.15s, border-color 0.15s;
  min-height: unset;
  box-shadow: none;
}
.findings-tag-chip:hover {
  background: var(--bg-hover-solid);
  color: var(--text-primary);
  transform: none;
  box-shadow: none;
}
.findings-tag-chip-active {
  background: var(--primary);
  color: #fff;
  border-color: var(--primary);
}
.findings-tag-chip-active:hover {
  background: var(--primary);
  color: #fff;
}
.findings-tag-clear {
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 12px;
  background: none;
  border: 1px dashed var(--border);
  color: var(--text-faint);
  cursor: pointer;
  min-height: unset;
  box-shadow: none;
}
.findings-tag-clear:hover {
  color: var(--text-secondary);
  border-color: var(--text-faint);
  transform: none;
  box-shadow: none;
}

/* Legacy styles */
.file-upload-button {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: var(--btn-primary-bg);
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: background-color 0.2s;
  text-decoration: none;
}

.file-upload-button:hover {
  background: var(--btn-primary-hover);
}

.file-upload-button svg {
  flex-shrink: 0;
}

.section-header {
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0 0 16px 0;
}

/* Breadcrumbs */
.breadcrumbs {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 0 16px;
  font-size: 14px;
  flex-wrap: wrap;
}

.breadcrumb-link {
  background: none;
  border: none;
  color: var(--primary);
  cursor: pointer;
  padding: 0;
  font-size: inherit;
  text-decoration: none;
  transition: color 0.2s;
}

.breadcrumb-link:hover {
  color: var(--btn-primary-hover);
  text-decoration: underline;
}

.breadcrumb-separator {
  color: var(--text-faint);
  user-select: none;
}

.breadcrumb-item {
  color: var(--text-secondary);
}

.breadcrumb-current {
  color: var(--text-primary);
  font-weight: 600;
}

.breadcrumb-meta {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-left: 12px;
  padding-left: 12px;
  border-left: 1px solid var(--border);
  font-size: 13px;
  color: var(--text-secondary);
}

.breadcrumb-meta-item {
  color: var(--text-secondary);
}

.breadcrumb-meta-separator {
  color: var(--text-faint);
}

/* AI Disclaimer Banner */
.ai-disclaimer-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  margin-bottom: 16px;
  background: var(--info-bg);
  border: 1px solid rgba(13, 148, 136, 0.2);
  border-radius: 8px;
  font-size: 14px;
  color: var(--text-secondary);
}

.ai-disclaimer-icon {
  flex-shrink: 0;
  color: var(--info);
}

/* Import Queue Notice */
.resume-notice {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  background: var(--banner-bg);
  border: 1px solid var(--banner-border);
  transition: all 0.3s;
}

.resume-notice.actively-generating {
  background: var(--primary-bg);
  border-color: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-bg);
}

.resume-notice-content {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
  min-width: 200px;
}

.resume-notice-icon {
  flex-shrink: 0;
}

.resume-notice-text-wrapper {
  flex: 1;
}

.resume-notice-text {
  margin: 0;
}

.spinner-small {
  width: 20px;
  height: 20px;
  border: 3px solid var(--primary-bg);
  border-top-color: var(--primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

.btn-spinner {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  vertical-align: middle;
  margin-inline-end: 4px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.local-status {
  padding: 8px 12px;
  margin-top: 8px;
  border-radius: 6px;
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 8px;
  animation: slideDown 0.2s ease-out;
}

.status-icon {
  font-size: 1.1rem;
  line-height: 1;
}

.status-info {
  background: #dbeafe;
  color: #1e40af;
  border: 1px solid #93c5fd;
}

.status-success {
  background: #d1fae5;
  color: #065f46;
  border: 1px solid #6ee7b7;
}

.status-error {
  background: #fee2e2;
  color: #991b1b;
  border: 1px solid #fca5a5;
}

@keyframes slideDown {
  from {
    opacity: 0;
    transform: translateY(-4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* ── Stale summaries popover ── */
.stale-popover {
  position: absolute;
  bottom: calc(100% + 10px);
  right: 0;
  z-index: 50;
  width: 320px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.18);
  padding: 16px;
}
.stale-popover-arrow {
  position: absolute;
  bottom: -6px;
  right: 24px;
  width: 12px;
  height: 12px;
  background: var(--bg-card);
  border-right: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  transform: rotate(45deg);
}
.stale-popover-msg {
  margin: 0 0 12px;
  font-size: 13px;
  line-height: 1.5;
  color: var(--text-secondary);
}
.stale-popover-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.stale-popover-btn {
  font-size: 13px !important;
  padding: 6px 12px !important;
}
.popover-enter-active,
.popover-leave-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.popover-enter-from,
.popover-leave-to {
  opacity: 0;
  transform: translateY(4px);
}

/* Bulk Selection Mode */
.secondary.active {
  background: var(--btn-primary-bg);
  color: white;
  border-color: var(--btn-primary-bg);
}

.secondary.active:hover {
  background: var(--btn-primary-hover);
  border-color: var(--btn-primary-hover);
}

.bulk-checkbox {
  width: 18px;
  height: 18px;
  cursor: pointer;
  accent-color: var(--primary);
}

tr.selected {
  background: var(--primary-bg);
}

tr.selected:hover {
  background: rgba(13, 148, 136, 0.12);
}

.bulk-actions-bar {
  position: fixed;
  bottom: 24px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 16px 24px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12), 0 2px 8px rgba(0, 0, 0, 0.08);
  min-width: 400px;
  max-width: 600px;
}

.bulk-actions-info {
  display: flex;
  align-items: center;
  gap: 16px;
  flex: 1;
}

.bulk-count {
  font-weight: 600;
  color: var(--text-primary);
  font-size: 15px;
}

.link-btn {
  background: none;
  border: none;
  color: var(--primary);
  font-size: 14px;
  cursor: pointer;
  padding: 4px 8px;
  text-decoration: underline;
  transition: color 0.2s;
}

.modify-btn {
  margin-left: 8px;
  font-size: 0.9em;
  opacity: 0.7;
  padding: 2px 4px;
}
.modify-btn:hover {
  opacity: 1;
}

.inline-edit-input {
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  padding: 4px 8px;
  border-radius: 4px;
  font-family: inherit;
  font-size: inherit;
  width: 300px;
  max-width: 100%;
}
.inline-edit-input:focus {
  outline: none;
  border-color: var(--primary);
}

.link-btn:hover {
  color: var(--btn-primary-hover);
}

.bulk-actions-buttons {
  display: flex;
  gap: 10px;
}

.slide-up-enter-active,
.slide-up-leave-active {
  transition: all 0.3s ease;
}

.slide-up-enter-from {
  opacity: 0;
  transform: translateX(-50%) translateY(20px);
}

.slide-up-leave-to {
  opacity: 0;
  transform: translateX(-50%) translateY(20px);
}

/* Inline Edit Form */
.inline-edit-form {
  margin-bottom: 24px;
  padding: 20px;
  padding-bottom: 20px;
  background: var(--surface-secondary);
  border: 1px solid var(--border);
  border-radius: 8px;
}

.unsaved-changes-banner {
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--warning-bg, #fff3cd);
  color: var(--warning-text, #856404);
  border: 1px solid var(--warning-border, #ffc107);
  border-radius: 6px;
  font-size: 14px;
  display: flex;
  align-items: center;
}

.unsaved-indicator {
  margin-left: 6px;
  color: #ffc107;
  font-size: 18px;
  line-height: 1;
  animation: pulse-dot 1.5s ease-in-out infinite;
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.btn-pulse {
  animation: pulse-border 1.5s ease-in-out infinite;
}

@keyframes pulse-border {
  0%, 100% { box-shadow: 0 0 0 0 rgba(255, 193, 7, 0.4); }
  50% { box-shadow: 0 0 0 4px rgba(255, 193, 7, 0); }
}

.form-section {
  margin-bottom: 16px;
}

.form-section label {
  display: block;
  font-weight: 500;
  margin-bottom: 6px;
  color: var(--text);
}

.edit-input,
.edit-select,
.edit-textarea {
  width: 100%;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--surface);
  color: var(--text);
  font-size: 14px;
  font-family: inherit;
}

/* Mobile-friendly form inputs */
@media (max-width: 768px) {
  .edit-input,
  .edit-select,
  .edit-textarea {
    padding: 12px;
    font-size: 16px; /* Prevents iOS zoom on focus */
  }
  
  .edit-textarea {
    min-height: 120px;
  }
  
  .form-section {
    margin-bottom: 20px;
  }
}

.edit-input:focus,
.edit-select:focus,
.edit-textarea:focus {
  outline: none;
  border-color: var(--primary);
}

.edit-textarea {
  font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
  line-height: 1.5;
  resize: vertical;
}

.hint {
  font-size: 12px;
  color: var(--text-faint);
  margin: 4px 0 0 0;
}

.edit-actions {
  position: sticky;
  bottom: 0;
  display: flex;
  gap: 12px;
  justify-content: flex-end;
  margin-top: 20px;
  padding: 16px 20px;
  background: var(--bg-card);
  border-top: 2px solid var(--border);
  box-shadow: 0 -4px 12px rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(8px);
  z-index: 100;
}

/* Mobile-friendly edit actions */
@media (max-width: 768px) {
  .edit-actions {
    padding: 12px 16px;
    gap: 8px;
    flex-wrap: wrap;
  }
  
  .edit-actions button {
    flex: 1;
    min-width: 120px;
  }
}

@media (max-width: 480px) {
  .edit-actions {
    padding: 12px;
    gap: 8px;
  }
  
  .edit-actions button {
    width: 100%;
    min-width: unset;
  }
}

.preview-dimmed {
  opacity: 0.5;
  pointer-events: none;
}

.meta-fields-section {
  margin: 24px 0;
  padding: 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
}

.meta-fields-section h4 {
  margin: 0 0 12px 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
}

.meta-display {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.meta-field-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.meta-label {
  font-weight: 500;
  font-size: 13px;
  color: var(--text-secondary);
  min-width: 120px;
}

.meta-value {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
}

.meta-value .muted {
  color: var(--text-faint);
  font-style: italic;
}

/* Mobile-friendly meta fields */
@media (max-width: 768px) {
  .meta-fields-section {
    padding: 12px;
  }
  
  .meta-field-row {
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }
  
  .meta-label {
    min-width: unset;
    width: 100%;
  }
  
  .meta-value {
    width: 100%;
  }
}
</style>
