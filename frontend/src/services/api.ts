import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8001',
  timeout: 120000,
})

export type ScanResult = {
  scan_id: string
  status: string
  message: string
  stage: string
  progress: number
  workspace: string
  artifacts: Record<string, string>
  metrics: Record<string, string | number>
  knowledge: {
    repository?: Record<string, string>
    summary?: string
    languages?: string[]
    frameworks?: string[]
    databases?: string[]
    package_managers?: string[]
    security_findings?: Array<{
      signal: string
      value: string
      source: string
      confidence: number
    }>
  }
  decision: {
    mode?: string
    risk_level?: string
    selected_modules?: string[]
    skipped_modules?: Array<Record<string, string>>
    checkpoints?: string[]
    rationale?: string[]
    next_steps?: string[]
  }
}

export type CreateScanInput = {
  repository_url: string
  source_type?: 'github'
  branch?: string
  sector?: string
  policy_document_text?: string
  policy_filename?: string
}

export async function createScan(input: string | CreateScanInput): Promise<ScanResult> {
  const body = typeof input === 'string' ? { repository_url: input, source_type: 'github' } : input
  try {
    const response = await api.post<ScanResult>('/api/scans', body)
    return response.data
  } catch (error) {
    if (axios.isAxiosError(error)) {
      const detail = error.response?.data?.detail
      if (typeof detail === 'string') {
        throw new Error(detail)
      }
      throw new Error(error.message)
    }
    throw error
  }
}

export async function createZipScan(file: File, sector: string, policyText = '', policyFilename = ''): Promise<ScanResult> {
  const form = new FormData()
  form.append('repository', file)
  form.append('sector', sector)
  form.append('policy_document_text', policyText)
  form.append('policy_filename', policyFilename || file.name)
  return (await api.post<ScanResult>('/api/scans/upload', form)).data
}

// ---- Scans ----
export const getLatestScanStatus = () => api.get('/api/scans/latest/status').then(r => r.data)
export const getScan = (scanId: string) => api.get(`/api/scans/${scanId}`).then(r => r.data)
export const cancelScan = (scanId: string) => api.post(`/api/scans/${scanId}/cancel`).then(r => r.data)
export const getReportHtmlUrl = (scanId: string) =>
  `${api.defaults.baseURL}/api/scans/report/html?scan_id=${scanId}`
export const getReportPdfUrl = (scanId: string) =>
  `${api.defaults.baseURL}/api/scans/report/pdf?scan_id=${scanId}`

// ---- LLM remediation ----
export const generateRemediation = (scanId: string) =>
  api.post(`/api/remediation/${encodeURIComponent(scanId)}/generate`, undefined, { timeout: 660000 }).then(r => r.data)
export const getRemediationStatus = (scanId: string) =>
  api.get(`/api/remediation/${encodeURIComponent(scanId)}`).then(r => r.data)
export const getRemediationDownloadUrl = (scanId: string) =>
  `${api.defaults.baseURL}/api/remediation/${encodeURIComponent(scanId)}/download`

// ---- Sectors ----
export const getSectors = () =>
  api.get('/api/scans/sectors').then(r => r.data)

// ---- Auth ----
export const checkUsername = (username: string) =>
  api.get(`/api/auth/check-username?username=${encodeURIComponent(username.trim())}`).then(r => r.data)
export const authPost = async (endpoint: string, body: unknown) => {
  try {
    return await api.post(`/api/auth${endpoint}`, body).then(r => r.data)
  } catch (err) {
    if (axios.isAxiosError(err)) {
      const status = err.response?.status
      const detail = err.response?.data?.detail ?? err.message
      // Re-throw with status so callers can branch on it (e.g. 409 → "account exists" CTA).
      const e = new Error(typeof detail === 'string' ? detail : err.message) as Error & { status?: number }
      e.status = status
      throw e
    }
    throw err
  }
}
export const verifyOtp = (body: unknown) => api.post('/api/auth/verify-otp', body).then(r => r.data)
export const forgotPasswordOtp = (body: unknown) =>
  api.post('/api/auth/forgot-password-otp', body).then(r => r.data)
export const resetPassword = (body: unknown) =>
  api.post('/api/auth/reset-password', body).then(r => r.data)
export const checkResetOtp = (body: unknown) =>
  api.post('/api/auth/check-reset-otp', body).then(r => r.data)
export const startOAuth = (provider: string) =>
  api.get(`/api/auth/oauth/${provider}`).then(r => r.data)
export const completeOAuth = (provider: string, code: string) =>
  api.get(`/api/auth/oauth/${provider}/callback?code=${encodeURIComponent(code)}`).then(r => r.data)
export const updateProfile = (body: unknown) =>
  api.post('/api/auth/update-profile', body).then(r => r.data)
export const submitSupportTicket = (body: unknown) =>
  api.post('/api/auth/support-ticket', body).then(r => r.data)

// ---- Audit logs ----
export const getAuditLogs = (scanId?: string) =>
  api.get('/api/audit-logs', { params: scanId ? { scan_id: scanId } : {} }).then(r => r.data)

export default api
