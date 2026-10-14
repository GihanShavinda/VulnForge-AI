import axios from 'axios'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000/api/v1',
  timeout: 900000,
})

export function apiError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      return detail.map((item) => item?.msg ?? JSON.stringify(item)).join(', ')
    }
    if (detail && typeof detail === 'object') return JSON.stringify(detail)
    return error.message
  }
  return error instanceof Error ? error.message : String(error)
}

export async function downloadReport(payload: unknown, filename: string) {
  const response = await api.post('/reports/generate', payload, {
    responseType: 'blob',
  })

  const blob = new Blob([response.data], {
    type:
      typeof response.headers['content-type'] === 'string'
        ? response.headers['content-type']
        : 'application/octet-stream',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}
