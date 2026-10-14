import { useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Panel, SuccessBox } from './Common'
import JsonViewer from './JsonViewer'

export default function JsonAction({
  title,
  description,
  path,
  sample,
  buttonLabel = 'Submit',
  onSuccess,
}: {
  title: string
  description: string
  path: string
  sample: unknown
  buttonLabel?: string
  onSuccess?: (result: unknown) => void
}) {
  const [payload, setPayload] = useState(JSON.stringify(sample, null, 2))
  const [result, setResult] = useState<unknown>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function submit() {
    setError('')
    setMessage('')
    try {
      const response = await api.post(path, JSON.parse(payload))
      setResult(response.data)
      setMessage('Request completed.')
      onSuccess?.(response.data)
    } catch (e) {
      setError(apiError(e))
    }
  }

  return (
    <Panel title={title}>
      <p className="hint">{description}</p>
      <ErrorBox message={error} />
      <SuccessBox message={message} />
      <textarea
        className="code-input"
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
      />
      <button onClick={submit}>{buttonLabel}</button>
      {result !== null && <JsonViewer value={result} maxHeight={420} />}
    </Panel>
  )
}
