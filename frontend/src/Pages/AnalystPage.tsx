import { useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Panel, SuccessBox } from '../components/Common'
import JsonViewer from '../components/JsonViewer'

const sample = {
  calculation_version: 'grounded-analyst-1.0',
  evidence: [
    {
      evidence_id: 'ASSET-1',
      evidence_type: 'asset',
      source: 'VulnForge inventory',
      confidence: 'confirmed',
      data: {
        name: 'ubuntu2404',
        ip: '192.168.37.20',
      },
    },
    {
      evidence_id: 'REACH-1',
      evidence_type: 'reachability',
      source: 'VulnForge lab',
      confidence: 'confirmed',
      data: {
        state: 'reachable',
      },
    },
  ],
}

export default function AnalystPage() {
  const [payload, setPayload] = useState(JSON.stringify(sample, null, 2))
  const [result, setResult] = useState<unknown>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function analyze() {
    setError('')
    setMessage('')
    try {
      const parsed = JSON.parse(payload)
      const response = await api.post('/analyst/analyze', parsed)
      setResult(response.data)
      setMessage('Grounded analysis completed and validated.')
    } catch (e) {
      setError(apiError(e))
    }
  }

  return (
    <>
      <ErrorBox message={error} />
      <SuccessBox message={message} />

      <Panel title="Grounded VulnForge AI Analyst">
        <p className="hint">
          Supply structured evidence only. Imported scanner text, HTTP content,
          package descriptions and report text remain untrusted data.
        </p>
        <textarea
          className="code-input"
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
        />
        <button onClick={analyze}>Analyze Structured Evidence</button>
      </Panel>

      {result !== null && (
        <Panel title="Grounded Analyst Output">
          <JsonViewer value={result} maxHeight={760} />
        </Panel>
      )}
    </>
  )
}
