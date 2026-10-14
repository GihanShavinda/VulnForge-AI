import { useEffect, useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Panel, SuccessBox } from '../components/Common'
import JsonViewer from '../components/JsonViewer'
import RecordTable from '../components/RecordTable'

const sample = {
  environment_name: 'VMware VulnForge Laboratory',
  dataset_name: 'final-vmware-evaluation',
  notes: 'Populate from validated lab findings before final reporting.',
  top_k: 3,
  findings: [
    {
      finding_ref: 'F-001',
      cvss_score: 10,
      kev: false,
      epss: 0.05,
      environmental_score: 35,
      expert_rank: 3,
      predicted_applicable: true,
      applicable: true,
      attack_path_relevant: false,
      triage_seconds: 90,
      pre_remediation_risk: 35,
      post_remediation_risk: 20,
      ai_factual_correct: true,
      ai_unsupported_claim: false,
      security_rule_correct: true,
      verification_success: true
    },
    {
      finding_ref: 'F-002',
      cvss_score: 6.5,
      kev: true,
      epss: 0.92,
      environmental_score: 94,
      expert_rank: 1,
      predicted_applicable: true,
      applicable: true,
      attack_path_relevant: true,
      triage_seconds: 45,
      pre_remediation_risk: 94,
      post_remediation_risk: 28,
      ai_factual_correct: true,
      ai_unsupported_claim: false,
      security_rule_correct: true,
      verification_success: true
    }
  ]
}

export default function EvaluationPage() {
  const [runs, setRuns] = useState<Record<string, unknown>[]>([])
  const [payload, setPayload] = useState(JSON.stringify(sample, null, 2))
  const [result, setResult] = useState<unknown>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function load() {
    try {
      const response = await api.get('/evaluation/runs')
      setRuns(Array.isArray(response.data) ? response.data : [])
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function runEvaluation() {
    setError('')
    setMessage('')
    try {
      const response = await api.post('/evaluation/runs', JSON.parse(payload))
      setResult(response.data)
      setMessage('Final experiment calculated and stored.')
      await load()
    } catch (e) {
      setError(apiError(e))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  return (
    <>
      <ErrorBox message={error} />
      <SuccessBox message={message} />

      <Panel title="VMware Final Evaluation">
        <p className="hint">
          Replace the sample rows with the final manually reviewed lab dataset.
          The engine compares CVSS-only, CVSS+KEV, CVSS+KEV+EPSS,
          VulnForge Environmental Risk and expert/manual ranking.
        </p>
        <textarea
          className="code-input"
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
        />
        <button onClick={runEvaluation}>Run Final Experiment</button>
      </Panel>

      {result !== null && (
        <Panel title="Final Experiment Table + Metrics">
          <JsonViewer value={result} maxHeight={760} />
        </Panel>
      )}

      <Panel title="Stored Evaluation Runs" actions={<button onClick={load}>Refresh</button>}>
        <RecordTable rows={runs} />
      </Panel>
    </>
  )
}
