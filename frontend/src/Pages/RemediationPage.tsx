import { useEffect, useState } from 'react'
import { api, apiError } from '../lib/api'
import {
  ErrorBox,
  Panel,
  StatusBadge,
  SuccessBox,
} from '../components/Common'
import JsonViewer from '../components/JsonViewer'
import JsonAction from '../components/JsonAction'

type CaseRow = {
  id: string
  finding_ref: string
  priority: string
  status: string
  owner: string
  due_date: string
  root_cause: string
  expected_risk_reduction: number
}


const createCaseSample = {
  finding_ref: 'F-LAB-001',
  finding_type: 'vulnerability',
  vulnerability_id: 'CVE-LAB-001',
  root_cause: 'Evidence-backed root cause required.',
  technical_remediation: 'Apply the validated technical fix.',
  temporary_mitigation: 'Restrict exposure until permanent remediation is complete.',
  affected_assets: ['192.168.37.20'],
  owner: 'Security Team',
  sla_days: 14,
  priority: 'P1',
  due_date: '2026-10-28',
  verification_procedure: 'Repeat the original assessment and compare evidence.',
  rollback_notes: 'Restore the VMware snapshot if the change causes instability.',
  expected_risk_reduction: 50
}

const evidenceSample = {
  evidence_stage: 'closure',
  evidence_type: 'verification',
  source: 'VulnForge reassessment',
  content: {
    note: 'Replace with verified post-remediation evidence.'
  },
  confidence: 'confirmed'
}

const reassessmentSample = {
  before_evidence: { state: 'vulnerable' },
  after_evidence: { state: 'remediated' },
  before_score: 80,
  after_score: 30,
  before_attack_path: {
    nodes: ['attacker', 'target'],
    relationships: ['REACHABLE_FROM'],
    status: 'theoretical'
  },
  after_attack_path: {},
  before_controls: [],
  after_controls: [{ name: 'host firewall' }]
}

const lanes = [
  'Open',
  'Triaged',
  'Assigned',
  'Remediation In Progress',
  'Ready for Verification',
  'Verified',
  'Closed',
  'Accepted Risk',
  'False Positive',
  'Deferred',
]

export default function RemediationPage() {
  const [cases, setCases] = useState<CaseRow[]>([])
  const [selected, setSelected] = useState<CaseRow | null>(null)
  const [detail, setDetail] = useState<unknown>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function load() {
    setError('')
    try {
      const response = await api.get('/remediation/cases')
      setCases(Array.isArray(response.data) ? response.data : [])
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function openCase(row: CaseRow) {
    setSelected(row)
    try {
      const response = await api.get(`/remediation/cases/${row.id}`)
      setDetail(response.data)
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function transition(toStatus: string) {
    if (!selected) return
    const reason =
      ['Accepted Risk', 'False Positive', 'Deferred'].includes(toStatus)
        ? window.prompt(`Reason required for ${toStatus}:`) ?? ''
        : window.prompt('Optional transition note:') ?? ''

    if (
      ['Accepted Risk', 'False Positive', 'Deferred'].includes(toStatus) &&
      !reason.trim()
    ) {
      return
    }

    setError('')
    setMessage('')
    try {
      await api.post(`/remediation/cases/${selected.id}/transition`, {
        to_status: toStatus,
        actor: 'VulnForge UI',
        reason: reason || null,
      })
      setMessage(`Case moved to ${toStatus}.`)
      await load()
      const response = await api.get(`/remediation/cases/${selected.id}`)
      setDetail(response.data)
      setSelected((response.data as { case: CaseRow }).case)
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

      <JsonAction
        title="Create Remediation Case"
        description="Create an evidence-backed remediation record with owner, SLA, verification procedure and expected risk reduction."
        path="/remediation/cases"
        sample={createCaseSample}
        buttonLabel="Create Case"
        onSuccess={() => void load()}
      />

      <Panel title="Remediation Workflow" actions={<button onClick={load}>Refresh</button>}>
        <div className="kanban">
          {lanes.map((lane) => (
            <section className="kanban-lane" key={lane}>
              <h3>{lane}</h3>
              {cases
                .filter((item) => item.status === lane)
                .map((item) => (
                  <button
                    className="case-card"
                    key={item.id}
                    onClick={() => openCase(item)}
                  >
                    <span className="case-line">
                      <b>{item.finding_ref}</b>
                      <StatusBadge value={item.priority} />
                    </span>
                    <small>{item.owner}</small>
                    <small>Due {item.due_date}</small>
                  </button>
                ))}
            </section>
          ))}
        </div>
      </Panel>

      {selected && (
        <>
        <JsonAction
          title={`Add Evidence — ${selected.finding_ref}`}
          description="Closure requires stored evidence. Change evidence_stage to before/during/after/closure as appropriate."
          path={`/remediation/cases/${selected.id}/evidence`}
          sample={evidenceSample}
          buttonLabel="Store Evidence"
          onSuccess={() => void openCase(selected)}
        />
        <JsonAction
          title={`Run Reassessment — ${selected.finding_ref}`}
          description="Compare before/after evidence, risk score, attack path and controls. Regression detection runs automatically."
          path={`/remediation/cases/${selected.id}/reassess`}
          sample={reassessmentSample}
          buttonLabel="Run Reassessment"
          onSuccess={() => void openCase(selected)}
        />
        <Panel title={`Case ${selected.finding_ref}`}>
          <div className="transition-bar">
            {lanes.map((lane) => (
              <button key={lane} onClick={() => transition(lane)}>
                {lane}
              </button>
            ))}
          </div>
          <JsonViewer value={detail ?? selected} maxHeight={650} />
        </Panel>
        </>
      )}
    </>
  )
}
