import { useEffect, useMemo, useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Loading, Panel, StatCard } from '../components/Common'
import JsonViewer from '../components/JsonViewer'
import RiskTrendChart from '../components/RiskTrendChart'

type Dashboard = {
  milestone?: string
  sections?: { name: string; status: string; description?: string }[]
  remediation_summary?: {
    total_cases?: number
    open_cases?: number
    verified_or_closed?: number
    reassessments?: number
    regressions_detected?: number
  }
  evaluation_summary?: {
    evaluation_runs?: number
    environment?: string
  }
}

type RiskScore = {
  id?: string
  final_score?: number
  priority_tier?: string
  created_at?: string
}

export default function OverviewPage() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null)
  const [riskScores, setRiskScores] = useState<RiskScore[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  async function load() {
    setLoading(true)
    setError('')
    try {
      const [d, r] = await Promise.all([
        api.get('/dashboard/final'),
        api.get('/environmental-risk/scores'),
      ])
      setDashboard(d.data)
      setRiskScores(Array.isArray(r.data) ? r.data : [])
    } catch (e) {
      setError(apiError(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const points = useMemo(
    () =>
      riskScores
        .slice()
        .reverse()
        .slice(-20)
        .map((row, index) => ({
          label: row.created_at
            ? new Date(row.created_at).toLocaleDateString()
            : `#${index + 1}`,
          value: Number(row.final_score ?? 0),
        })),
    [riskScores],
  )

  if (loading) return <Loading />

  const remediation = dashboard?.remediation_summary ?? {}
  const evaluation = dashboard?.evaluation_summary ?? {}

  return (
    <>
      <ErrorBox message={error} />

      <section className="stats-grid">
        <StatCard label="Remediation Cases" value={remediation.total_cases ?? 0} />
        <StatCard label="Open Cases" value={remediation.open_cases ?? 0} />
        <StatCard label="Verified / Closed" value={remediation.verified_or_closed ?? 0} />
        <StatCard label="Reassessments" value={remediation.reassessments ?? 0} />
        <StatCard label="Regressions" value={remediation.regressions_detected ?? 0} />
        <StatCard label="Evaluation Runs" value={evaluation.evaluation_runs ?? 0} />
      </section>

      <Panel title="Risk Trends">
        {points.length ? (
          <RiskTrendChart points={points} />
        ) : (
          <p className="hint">
            Environmental-risk history will appear here after V17 calculations are stored.
          </p>
        )}
      </Panel>

      <Panel title="Final Dashboard Coverage" actions={<button onClick={load}>Refresh</button>}>
        <div className="coverage-grid">
          {(dashboard?.sections ?? []).map((section) => (
            <article className="coverage-card" key={section.name}>
              <strong>{section.name}</strong>
              <span>{section.status}</span>
              <p>{section.description}</p>
            </article>
          ))}
        </div>
      </Panel>

      <Panel title="Raw Dashboard Response">
        <JsonViewer value={dashboard} />
      </Panel>
    </>
  )
}
