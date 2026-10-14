import { useState } from 'react'
import { api, apiError, downloadReport } from '../lib/api'
import { ErrorBox, Panel, SuccessBox } from '../components/Common'

const reportTypes = [
  ['executive', 'Executive Report'],
  ['technical_vulnerability_assessment', 'Technical Vulnerability Assessment'],
  ['asset', 'Asset Report'],
  ['attack_path', 'Attack Path Report'],
  ['remediation', 'Remediation Report'],
  ['verification', 'Verification Report'],
] as const

async function safeGet(path: string) {
  try {
    const response = await api.get(path)
    return response.data
  } catch (error) {
    return {
      unavailable: true,
      endpoint: path,
      error: apiError(error),
    }
  }
}

function rows(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) {
    return value.map((item) =>
      item && typeof item === 'object'
        ? (item as Record<string, unknown>)
        : { value: item },
    )
  }
  if (value && typeof value === 'object') {
    return [value as Record<string, unknown>]
  }
  return [{ value }]
}

async function buildSections(reportType: string) {
  if (reportType === 'executive') {
    const [dashboard, risk, remediation, evaluation] = await Promise.all([
      safeGet('/dashboard/final'),
      safeGet('/environmental-risk/scores'),
      safeGet('/remediation/cases'),
      safeGet('/evaluation/runs'),
    ])
    return [
      {
        heading: 'Executive Exposure Overview',
        narrative: 'High-level VulnForge posture and final dashboard summary.',
        rows: rows(dashboard),
      },
      {
        heading: 'Environmental Risk',
        rows: rows(risk),
      },
      {
        heading: 'Remediation Status',
        rows: rows(remediation),
      },
      {
        heading: 'Evaluation Results',
        rows: rows(evaluation),
      },
    ]
  }

  if (reportType === 'technical_vulnerability_assessment') {
    const [severity, config, web, tls, secrets, patch, exploitability] =
      await Promise.all([
        safeGet('/severity/analyses'),
        safeGet('/config-assessment/runs'),
        safeGet('/web-assessment/imports'),
        safeGet('/tls-assessment/imports'),
        safeGet('/secret-exposure/imports'),
        safeGet('/patch-lifecycle/runs'),
        safeGet('/exploitability/assessments'),
      ])
    return [
      { heading: 'Severity Analysis', rows: rows(severity) },
      { heading: 'Configuration Assessment', rows: rows(config) },
      { heading: 'Web Security', rows: rows(web) },
      { heading: 'TLS Security', rows: rows(tls) },
      { heading: 'Secret Exposure', rows: rows(secrets) },
      { heading: 'Patch / Lifecycle', rows: rows(patch) },
      { heading: 'Exploitability Evidence', rows: rows(exploitability) },
    ]
  }

  if (reportType === 'asset') {
    const assets = await safeGet('/security-lab/assets')
    return [
      {
        heading: 'Asset Inventory',
        narrative:
          'Managed assets from the approved VulnForge laboratory inventory.',
        rows: rows(assets),
      },
    ]
  }

  if (reportType === 'attack_path') {
    const [paths, runs] = await Promise.all([
      safeGet('/attack-graph/paths'),
      safeGet('/attack-graph/runs'),
    ])
    return [
      { heading: 'Calculated Attack Paths', rows: rows(paths) },
      { heading: 'Graph Sync Runs', rows: rows(runs) },
    ]
  }

  if (reportType === 'remediation') {
    const cases = await safeGet('/remediation/cases')
    return [
      {
        heading: 'Remediation Cases',
        rows: rows(cases),
      },
    ]
  }

  const [cases, evaluation] = await Promise.all([
    safeGet('/remediation/cases'),
    safeGet('/evaluation/runs'),
  ])
  return [
    {
      heading: 'Verification / Remediation Status',
      rows: rows(cases),
    },
    {
      heading: 'Final Evaluation',
      rows: rows(evaluation),
    },
  ]
}

export default function ReportsPage() {
  const [reportType, setReportType] = useState('executive')
  const [format, setFormat] = useState<'pdf' | 'csv' | 'json'>('pdf')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function generate() {
    setError('')
    setMessage('')

    const typeLabel =
      reportTypes.find(([value]) => value === reportType)?.[1] ??
      'VulnForge Report'

    try {
      const sections = await buildSections(reportType)
      const payload = {
        report_type: reportType,
        report_format: format,
        title: `VulnForge ${typeLabel}`,
        generated_for: 'VulnForge VMware Laboratory',
        sections,
      }

      await downloadReport(
        payload,
        `vulnforge_${reportType}.${format}`,
      )
      setMessage('Evidence-backed report generated.')
    } catch (e) {
      setError(apiError(e))
    }
  }

  return (
    <>
      <ErrorBox message={error} />
      <SuccessBox message={message} />

      <Panel title="Final Report Centre">
        <p className="hint">
          Report sections are populated from the corresponding VulnForge APIs
          before PDF/CSV/JSON generation.
        </p>

        <div className="form-grid">
          <label>
            Report
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value)}
            >
              {reportTypes.map(([value, label]) => (
                <option value={value} key={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>

          <label>
            Format
            <select
              value={format}
              onChange={(e) =>
                setFormat(e.target.value as 'pdf' | 'csv' | 'json')
              }
            >
              <option value="pdf">PDF</option>
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
            </select>
          </label>
        </div>

        <button onClick={generate}>Generate Evidence-Backed Report</button>
      </Panel>

      <Panel title="Report Coverage">
        <div className="coverage-grid">
          {reportTypes.map(([, label]) => (
            <article className="coverage-card" key={label}>
              <strong>{label}</strong>
              <span>PDF · CSV · JSON</span>
            </article>
          ))}
        </div>
      </Panel>
    </>
  )
}
