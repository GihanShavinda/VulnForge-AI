import { useMemo, useState } from 'react'
import AttackGraphPage from './Pages/AttackGraphPage'
import AnalystPage from './Pages/AnalystPage'
import CollectionPage from './Pages/CollectionPage'
import EvaluationPage from './Pages/EvaluationPage'
import EnvironmentalRiskPage from './Pages/EnvironmentalRiskPage'
import LabValidationPage from './Pages/LabValidationPage'
import OverviewPage from './Pages/OverviewPage'
import RemediationPage from './Pages/RemediationPage'
import ReportsPage from './Pages/ReportsPage'
import SecurityControlsPage from './Pages/SecurityControlsPage'
import ThreatIntelPage from './Pages/ThreatIntelPage'
import WeaknessContextPage from './Pages/WeaknessContextPage'

type Tab =
  | 'overview'
  | 'sbom'
  | 'threat-intel'
  | 'weakness-context'
  | 'severity'
  | 'configuration'
  | 'web'
  | 'tls'
  | 'secrets'
  | 'patch-eol'
  | 'exploitability'
  | 'attack-graph'
  | 'environmental-risk'
  | 'controls'
  | 'analyst'
  | 'remediation'
  | 'evaluation'
  | 'reports'
  | 'vmware-lab'

const navGroups: { heading: string; items: { id: Tab; label: string }[] }[] = [
  {
    heading: 'Overview',
    items: [{ id: 'overview', label: 'Exposure Overview' }],
  },
  {
    heading: 'Inventory & Intelligence',
    items: [
      { id: 'sbom', label: 'SBOM / Packages' },
      { id: 'threat-intel', label: 'Vulnerability Intelligence' },
      { id: 'weakness-context', label: 'CWE / CAPEC / ATT&CK' },
    ],
  },
  {
    heading: 'Exposure',
    items: [
      { id: 'configuration', label: 'Configuration Weaknesses' },
      { id: 'web', label: 'Web Security' },
      { id: 'tls', label: 'TLS Security' },
      { id: 'secrets', label: 'Secrets' },
      { id: 'patch-eol', label: 'Patch / EOL' },
    ],
  },
  {
    heading: 'Risk',
    items: [
      { id: 'severity', label: 'Severity Analysis' },
      { id: 'exploitability', label: 'Exploitability' },
      { id: 'attack-graph', label: 'Attack Paths' },
      { id: 'environmental-risk', label: 'Environmental Risk' },
      { id: 'controls', label: 'Security Controls' },
    ],
  },
  {
    heading: 'Operations',
    items: [
      { id: 'analyst', label: 'Grounded AI Analyst' },
      { id: 'remediation', label: 'Remediation / Verification' },
      { id: 'evaluation', label: 'Final Evaluation' },
      { id: 'reports', label: 'Reports' },
      { id: 'vmware-lab', label: 'VMware Lab Validation' },
    ],
  },
]

const titles: Record<Tab, string> = {
  overview: 'Exposure Overview',
  sbom: 'SBOM & Software Composition',
  'threat-intel': 'Vulnerability Intelligence',
  'weakness-context': 'Weakness & Adversary Context',
  severity: 'Severity Analysis',
  configuration: 'Configuration Weaknesses',
  web: 'Web Security',
  tls: 'TLS Security',
  secrets: 'Secret Exposure',
  'patch-eol': 'Patch / EOL',
  exploitability: 'Exploitability Evidence',
  'attack-graph': 'Attack Paths',
  'environmental-risk': 'Environmental Risk',
  controls: 'Security Controls & Residual Risk',
  analyst: 'Grounded VulnForge AI Analyst',
  remediation: 'Remediation & Verification',
  evaluation: 'Final VMware Evaluation',
  reports: 'Final Reports',
  'vmware-lab': 'VMware Lab Validation',
}

export default function PostV5Workspace() {
  const [tab, setTab] = useState<Tab>('overview')

  const content = useMemo(() => {
    switch (tab) {
      case 'overview':
        return <OverviewPage />

      case 'sbom':
        return (
          <CollectionPage
            title="SBOM Imports"
            description="Imported CycloneDX/SPDX/Syft/Trivy/Grype and OS-package evidence."
            listPath="/sbom/imports"
            childEndpoints={[
              {
                label: 'Components',
                buildPath: (row) =>
                  row.id ? `/sbom/imports/${row.id}/components` : null,
              },
              {
                label: 'Vulnerability Matches',
                buildPath: (row) =>
                  row.id ? `/sbom/imports/${row.id}/matches` : null,
              },
              {
                label: 'Component Drift',
                buildPath: (row) =>
                  row.id ? `/sbom/imports/${row.id}/drift` : null,
              },
            ]}
          />
        )

      case 'threat-intel':
        return <ThreatIntelPage />

      case 'weakness-context':
        return <WeaknessContextPage />

      case 'severity':
        return (
          <CollectionPage
            title="CVSS + Environmental Severity Analyses"
            description="CVSS is shown as technical severity, not the sole remediation priority."
            listPath="/severity/analyses"
          />
        )

      case 'configuration':
        return (
          <CollectionPage
            title="Configuration Assessment Runs"
            description="Linux/Windows baseline evidence and deterministic configuration findings."
            listPath="/config-assessment/runs"
            childEndpoints={[
              {
                label: 'Configuration Findings',
                buildPath: (row) =>
                  row.id ? `/config-assessment/runs/${row.id}/findings` : null,
              },
              {
                label: 'Configuration Evidence',
                buildPath: (row) =>
                  row.id ? `/config-assessment/runs/${row.id}/evidence` : null,
              },
            ]}
          />
        )

      case 'web':
        return (
          <CollectionPage
            title="Web Assessment Imports"
            description="ZAP, Nikto, Nuclei and WhatWeb findings are imported as untrusted evidence."
            listPath="/web-assessment/imports"
            childEndpoints={[
              {
                label: 'Web Findings',
                buildPath: (row) =>
                  row.id ? `/web-assessment/imports/${row.id}/findings` : null,
              },
              {
                label: 'Web Evidence',
                buildPath: (row) =>
                  row.id ? `/web-assessment/imports/${row.id}/evidence` : null,
              },
            ]}
          />
        )

      case 'tls':
        return (
          <CollectionPage
            title="TLS Assessment Imports"
            description="Certificate, protocol and cryptographic findings with preserved scanner evidence."
            listPath="/tls-assessment/imports"
            childEndpoints={[
              {
                label: 'TLS Findings',
                buildPath: (row) =>
                  row.id ? `/tls-assessment/imports/${row.id}/findings` : null,
              },
              {
                label: 'TLS Evidence',
                buildPath: (row) =>
                  row.id ? `/tls-assessment/imports/${row.id}/evidence` : null,
              },
            ]}
          />
        )

      case 'secrets':
        return (
          <CollectionPage
            title="Secret Exposure Imports"
            description="Masked, fingerprinted secret evidence without returning plaintext secrets."
            listPath="/secret-exposure/imports"
            childEndpoints={[
              {
                label: 'Secret Findings',
                buildPath: (row) =>
                  row.id ? `/secret-exposure/imports/${row.id}/findings` : null,
              },
            ]}
          />
        )

      case 'patch-eol':
        return (
          <CollectionPage
            title="Patch & Lifecycle Runs"
            description="Patch availability, vendor backports, temporary controls and lifecycle/EOL risk."
            listPath="/patch-lifecycle/runs"
            childEndpoints={[
              {
                label: 'Patch Findings',
                buildPath: (row) =>
                  row.id ? `/patch-lifecycle/runs/${row.id}/patch-findings` : null,
              },
              {
                label: 'Lifecycle Findings',
                buildPath: (row) =>
                  row.id ? `/patch-lifecycle/runs/${row.id}/lifecycle-findings` : null,
              },
            ]}
          />
        )

      case 'exploitability':
        return (
          <CollectionPage
            title="Exploitability Assessments"
            description="Applicability and exploitability are evidence-based; no exploits are executed."
            listPath="/exploitability/assessments"
            childEndpoints={[
              {
                label: 'Exploitability Signals',
                buildPath: (row) =>
                  row.id ? `/exploitability/assessments/${row.id}/signals` : null,
              },
            ]}
          />
        )

      case 'attack-graph':
        return <AttackGraphPage />

      case 'environmental-risk':
        return <EnvironmentalRiskPage />

      case 'controls':
        return <SecurityControlsPage />

      case 'analyst':
        return <AnalystPage />

      case 'remediation':
        return <RemediationPage />

      case 'evaluation':
        return <EvaluationPage />

      case 'reports':
        return <ReportsPage />

      case 'vmware-lab':
        return <LabValidationPage />

      default:
        return null
    }
  }, [tab])

  return (
    <div className="shell post-v5-shell">
      <aside className="platform-sidebar">
        <div className="brand">
          <b>VF</b>
          <div>
            <strong>VulnForge AI</strong>
            <small>V6–V20 Integration</small>
          </div>
        </div>

        <nav className="grouped-nav">
          {navGroups.map((group) => (
            <div className="nav-group" key={group.heading}>
              <span className="nav-heading">{group.heading}</span>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  className={tab === item.id ? 'active' : ''}
                  onClick={() => setTab(item.id)}
                >
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="warning">
          Authorized laboratory only.
          <br />
          No automatic exploitation.
        </div>
      </aside>

      <main className="platform-main">
        <header>
          <div>
            <h1>{titles[tab]}</h1>
            <p>
              Evidence-backed exposure management, attack-path analysis,
              grounded AI and remediation verification.
            </p>
          </div>
          <span>V20 · 1.0.0</span>
        </header>

        {content}
      </main>
    </div>
  )
}
