import { useState } from 'react'
import CollectionPage from './CollectionPage'
import JsonAction from '../components/JsonAction'

const sample = {
  asset_id: null,
  vulnerability_id: 'CVE-LAB-RISK-001',
  calculation_version: 'ers-2.0-experimental',
  factors: {
    technical_severity_cvss: 6.0,
    exploit_probability: 0.9,
    known_exploitation: true,
    network_exposure: 'external',
    service_reachability: 'public',
    asset_criticality: 'critical',
    attack_path_importance: 'critical',
    privilege_impact: 'admin',
    credential_exposure: 'exposed',
    security_control_strength: 'weak',
    patch_availability: 'available',
    threat_relevance: 'active',
    evidence_confidence: 'confirmed',
    lifecycle_risk: 'legacy',
  },
}

export default function EnvironmentalRiskPage() {
  const [reloadKey, setReloadKey] = useState(0)

  return (
    <>
      <JsonAction
        title="Calculate Environmental Risk"
        description="Experimental 0–100 score. Replace sample values with evidence-backed factors from VulnForge."
        path="/environmental-risk/score"
        sample={sample}
        buttonLabel="Calculate & Store Score"
        onSuccess={() => setReloadKey((x) => x + 1)}
      />
      <div key={reloadKey}>
        <CollectionPage
          title="Environmental Risk History"
          description="Every score stores raw factors, normalized factors, weights and contribution records."
          listPath="/environmental-risk/scores"
          childEndpoints={[
            {
              label: 'Factor Contributions',
              buildPath: (row) =>
                row.id ? `/environmental-risk/scores/${row.id}/contributions` : null,
            },
          ]}
        />
      </div>
    </>
  )
}
