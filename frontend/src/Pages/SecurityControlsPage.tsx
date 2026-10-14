import { useState } from 'react'
import CollectionPage from './CollectionPage'
import JsonAction from '../components/JsonAction'

const controlSample = {
  asset_id: null,
  name: 'Lab WAF',
  control_type: 'waf',
  owner: 'Security Team',
  effectiveness: 90,
  confidence: 95,
  evidence: {
    source: 'validated laboratory configuration',
    mode: 'blocking',
  },
  temporary: false,
  effective_from: null,
  expires_at: null,
  mitigation_until: null,
  enabled: true,
}

const assessmentSample = {
  asset_id: null,
  vulnerability_id: 'CVE-LAB-CONTROL-001',
  exposure_type: 'web_application',
  inherent_risk: 80,
  control_ids: [],
  calculation_version: 'control-aware-risk-1.0',
}

export default function SecurityControlsPage() {
  const [reloadKey, setReloadKey] = useState(0)

  return (
    <>
      <JsonAction
        title="Register Security Control"
        description="Controls are evidence-backed and may prevent, reduce, detect, contain, or not affect an exposure."
        path="/security-controls"
        sample={controlSample}
        buttonLabel="Create Control"
        onSuccess={() => setReloadKey((x) => x + 1)}
      />

      <JsonAction
        title="Calculate Residual Risk"
        description="Insert one or more control UUIDs returned by the control API. Controls never automatically resolve a vulnerability."
        path="/security-controls/assess"
        sample={assessmentSample}
        buttonLabel="Assess Residual Risk"
        onSuccess={() => setReloadKey((x) => x + 1)}
      />

      <div key={reloadKey}>
        <CollectionPage
          title="Control-Aware Risk Assessments"
          description="Compare inherent risk with residual risk and inspect every control contribution."
          listPath="/security-controls/assessments"
          childEndpoints={[
            {
              label: 'Control Contributions',
              buildPath: (row) =>
                row.id
                  ? `/security-controls/assessments/${row.id}/contributions`
                  : null,
            },
          ]}
        />
      </div>
    </>
  )
}
