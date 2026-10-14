import { useEffect, useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Panel, SuccessBox } from '../components/Common'
import RecordTable from '../components/RecordTable'
import JsonViewer from '../components/JsonViewer'

type Asset = {
  id: string
  hostname: string
  ip_address: string
  operating_system?: string | null
  role?: string | null
  scanning_enabled: boolean
}

export default function LabValidationPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [selectedAsset, setSelectedAsset] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [discoveryTarget, setDiscoveryTarget] = useState('192.168.37.0/24')
  const [result, setResult] = useState<unknown>(null)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  async function loadAssets() {
    try {
      const response = await api.get('/security-lab/assets')
      const rows = Array.isArray(response.data) ? response.data : []
      setAssets(rows)
      if (!selectedAsset && rows.length) setSelectedAsset(rows[0].id)
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function runDiscovery() {
    setError('')
    setMessage('')
    try {
      const response = await api.post('/scans/discovery', {
        target: discoveryTarget,
        method: 'arp',
        explicitly_authorized: authorized,
      })
      setResult(response.data)
      setMessage('Authorized VMware discovery completed.')
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function enumerate() {
    if (!selectedAsset) return
    setError('')
    setMessage('')
    try {
      const response = await api.post('/scans/services', {
        asset_id: selectedAsset,
        protocol: 'tcp',
        top_ports: 1000,
        explicitly_authorized: authorized,
      })
      setResult(response.data)
      setMessage('Authorized service reassessment completed.')
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function loadPosture() {
    if (!selectedAsset) return
    setError('')
    try {
      const [services, technologies] = await Promise.all([
        api.get(`/assets/${selectedAsset}/services`),
        api.get(`/assets/${selectedAsset}/technologies`),
      ])
      setResult({
        asset_id: selectedAsset,
        services: services.data,
        technologies: technologies.data,
      })
    } catch (e) {
      setError(apiError(e))
    }
  }

  useEffect(() => {
    void loadAssets()
  }, [])

  return (
    <>
      <ErrorBox message={error} />
      <SuccessBox message={message} />

      <Panel title="VMware Lab Acceptance / Reassessment">
        <p className="hint">
          All active network actions remain restricted by backend ScanScope validation.
          Enable explicit authorization only for your approved private lab.
        </p>

        <div className="form-grid">
          <label>
            Lab CIDR
            <input
              value={discoveryTarget}
              onChange={(e) => setDiscoveryTarget(e.target.value)}
            />
          </label>

          <label>
            Asset
            <select
              value={selectedAsset}
              onChange={(e) => setSelectedAsset(e.target.value)}
            >
              <option value="">Select asset</option>
              {assets
                .filter((asset) => asset.scanning_enabled)
                .map((asset) => (
                  <option value={asset.id} key={asset.id}>
                    {asset.hostname} — {asset.ip_address}
                  </option>
                ))}
            </select>
          </label>

          <label className="check">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
            />
            Explicitly authorize this lab action
          </label>
        </div>

        <div className="button-row">
          <button disabled={!authorized} onClick={runDiscovery}>
            Run ARP Discovery
          </button>
          <button disabled={!authorized || !selectedAsset} onClick={enumerate}>
            Re-run Service Enumeration
          </button>
          <button disabled={!selectedAsset} onClick={loadPosture}>
            Load Existing Asset Posture
          </button>
        </div>
      </Panel>

      <Panel title="Managed VMware Assets">
        <RecordTable rows={assets as unknown as Record<string, unknown>[]} />
      </Panel>

      {result !== null && (
        <Panel title="Lab Evidence / Result">
          <JsonViewer value={result} maxHeight={700} />
        </Panel>
      )}
    </>
  )
}
