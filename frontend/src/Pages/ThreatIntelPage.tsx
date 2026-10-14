import { useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Panel } from '../components/Common'
import CollectionPage from './CollectionPage'
import JsonViewer from '../components/JsonViewer'

export default function ThreatIntelPage() {
  const [cve, setCve] = useState('')
  const [detail, setDetail] = useState<unknown>(null)
  const [error, setError] = useState('')

  async function lookup() {
    setError('')
    try {
      const response = await api.get(
        `/threat-intel/vulnerabilities/${encodeURIComponent(cve.trim())}`,
      )
      setDetail(response.data)
    } catch (e) {
      setError(apiError(e))
    }
  }

  return (
    <>
      <ErrorBox message={error} />
      <Panel title="Vulnerability Intelligence Lookup">
        <div className="inline-form">
          <input
            value={cve}
            onChange={(e) => setCve(e.target.value)}
            placeholder="CVE-2021-44228"
          />
          <button disabled={!cve.trim()} onClick={lookup}>
            Load NVD / OSV / KEV / EPSS Evidence
          </button>
        </div>
      </Panel>

      {detail !== null && (
        <Panel title="Threat Intelligence Detail">
          <JsonViewer value={detail} />
        </Panel>
      )}

      <CollectionPage
        title="Threat Intelligence Sources"
        description="Source freshness, provenance and configured intelligence providers."
        listPath="/threat-intel/sources"
      />
    </>
  )
}
