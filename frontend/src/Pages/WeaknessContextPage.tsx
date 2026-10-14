import { useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Panel } from '../components/Common'
import JsonViewer from '../components/JsonViewer'

export default function WeaknessContextPage() {
  const [canonicalId, setCanonicalId] = useState('')
  const [findingId, setFindingId] = useState('')
  const [result, setResult] = useState<unknown>(null)
  const [error, setError] = useState('')

  async function lookup(path: string) {
    setError('')
    try {
      const response = await api.get(path)
      setResult(response.data)
    } catch (e) {
      setError(apiError(e))
    }
  }

  return (
    <>
      <ErrorBox message={error} />

      <Panel title="CVE → CWE → CAPEC → ATT&CK Context">
        <p className="hint">
          VulnForge distinguishes potential mappings from observed or confirmed behaviour.
        </p>
        <div className="inline-form">
          <input
            value={canonicalId}
            onChange={(e) => setCanonicalId(e.target.value)}
            placeholder="CVE-2021-44228"
          />
          <button
            disabled={!canonicalId.trim()}
            onClick={() =>
              lookup(`/weakness-context/vulnerabilities/${encodeURIComponent(canonicalId.trim())}`)
            }
          >
            Lookup Vulnerability
          </button>
        </div>

        <div className="inline-form">
          <input
            value={findingId}
            onChange={(e) => setFindingId(e.target.value)}
            placeholder="finding identifier"
          />
          <button
            disabled={!findingId.trim()}
            onClick={() =>
              lookup(`/weakness-context/findings/${encodeURIComponent(findingId.trim())}`)
            }
          >
            Lookup Finding
          </button>
        </div>
      </Panel>

      {result !== null && (
        <Panel title="Weakness / Adversary Context">
          <JsonViewer value={result} />
        </Panel>
      )}
    </>
  )
}
