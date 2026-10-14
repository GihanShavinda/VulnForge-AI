import { useEffect, useState } from 'react'
import { api, apiError } from '../lib/api'
import { ErrorBox, Loading, Panel } from '../components/Common'
import JsonViewer from '../components/JsonViewer'
import RecordTable from '../components/RecordTable'

export type ChildEndpoint = {
  label: string
  buildPath: (row: Record<string, unknown>) => string | null
}

export default function CollectionPage({
  title,
  description,
  listPath,
  childEndpoints = [],
}: {
  title: string
  description: string
  listPath: string
  childEndpoints?: ChildEndpoint[]
}) {
  const [rows, setRows] = useState<Record<string, unknown>[]>([])
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null)
  const [childData, setChildData] = useState<Record<string, unknown>>({})
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  async function load() {
    setLoading(true)
    setError('')
    try {
      const response = await api.get(listPath)
      setRows(Array.isArray(response.data) ? response.data : [response.data])
    } catch (e) {
      setError(apiError(e))
    } finally {
      setLoading(false)
    }
  }

  async function selectRow(row: Record<string, unknown>) {
    setSelected(row)
    setChildData({})
    const next: Record<string, unknown> = {}

    for (const endpoint of childEndpoints) {
      const path = endpoint.buildPath(row)
      if (!path) continue
      try {
        const response = await api.get(path)
        next[endpoint.label] = response.data
      } catch (e) {
        next[endpoint.label] = { error: apiError(e) }
      }
    }
    setChildData(next)
  }

  useEffect(() => {
    void load()
  }, [listPath])

  if (loading) return <Loading />

  return (
    <>
      <ErrorBox message={error} />

      <Panel title={title} actions={<button onClick={load}>Refresh</button>}>
        <p className="hint">{description}</p>
        <RecordTable
          rows={rows}
          selectedId={selected ? String(selected.id ?? '') : undefined}
          onSelect={selectRow}
        />
      </Panel>

      {selected && (
        <Panel title="Selected Record">
          <JsonViewer value={selected} />
        </Panel>
      )}

      {Object.entries(childData).map(([label, value]) => (
        <Panel title={label} key={label}>
          <JsonViewer value={value} />
        </Panel>
      ))}
    </>
  )
}
