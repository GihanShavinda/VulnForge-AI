import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { api, apiError } from '../lib/api'
import { ErrorBox, Panel } from '../components/Common'
import JsonViewer from '../components/JsonViewer'
import RecordTable from '../components/RecordTable'

type GraphPath = {
  id?: string
  path_status?: string
  confidence?: string
  confidence_score?: number
  node_sequence?: string[]
  relationship_sequence?: string[]
  critical_destination?: boolean
  credential_dependency?: boolean
  reachable_high_value_asset?: boolean
}

function GraphCanvas({ path }: { path: GraphPath | null }) {
  const ref = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!ref.current || !path) return

    const nodes = path.node_sequence ?? []
    const relationships = path.relationship_sequence ?? []
    const elements: cytoscape.ElementDefinition[] = []

    nodes.forEach((id) => {
      elements.push({
        data: { id, label: id },
      })
    })

    relationships.forEach((rel, index) => {
      const source = nodes[index]
      const target = nodes[index + 1]
      if (!source || !target) return
      elements.push({
        data: {
          id: `edge-${index}`,
          source,
          target,
          label: rel,
        },
      })
    })

    const cy = cytoscape({
      container: ref.current,
      elements,
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 25,
      },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#10b981',
            color: '#e5e7eb',
            label: 'data(label)',
            'text-wrap': 'wrap',
            'text-max-width': '130px',
            'font-size': 10,
            width: 36,
            height: 36,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            color: '#94a3b8',
            'font-size': 8,
            'text-background-color': '#071019',
            'text-background-opacity': 1,
          },
        },
      ],
    })

    return () => cy.destroy()
  }, [path])

  return <div ref={ref} className="graph-canvas" />
}

export default function AttackGraphPage() {
  const [runs, setRuns] = useState<Record<string, unknown>[]>([])
  const [paths, setPaths] = useState<GraphPath[]>([])
  const [selectedPath, setSelectedPath] = useState<GraphPath | null>(null)
  const [evidence, setEvidence] = useState<unknown>(null)
  const [error, setError] = useState('')

  async function load() {
    setError('')
    try {
      const [r, p] = await Promise.all([
        api.get('/attack-graph/runs'),
        api.get('/attack-graph/paths'),
      ])
      setRuns(Array.isArray(r.data) ? r.data : [])
      setPaths(Array.isArray(p.data) ? p.data : [])
    } catch (e) {
      setError(apiError(e))
    }
  }

  async function selectPath(row: Record<string, unknown>) {
    const path = row as GraphPath
    setSelectedPath(path)
    setEvidence(null)
    if (!path.id) return
    try {
      const response = await api.get(`/attack-graph/paths/${path.id}/evidence`)
      setEvidence(response.data)
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

      <Panel title="Neo4j Attack Graph" actions={<button onClick={load}>Refresh</button>}>
        <p className="hint">
          Paths are analytical. A theoretical or supported edge never proves exploitation.
        </p>
        <GraphCanvas path={selectedPath} />
      </Panel>

      <Panel title="Calculated Attack Paths">
        <RecordTable
          rows={paths as unknown as Record<string, unknown>[]}
          onSelect={selectPath}
          selectedId={selectedPath?.id}
        />
      </Panel>

      {selectedPath && (
        <Panel title="Selected Path">
          <JsonViewer value={selectedPath} />
        </Panel>
      )}

      {evidence !== null && (
        <Panel title="Path Evidence">
          <JsonViewer value={evidence} />
        </Panel>
      )}

      <Panel title="Graph Sync Runs">
        <RecordTable rows={runs} />
      </Panel>
    </>
  )
}
