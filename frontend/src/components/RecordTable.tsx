import { Empty } from './Common'

function printable(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export default function RecordTable({
  rows,
  onSelect,
  selectedId,
}: {
  rows: Record<string, unknown>[]
  onSelect?: (row: Record<string, unknown>) => void
  selectedId?: string
}) {
  if (!rows.length) return <Empty />

  const preferred = [
    'id',
    'canonical_id',
    'vulnerability_id',
    'name',
    'title',
    'status',
    'priority_tier',
    'final_score',
    'severity',
    'created_at',
    'imported_at',
  ]

  const discovered = Array.from(
    new Set(rows.flatMap((row) => Object.keys(row))),
  )

  const columns = [
    ...preferred.filter((key) => discovered.includes(key)),
    ...discovered.filter((key) => !preferred.includes(key)),
  ].slice(0, 9)

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const id = String(row.id ?? index)
            return (
              <tr
                key={id}
                className={selectedId === id ? 'selected-row' : ''}
                onClick={() => onSelect?.(row)}
              >
                {columns.map((column) => (
                  <td key={column} className="clip-cell">
                    {printable(row[column])}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
