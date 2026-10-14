export default function JsonViewer({
  value,
  maxHeight = 460,
}: {
  value: unknown
  maxHeight?: number
}) {
  return (
    <pre className="json-viewer" style={{ maxHeight }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}
