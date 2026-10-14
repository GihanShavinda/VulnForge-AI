import type { ReactNode } from 'react'

export function Panel({
  title,
  children,
  actions,
}: {
  title: string
  children: ReactNode
  actions?: ReactNode
}) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  )
}

export function StatCard({
  label,
  value,
  hint,
}: {
  label: string
  value: ReactNode
  hint?: string
}) {
  return (
    <article className="stat-card">
      <small>{label}</small>
      <strong>{value}</strong>
      {hint && <span>{hint}</span>}
    </article>
  )
}

export function StatusBadge({ value }: { value: unknown }) {
  const label = String(value ?? 'unknown')
  const normalized = label.toLowerCase().replace(/\s+/g, '-')
  return <span className={`status-badge status-${normalized}`}>{label}</span>
}

export function Loading() {
  return <div className="loading">Loading…</div>
}

export function Empty({ text = 'No records available.' }: { text?: string }) {
  return <div className="empty-state">{text}</div>
}

export function ErrorBox({ message }: { message: string }) {
  if (!message) return null
  return <div className="alert danger">{message}</div>
}

export function SuccessBox({ message }: { message: string }) {
  if (!message) return null
  return <div className="alert success">{message}</div>
}
