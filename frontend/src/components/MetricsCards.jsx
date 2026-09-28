import React from 'react'

export default function MetricsCards({ metrics }) {
  const cards = [
    { label: 'Total Events', value: metrics?.total_events ?? 0, color: '#39b8ff' },
    { label: 'Quarantined', value: metrics?.quarantined ?? 0, color: metrics?.quarantined ? '#ff9aa8' : '#32d583' },
    { label: 'Parser Success Rate', value: `${metrics?.parser_success_rate ?? 0}%`, color: '#5ee6a1' },
    { label: 'Active Sources', value: metrics?.source_count ?? Object.keys(metrics?.sources || {}).length, color: '#e8edf5' },
  ]

  return (
    <div className="cards">
      {cards.map(c => (
        <div className="card" key={c.label}>
          <span>{c.label}</span>
          <strong style={{ color: c.color }}>{c.value}</strong>
        </div>
      ))}
    </div>
  )
}
