import React from 'react'
import { Download } from 'lucide-react'

export default function SampleLogsCard() {
  return (
    <div
      className="panel"
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '16px',
        border: '1px solid #1e3a5a',
        background: 'linear-gradient(180deg, #0e2035, #0a1726)'
      }}
    >
      <div style={{ flex: 1, minWidth: '280px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <span className="eyebrow" style={{ color: '#4bb8ff', fontWeight: 700 }}>JUDGE TESTING KIT</span>
          <span className="pill good">175 Synthetic Logs</span>
        </div>
        <div className="panel-title" style={{ fontSize: '16px' }}>Sample Logs</div>
        <p className="muted" style={{ margin: '4px 0 0' }}>
          Download 100+ synthetic logs covering all implemented parsers, including unknown logs for quarantine testing.
        </p>
      </div>
      <div>
        <a
          href="/UniLogX-Sample-Logs.zip"
          download="UniLogX-Sample-Logs.zip"
          className="button-link"
          style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}
        >
          <Download size={16} />
          Download Sample Logs
        </a>
      </div>
    </div>
  )
}
