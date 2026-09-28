import React from 'react'

export default function ParserStatus({ parsers = [], onSelect }) {
  return (
    <div className="parser-grid">
      {parsers.map(p => (
        <div
          className="parser-card"
          key={p.name}
          onClick={() => onSelect?.(p)}
          style={{ cursor: onSelect ? 'pointer' : 'default', transition: 'border-color 0.2s' }}
        >
          <div className="parser-icon">{p.name[0].toUpperCase()}</div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <b style={{ fontSize: '14px' }}>{p.display_name || p.name}</b>
                <div style={{ fontSize: '11px', color: '#48b7ff', marginTop: '2px' }}>
                  {p.vendor || 'Generic'} &bull; <span className="mono">v{p.version || '1.0'}</span>
                </div>
              </div>
              <span className="pill good">{p.status || 'Active'}</span>
            </div>

            <p style={{ margin: '8px 0 10px', fontSize: '12px', color: '#9bb0c4', lineHeight: '1.4' }}>
              {p.description}
            </p>

            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', fontSize: '11px', color: '#8aa0b6' }}>
              <span
                style={{
                  background: '#071320',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  border: '1px solid #162c41',
                }}
              >
                Format: <b style={{ color: '#d0e2f5' }}>{p.format || p.supported_format}</b>
              </span>
              <span
                style={{
                  background: '#071320',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  border: '1px solid #162c41',
                }}
              >
                Source: <b style={{ color: '#d0e2f5' }}>{p.source || p.supported_source || 'general'}</b>
              </span>
              <span
                style={{
                  background: '#0d2820',
                  color: '#5ee6a1',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  border: '1px solid #144933',
                }}
              >
                Processed: <b>{p.processed_count || 0}</b>
              </span>
              {p.mapping_file && (
                <span
                  style={{
                    background: '#12263a',
                    color: '#8ac4ff',
                    padding: '3px 8px',
                    borderRadius: '6px',
                    border: '1px solid #1b3d60',
                  }}
                >
                  YAML Spec
                </span>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
