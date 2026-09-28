import React from 'react'

export default function ParserDetailsModal({ parser, onClose }) {
  if (!parser) return null

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" style={{ maxWidth: '800px' }} onClick={e => e.stopPropagation()}>
        {/* MODAL HEADER */}
        <div className="modal-head" style={{ alignItems: 'flex-start' }}>
          <div>
            <div className="eyebrow" style={{ color: '#48b7ff', letterSpacing: '0.12em' }}>
              PARSER REGISTRY &amp; ONBOARDING
            </div>
            <h2 style={{ margin: '4px 0 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
              {parser.display_name || parser.name}
              <span
                className="mono"
                style={{
                  fontSize: '13px',
                  background: '#12263a',
                  padding: '3px 8px',
                  borderRadius: '6px',
                  color: '#48b7ff',
                  fontWeight: 'normal',
                }}
              >
                v{parser.version || '1.0'}
              </span>
            </h2>
          </div>
          <button onClick={onClose} style={{ fontSize: '28px', cursor: 'pointer', lineHeight: '1' }}>
            ×
          </button>
        </div>

        {/* SECTION 1: METADATA & SPECS */}
        <div style={{ marginTop: '20px' }}>
          <h3
            style={{
              fontSize: '12px',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: '#48b7ff',
              marginBottom: '8px',
            }}
          >
            Parser Identification &amp; Vendor
          </h3>
          <div
            className="detail-grid"
            style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', margin: '0 0 16px' }}
          >
            <div>
              <span>Identifier</span>
              <b className="mono">{parser.name}</b>
            </div>
            <div>
              <span>Vendor / Standard</span>
              <b>{parser.vendor || 'Generic'}</b>
            </div>
            <div>
              <span>Source Domain</span>
              <b>{parser.source || parser.supported_source || 'general'}</b>
            </div>
            <div>
              <span>Status</span>
              <span className="pill good">{parser.status || 'Active'}</span>
            </div>

            <div>
              <span>Log Format</span>
              <b className="mono">{parser.format || parser.supported_format}</b>
            </div>
            <div>
              <span>Mapping Spec</span>
              <b>{parser.mapping_file || 'Native In-Code'}</b>
            </div>
            <div>
              <span>Processed Events</span>
              <b style={{ color: '#5ee6a1' }}>{parser.processed_count || 0}</b>
            </div>
            <div>
              <span>Routing Mode</span>
              <span className="pill" style={{ background: '#12263a', color: '#48b7ff' }}>
                Deterministic
              </span>
            </div>
          </div>
        </div>

        {/* SECTION 2: DESCRIPTION */}
        <div>
          <h3
            style={{
              fontSize: '12px',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: '#48b7ff',
              marginBottom: '8px',
            }}
          >
            Description &amp; Capabilities
          </h3>
          <div
            style={{
              background: '#071320',
              border: '1px solid #162c41',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '13px',
              color: '#c5d5e5',
              lineHeight: '1.5',
            }}
          >
            {parser.description}
          </div>
        </div>

        {/* SECTION 3: SUPPORTED NORMALIZED FIELDS */}
        <div style={{ marginTop: '16px' }}>
          <h3
            style={{
              fontSize: '12px',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: '#48b7ff',
              marginBottom: '8px',
            }}
          >
            Supported Normalized Target Fields
          </h3>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {(parser.supported_fields || []).length > 0 ? (
              parser.supported_fields.map(field => (
                <span
                  key={field}
                  className="mono"
                  style={{
                    background: '#0a1d30',
                    border: '1px solid #1b3d60',
                    color: '#8ac4ff',
                    fontSize: '11px',
                    padding: '4px 9px',
                    borderRadius: '6px',
                  }}
                >
                  {field}
                </span>
              ))
            ) : (
              <span style={{ color: '#7a8ea3', fontSize: '12px' }}>
                Standard ECS-aligned extraction (timestamp, source, destination, message)
              </span>
            )}
          </div>
        </div>

        {/* MODAL FOOTER */}
        <div
          style={{
            marginTop: '24px',
            display: 'flex',
            justifyContent: 'flex-end',
            borderTop: '1px solid #1b3045',
            paddingTop: '16px',
          }}
        >
          <button
            type="button"
            className="button-link"
            style={{ background: '#172738', color: '#c5d5e5', border: '1px solid #233e59' }}
            onClick={onClose}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
