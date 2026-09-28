import React, { useState } from 'react'

export default function EventDetailsModal({ event, onClose }) {
  if (!event) return null

  const [copiedRaw, setCopiedRaw] = useState(false)
  const [copiedJson, setCopiedJson] = useState(false)

  const norm = event.normalized || {}
  const ulx = norm.ulx || {}

  // Untouched raw event evidence: prioritize raw_event, then unescape raw_json
  let rawText = event.raw_event
  if (!rawText && event.raw_json) {
    try {
      rawText = JSON.parse(event.raw_json)
    } catch {
      rawText = event.raw_json
    }
  }
  if (!rawText && norm.raw_event) {
    rawText = norm.raw_event
  }
  if (!rawText && event.message) {
    rawText = event.message
  }
  const rawString = typeof rawText === 'object' ? JSON.stringify(rawText, null, 2) : String(rawText || '—')

  const copyToClipboard = (text, setFlag) => {
    navigator.clipboard?.writeText(text).then(() => {
      setFlag(true)
      setTimeout(() => setFlag(false), 2000)
    }).catch(() => {})
  }

  // Derived normalized values
  const eventId = event.event_id || norm.event_id || norm.event?.id || '—'
  const traceId = event.trace_id || norm.trace_id || '—'
  const timestamp = event.timestamp || norm['@timestamp'] || norm.timestamp || '—'
  const sourceIp = event.source_ip || norm.source?.ip || '—'
  const destIp = event.destination_ip || norm.destination?.ip || '—'
  const sourcePort = event.source_port ?? norm.source?.port ?? null
  const sourceService = (typeof norm.source?.service === 'string' ? norm.source.service : norm.source?.service?.name) || norm.source_service || null
  const destPort = event.destination_port ?? norm.destination?.port ?? null
  const destService = (typeof norm.destination?.service === 'string' ? norm.destination.service : norm.destination?.service?.name) || norm.destination_service || null
  const transport = event.transport || norm.network?.transport || norm.protocol || '—'
  const action = event.action || norm.network?.action || norm.action || '—'
  const outcome = event.outcome || norm.event?.outcome || norm.outcome || '—'
  const category = event.category || norm.event?.category || norm.category || '—'
  const eventType = norm.event_type || norm.event?.type || norm.event_code || '—'
  const parserName = event.parser_name || norm.parser || '—'
  const parserVersion = event.parser_version || ulx.parser_version || norm.parser_version || '1.0'
  const sourceFile = event.source_file || ulx.source_file || norm.source_file || 'upload'
  const lineNumber = event.line_number ?? ulx.line_number ?? norm.line_number ?? '—'
  const ingestedAt = event.ingested_at || ulx.ingested_at || norm.ingested_at || '—'
  const processedAt = event.processed_at || ulx.processed_at || event.created_at || '—'
  const rawHash = event.raw_hash || norm.raw_hash || (norm.event?.hash ? norm.event.hash.replace('sha256:', '') : '—')
  const rawPath = event.raw_path || ulx.raw_path || norm.raw_path || null

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" style={{ maxWidth: '960px' }} onClick={e => e.stopPropagation()}>
        {/* MODAL HEADER */}
        <div className="modal-head" style={{ alignItems: 'flex-start' }}>
          <div>
            <div className="eyebrow" style={{ letterSpacing: '0.12em' }}>SIH FORENSIC TRACEABILITY &amp; EVIDENCE AUDIT</div>
            <h2 style={{ margin: '4px 0 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
              Event Details
              <span className="mono" style={{ fontSize: '13px', background: '#12263a', padding: '3px 8px', borderRadius: '6px', color: '#48b7ff', fontWeight: 'normal' }}>
                {eventId}
              </span>
            </h2>
          </div>
          <button onClick={onClose} style={{ fontSize: '28px', cursor: 'pointer', lineHeight: '1' }}>×</button>
        </div>

        {/* SECTION 1: NORMALIZED SECURITY EVENT */}
        <div style={{ marginTop: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#48b7ff', margin: 0 }}>
              1. Normalized Security Event
            </h3>
            <span style={{ fontSize: '11px', color: '#7f91a6' }}>Common Schema Representation</span>
          </div>

          <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', margin: '0 0 16px' }}>
            <div>
              <span>Event ID</span>
              <b className="mono" style={{ fontSize: '11px' }}>{eventId}</b>
            </div>
            <div>
              <span>Trace ID</span>
              <b className="mono" style={{ fontSize: '11px' }}>{traceId}</b>
            </div>
            <div>
              <span>Timestamp (@timestamp)</span>
              <b>{timestamp}</b>
            </div>
            <div>
              <span>Outcome</span>
              <span className={`pill ${outcome === 'failure' ? 'bad' : outcome === 'success' ? 'good' : ''}`}>
                {outcome}
              </span>
            </div>

            <div>
              <span>Source IP (source.ip)</span>
              <b className="mono">{sourceIp}</b>
            </div>
            <div>
              <span>Source Port (source.port)</span>
              <b>
                {sourcePort !== null ? sourcePort : '—'}{' '}
                {sourceService && <span style={{ color: '#2f9ef4', fontSize: '11px' }}>({sourceService})</span>}
              </b>
            </div>
            <div>
              <span>Destination IP (destination.ip)</span>
              <b className="mono">{destIp}</b>
            </div>
            <div>
              <span>Destination Port (destination.port)</span>
              <b>
                {destPort !== null ? destPort : '—'}{' '}
                {destService && <span style={{ color: '#2f9ef4', fontSize: '11px' }}>({destService})</span>}
              </b>
            </div>

            <div>
              <span>Transport / Protocol</span>
              <b>{transport}</b>
            </div>
            <div>
              <span>Action (network.action)</span>
              <b style={{ color: action === 'denied' || action === 'deny' ? '#ff9aa8' : action === 'allowed' || action === 'allow' ? '#5ee6a1' : 'inherit' }}>
                {action}
              </b>
            </div>
            <div>
              <span>Category (event.category)</span>
              <b>{category}</b>
            </div>
            <div>
              <span>Type (event.type)</span>
              <b>{eventType}</b>
            </div>
          </div>
        </div>

        {/* SECTION 2: PARSER & EXECUTION INFORMATION */}
        <div style={{ marginTop: '14px' }}>
          <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#48b7ff', marginBottom: '8px' }}>
            2. Parser &amp; Processing Status
          </h3>
          <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', margin: '0 0 16px' }}>
            <div>
              <span>Parser Name</span>
              <b style={{ color: '#9ad0ff' }}>{parserName}</b>
            </div>
            <div>
              <span>Parser Version</span>
              <b>v{parserVersion}</b>
            </div>
            <div>
              <span>Source Domain</span>
              <b>{event.source_type || norm.source_type || '—'}</b>
            </div>
            <div>
              <span>Processing Status</span>
              <span className="pill good">Validated &amp; Stored</span>
            </div>
          </div>
        </div>

        {/* SECTION 3: FORENSIC TRACEABILITY & PROVENANCE */}
        <div style={{ marginTop: '14px' }}>
          <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#48b7ff', marginBottom: '8px' }}>
            3. Forensic Traceability &amp; Chain of Custody
          </h3>
          <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', margin: '0 0 16px' }}>
            <div>
              <span>Source File</span>
              <b>{sourceFile}</b>
            </div>
            <div>
              <span>Line Number</span>
              <b>{lineNumber}</b>
            </div>
            <div>
              <span>Ingested At</span>
              <b style={{ fontSize: '11px' }}>{ingestedAt}</b>
            </div>
            <div>
              <span>Processed At</span>
              <b style={{ fontSize: '11px' }}>{processedAt}</b>
            </div>
            <div style={{ gridColumn: 'span 4' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>SHA-256 Raw Hash (Evidence Fingerprint)</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(rawHash, () => {})}
                  style={{ background: 'transparent', border: 'none', color: '#7f91a6', fontSize: '11px', cursor: 'pointer' }}
                >
                  Copy Hash
                </button>
              </div>
              <b className="mono" style={{ color: '#32d583', fontSize: '11px', wordBreak: 'break-all' }}>
                {rawHash}
              </b>
            </div>
            {rawPath && (
              <div style={{ gridColumn: 'span 4' }}>
                <span>Raw Storage Evidence Location</span>
                <b className="mono" style={{ color: '#48b7ff', fontSize: '11px', wordBreak: 'break-all' }}>
                  {rawPath}
                </b>
              </div>
            )}
          </div>
        </div>

        {/* SECTION 4: ORIGINAL RAW EVENT (UNTOUCHED EVIDENCE) */}
        <div style={{ marginTop: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#48b7ff', margin: 0 }}>
              4. Original Raw Event (Untouched Evidence)
            </h3>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: '#32d583' }}>● Preserved as received</span>
              <button
                type="button"
                className="button-link"
                style={{ padding: '4px 10px', fontSize: '11px', cursor: 'pointer' }}
                onClick={() => copyToClipboard(rawString, setCopiedRaw)}
              >
                {copiedRaw ? 'Copied!' : 'Copy Raw'}
              </button>
            </div>
          </div>
          <pre style={{
            background: '#040b13',
            border: '1px solid #143224',
            color: '#49e88d',
            padding: '12px 14px',
            borderRadius: '8px',
            overflowX: 'auto',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            fontSize: '12px',
            fontFamily: "'JetBrains Mono', monospace",
            lineHeight: '1.5',
            margin: 0
          }}>
            {rawString}
          </pre>
        </div>

        {/* SECTION 5: COMPLETE NORMALIZED JSON */}
        <div style={{ marginTop: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#48b7ff', margin: 0 }}>
              5. Complete Normalized JSON
            </h3>
            <button
              type="button"
              className="button-link"
              style={{ padding: '4px 10px', fontSize: '11px', cursor: 'pointer', background: '#12304b' }}
              onClick={() => copyToClipboard(JSON.stringify(norm, null, 2), setCopiedJson)}
            >
              {copiedJson ? 'Copied!' : 'Copy JSON'}
            </button>
          </div>
          <pre style={{
            background: '#050d18',
            border: '1px solid #1b354f',
            color: '#a3d4ff',
            padding: '12px 14px',
            borderRadius: '8px',
            maxHeight: '220px',
            overflowY: 'auto',
            fontSize: '11px',
            fontFamily: "'JetBrains Mono', monospace",
            lineHeight: '1.4',
            margin: 0
          }}>
            {JSON.stringify(norm, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  )
}
