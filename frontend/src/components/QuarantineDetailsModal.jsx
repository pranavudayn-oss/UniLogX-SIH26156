import React, { useState } from 'react'

export default function QuarantineDetailsModal({ item, onClose, onReprocess }) {
  if (!item) return null

  const [loading, setLoading] = useState(false)
  const [reprocessMsg, setReprocessMsg] = useState(null)
  const [copiedRaw, setCopiedRaw] = useState(false)
  const [copiedHash, setCopiedHash] = useState(false)

  const copyToClipboard = (text, setFlag) => {
    navigator.clipboard?.writeText(text).then(() => {
      setFlag(true)
      setTimeout(() => setFlag(false), 2000)
    }).catch(() => {})
  }

  const handleReprocess = async () => {
    setLoading(true)
    setReprocessMsg(null)
    try {
      const res = await onReprocess?.(item.id)
      if (res?.reprocessed > 0) {
        setReprocessMsg({ type: 'success', text: `Success! Quarantined event #${item.id} was successfully parsed and normalized into Events.` })
      } else {
        setReprocessMsg({ type: 'error', text: `Reprocess attempt completed: Log could not be parsed by active parsers. Remains quarantined.` })
      }
    } catch (e) {
      setReprocessMsg({ type: 'error', text: `Reprocess failed: ${e.message || 'Unknown error'}` })
    } finally {
      setLoading(false)
    }
  }

  const isResolved = item.status === 'reprocessed'

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" style={{ maxWidth: '880px' }} onClick={e => e.stopPropagation()}>
        {/* MODAL HEADER */}
        <div className="modal-head" style={{ alignItems: 'flex-start' }}>
          <div>
            <div className="eyebrow" style={{ color: '#ff9aa8', letterSpacing: '0.12em' }}>QUARANTINE AUDIT &amp; FORENSIC EVIDENCE</div>
            <h2 style={{ margin: '4px 0 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
              Quarantine Record
              <span className="mono" style={{ fontSize: '13px', background: '#241217', padding: '3px 8px', borderRadius: '6px', color: '#ff9aa8', fontWeight: 'normal' }}>
                #{item.id}
              </span>
            </h2>
          </div>
          <button onClick={onClose} style={{ fontSize: '28px', cursor: 'pointer', lineHeight: '1' }}>×</button>
        </div>

        {/* NOTICES */}
        {reprocessMsg && (
          <div
            className="notice"
            style={{
              marginTop: '16px',
              background: reprocessMsg.type === 'success' ? '#0d2d1f' : '#2d1419',
              border: `1px solid ${reprocessMsg.type === 'success' ? '#1f6a49' : '#6a1f2c'}`,
              color: reprocessMsg.type === 'success' ? '#5ee6a1' : '#ff9aa8',
            }}
          >
            {reprocessMsg.text}
          </div>
        )}

        {/* SECTION 1: QUARANTINE STATUS & ROOT CAUSE */}
        <div style={{ marginTop: '18px' }}>
          <div style={{
            background: '#150a0e',
            border: '1px solid #3c1a22',
            borderRadius: '10px',
            padding: '14px 16px',
            marginBottom: '14px'
          }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#ff9aa8', marginBottom: '4px' }}>
              Quarantine Root Cause / Diagnosis
            </div>
            <div style={{ color: '#ffccd4', fontSize: '13px', fontWeight: '600' }}>
              {item.reason || 'Unknown error during format detection / parsing'}
            </div>
          </div>

          <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', margin: '0 0 16px' }}>
            <div>
              <span>Status</span>
              <span className={`pill ${isResolved ? 'good' : 'bad'}`}>
                {item.status || 'quarantined'}
              </span>
            </div>
            <div>
              <span>Detected Source</span>
              <b>{item.source_type || 'unknown'}</b>
            </div>
            <div>
              <span>Parser Attempted</span>
              <b>{item.parser_attempted || 'none'}</b>
            </div>
            <div>
              <span>Quarantined At</span>
              <b style={{ fontSize: '11px' }}>{item.created_at || '—'}</b>
            </div>
          </div>
        </div>

        {/* SECTION 2: PROVENANCE & CHAIN OF CUSTODY */}
        <div style={{ marginTop: '10px' }}>
          <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#48b7ff', marginBottom: '8px' }}>
            Provenance &amp; Source Metadata
          </h3>
          <div className="detail-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', margin: '0 0 14px' }}>
            <div>
              <span>Source File</span>
              <b>{item.source_file || 'upload'}</b>
            </div>
            <div>
              <span>Line Number</span>
              <b>{item.line_number ?? '—'}</b>
            </div>
            <div>
              <span>Ingestion ID</span>
              <b className="mono" style={{ fontSize: '11px' }}>{item.ingestion_id || '—'}</b>
            </div>
            <div style={{ gridColumn: 'span 3' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>SHA-256 Raw Hash</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(item.raw_hash, setCopiedHash)}
                  style={{ background: 'transparent', border: 'none', color: '#7f91a6', fontSize: '11px', cursor: 'pointer' }}
                >
                  {copiedHash ? 'Copied!' : 'Copy Hash'}
                </button>
              </div>
              <b className="mono" style={{ color: '#ff9aa8', fontSize: '11px', wordBreak: 'break-all' }}>
                {item.raw_hash || '—'}
              </b>
            </div>
          </div>
        </div>

        {/* SECTION 3: UNTOUCHED RAW EVIDENCE */}
        <div style={{ marginTop: '10px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#ff9aa8', margin: 0 }}>
              Untouched Quarantined Raw Log
            </h3>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: '#ff9aa8' }}>● Exact raw content preserved</span>
              <button
                type="button"
                className="button-link"
                style={{ padding: '4px 10px', fontSize: '11px', cursor: 'pointer', background: '#3b1c24', border: '1px solid #632d3b' }}
                onClick={() => copyToClipboard(item.raw_text, setCopiedRaw)}
              >
                {copiedRaw ? 'Copied!' : 'Copy Raw'}
              </button>
            </div>
          </div>
          <pre style={{
            background: '#040b13',
            border: '1px solid #3c1a22',
            color: '#ffb3bf',
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
            {item.raw_text || '—'}
          </pre>
        </div>

        {/* SECTION 4: ACTIONS */}
        <div style={{
          marginTop: '20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderTop: '1px solid #1b3045',
          paddingTop: '16px'
        }}>
          <div>
            {isResolved ? (
              <span style={{ color: '#5ee6a1', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                ✓ Record was previously reprocessed into normalized Events
              </span>
            ) : (
              <span style={{ color: '#8899aa', fontSize: '12px' }}>
                Reprocessing re-evaluates the log against all active format detectors and parsers.
              </span>
            )}
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              type="button"
              className="button-link"
              style={{ background: '#172738', color: '#c5d5e5', border: '1px solid #233e59' }}
              onClick={onClose}
            >
              Close
            </button>
            <button
              type="button"
              className="button-link"
              onClick={handleReprocess}
              disabled={loading}
              style={{
                opacity: loading ? 0.6 : 1,
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              {loading ? 'Reprocessing...' : isResolved ? 'Reprocess Again' : 'Reprocess Record'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
