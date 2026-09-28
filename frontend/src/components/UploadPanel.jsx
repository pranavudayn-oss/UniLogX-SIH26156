import React, { useState } from 'react'
import { uploadLog } from '../api/client'

export default function UploadPanel({ onDone }) {
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const submit = async () => {
    if (!file) return
    setBusy(true)
    setMsg('Preserving raw evidence and executing pipeline...')
    try {
      const r = await uploadLog(file)
      const ingInfo = r.ingestion_id ? ` • ID: ${r.ingestion_id}` : ''
      setMsg(`✓ Ingested: ${r.processed} normalized, ${r.quarantined} quarantined • Detected: ${r.detected_format}${ingInfo}`)
      onDone?.()
    } catch (e) {
      setMsg(e?.response?.data?.detail || 'Upload failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel">
      <div className="panel-title">Universal Lossless Log Ingestion</div>
      <p className="muted">
        Drop any heterogeneous log file (.log, .txt, .json, .csv) from Firewalls, Web Servers, CloudTrail, Syslog, or custom services.
        Raw evidence is preserved unchanged with cryptographic SHA-256 verification.
      </p>
      <div className="upload-row">
        <input
          type="file"
          accept=".log,.txt,.json,.csv"
          onChange={e => setFile(e.target.files[0])}
        />
        <button onClick={submit} disabled={!file || busy}>
          {busy ? 'Processing...' : 'Process Log'}
        </button>
      </div>
      {msg && <div className="notice">{msg}</div>}
    </div>
  )
}

