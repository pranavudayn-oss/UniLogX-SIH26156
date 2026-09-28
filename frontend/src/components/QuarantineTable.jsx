import React from 'react'

export default function QuarantineTable({ items = [], onSelect, onReprocessOne }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source File</th>
            <th>Source Type</th>
            <th>Reason</th>
            <th>Status</th>
            <th>SHA-256</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {items.map(x => (
            <tr
              key={x.id}
              onClick={() => onSelect?.(x)}
              style={{ cursor: 'pointer' }}
              title="Click to view full quarantine details and raw evidence"
            >
              <td>{x.created_at || '—'}</td>
              <td>{x.source_file || 'upload'}</td>
              <td>{x.source_type}</td>
              <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{x.reason}</td>
              <td>
                <span className={`pill ${x.status === 'reprocessed' ? 'good' : 'bad'}`}>
                  {x.status || 'quarantined'}
                </span>
              </td>
              <td className="mono">{x.raw_hash?.slice(0, 16)}…</td>
              <td>
                {x.status !== 'reprocessed' ? (
                  <button
                    className="button-link"
                    style={{ padding: '4px 10px', fontSize: '11px' }}
                    onClick={e => {
                      e.stopPropagation()
                      onReprocessOne?.(x.id)
                    }}
                  >
                    Reprocess
                  </button>
                ) : (
                  <span style={{ color: '#5ee6a1', fontSize: '11px' }}>Resolved</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!items.length && <div className="empty">No quarantined events.</div>}
    </div>
  )
}
