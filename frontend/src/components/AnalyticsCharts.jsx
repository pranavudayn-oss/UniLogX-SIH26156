import React from 'react'

export default function AnalyticsCharts({ metrics }) {
  if (!metrics) return null

  const parsers = Object.entries(metrics.events_by_parser || metrics.parsers || {})
  const categories = Object.entries(metrics.events_by_category || metrics.categories || {})
  const outcomes = Object.entries(metrics.events_by_outcome || metrics.outcomes || {})
  const reasons = Object.entries(metrics.quarantine_summary?.by_reason || {})

  const totalEvents = metrics.total_events || 1
  const maxParserCount = Math.max(...parsers.map(([, v]) => v), 1)
  const maxCategoryCount = Math.max(...categories.map(([, v]) => v), 1)

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '14px', marginBottom: '18px' }}>
      {/* 1. EVENTS BY PARSER / SOURCE */}
      <div className="panel" style={{ margin: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <div className="panel-title" style={{ fontSize: '15px' }}>Events by Parser</div>
            <p className="muted" style={{ margin: '2px 0 0', fontSize: '11px' }}>
              Normalized traffic distribution across registered parsers
            </p>
          </div>
          <span style={{ fontSize: '11px', color: '#48b7ff' }}>{parsers.length} active</span>
        </div>

        {parsers.length === 0 ? (
          <div className="muted" style={{ padding: '20px 0', textAlign: 'center' }}>No event data recorded yet.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {parsers.map(([name, count]) => {
              const pct = Math.round((count / maxParserCount) * 100)
              const totalPct = Math.round((count / totalEvents) * 100)
              return (
                <div key={name}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: 600, color: '#e8edf5' }}>{name}</span>
                    <span style={{ color: '#8899aa' }}>
                      <b style={{ color: '#fff' }}>{count}</b> ({totalPct}%)
                    </span>
                  </div>
                  <div style={{ height: '6px', background: '#0a1624', borderRadius: '4px', overflow: 'hidden' }}>
                    <div
                      style={{
                        height: '100%',
                        width: `${pct}%`,
                        background: 'linear-gradient(90deg, #2f9ef4, #5ee6a1)',
                        borderRadius: '4px',
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* 2. EVENTS BY CATEGORY */}
      <div className="panel" style={{ margin: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <div className="panel-title" style={{ fontSize: '15px' }}>Events by Category</div>
            <p className="muted" style={{ margin: '2px 0 0', fontSize: '11px' }}>
              Taxonomy distribution based on ECS category mappings
            </p>
          </div>
          <span style={{ fontSize: '11px', color: '#48b7ff' }}>{categories.length} categories</span>
        </div>

        {categories.length === 0 ? (
          <div className="muted" style={{ padding: '20px 0', textAlign: 'center' }}>No categories mapped yet.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {categories.map(([cat, count]) => {
              const pct = Math.round((count / maxCategoryCount) * 100)
              const totalPct = Math.round((count / totalEvents) * 100)
              return (
                <div key={cat}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                    <span style={{ fontWeight: 600, color: '#e8edf5', textTransform: 'capitalize' }}>{cat}</span>
                    <span style={{ color: '#8899aa' }}>
                      <b style={{ color: '#fff' }}>{count}</b> ({totalPct}%)
                    </span>
                  </div>
                  <div style={{ height: '6px', background: '#0a1624', borderRadius: '4px', overflow: 'hidden' }}>
                    <div
                      style={{
                        height: '100%',
                        width: `${pct}%`,
                        background: 'linear-gradient(90deg, #7c5cff, #39b8ff)',
                        borderRadius: '4px',
                        transition: 'width 0.3s ease',
                      }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* 3. EVENT OUTCOMES */}
      <div className="panel" style={{ margin: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <div className="panel-title" style={{ fontSize: '15px' }}>Event Outcomes</div>
            <p className="muted" style={{ margin: '2px 0 0', fontSize: '11px' }}>
              Security verdict breakdown across all ingested events
            </p>
          </div>
        </div>

        {outcomes.length === 0 ? (
          <div className="muted" style={{ padding: '20px 0', textAlign: 'center' }}>No outcomes recorded yet.</div>
        ) : (
          <div style={{ display: 'flex', gap: '12px' }}>
            {outcomes.map(([outcome, count]) => {
              const isGood = outcome.toLowerCase() === 'success' || outcome.toLowerCase() === 'allow'
              const isBad = outcome.toLowerCase() === 'failure' || outcome.toLowerCase() === 'deny' || outcome.toLowerCase() === 'accessdenied'
              const color = isGood ? '#5ee6a1' : isBad ? '#ff9aa8' : '#e8edf5'
              const bg = isGood ? '#0b261b' : isBad ? '#2b1016' : '#0e1e30'
              const border = isGood ? '#164834' : isBad ? '#4d1923' : '#1b344e'

              return (
                <div
                  key={outcome}
                  style={{
                    flex: 1,
                    background: bg,
                    border: `1px solid ${border}`,
                    borderRadius: '10px',
                    padding: '14px',
                    textAlign: 'center',
                  }}
                >
                  <span
                    className={`pill ${isGood ? 'good' : isBad ? 'bad' : ''}`}
                    style={{ textTransform: 'capitalize', marginBottom: '8px' }}
                  >
                    {outcome}
                  </span>
                  <div style={{ fontSize: '24px', fontWeight: 800, color, marginTop: '6px' }}>{count}</div>
                  <div style={{ fontSize: '11px', color: '#7a8fa6', marginTop: '2px' }}>
                    {Math.round((count / totalEvents) * 100)}% of total
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* 4. QUARANTINE ROOT-CAUSE SUMMARY */}
      <div className="panel" style={{ margin: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <div className="panel-title" style={{ fontSize: '15px' }}>Quarantine Diagnostics</div>
            <p className="muted" style={{ margin: '2px 0 0', fontSize: '11px' }}>
              Root causes for isolated/malformed logs
            </p>
          </div>
          <span className={`pill ${metrics.quarantined > 0 ? 'bad' : 'good'}`}>
            {metrics.quarantined} Active
          </span>
        </div>

        {reasons.length === 0 ? (
          <div className="muted" style={{ padding: '20px 0', textAlign: 'center' }}>
            Quarantine store is clear — all events successfully parsed.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '140px', overflowY: 'auto' }}>
            {reasons.slice(0, 5).map(([reason, count]) => (
              <div
                key={reason}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: '#091522',
                  border: '1px solid #172b3e',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '11px',
                }}
              >
                <span
                  style={{
                    color: '#c5d5e5',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxWidth: '80%',
                  }}
                  title={reason}
                >
                  {reason}
                </span>
                <b style={{ color: '#ff9aa8' }}>{count}</b>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
