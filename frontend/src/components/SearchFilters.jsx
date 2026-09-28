import React, { useState } from 'react'

export default function SearchFilters({
  value,
  setValue,
  source,
  setSource,
  outcome = '',
  setOutcome,
  category = '',
  setCategory,
  transport = '',
  setTransport,
  parser = '',
  setParser,
  sourceIp = '',
  setSourceIp,
  destIp = '',
  setDestIp,
  destPort = '',
  setDestPort,
}) {
  const [showAdvanced, setShowAdvanced] = useState(false)

  return (
    <div className="filters" style={{ flexDirection: 'column', gap: '8px' }}>
      {/* Primary search bar */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          style={{ flex: '1 1 320px', minWidth: '240px' }}
          placeholder="Search: IP, field=value (e.g. source.ip=10.0.0.1 destination.port=443 outcome=failure)"
          value={value}
          onChange={e => setValue(e.target.value)}
        />
        <button
          className="button-link"
          style={{ padding: '6px 12px', fontSize: '12px', cursor: 'pointer', whiteSpace: 'nowrap' }}
          onClick={() => setShowAdvanced(v => !v)}
        >
          {showAdvanced ? '▲ Less Filters' : '▼ More Filters'}
        </button>
      </div>

      {/* Quick filter row */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        <select value={source} onChange={e => setSource(e.target.value)}>
          <option value="">All Sources</option>
          <option value="firewall">Firewall (Cisco ASA / CEF)</option>
          <option value="web_server">Web Server (Nginx / Apache)</option>
          <option value="cloud_provider">Cloud Provider (CloudTrail)</option>
          <option value="syslog_host">Syslog Host</option>
          <option value="network_device">Network Device (KV)</option>
        </select>

        <select value={outcome} onChange={e => setOutcome?.(e.target.value)}>
          <option value="">All Outcomes</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
          <option value="unknown">Unknown</option>
        </select>

        <select value={category} onChange={e => setCategory?.(e.target.value)}>
          <option value="">All Categories</option>
          <option value="network">Network</option>
          <option value="web">Web</option>
          <option value="cloud">Cloud</option>
          <option value="authentication">Authentication</option>
          <option value="system">System</option>
        </select>
      </div>

      {/* Advanced filters (collapsible) */}
      {showAdvanced && (
        <div style={{
          display: 'flex', gap: '8px', flexWrap: 'wrap',
          padding: '10px 12px',
          background: 'rgba(255,255,255,0.04)',
          borderRadius: '6px',
          border: '1px solid rgba(255,255,255,0.08)'
        }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: '#8899aa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Transport</label>
            <select value={transport} onChange={e => setTransport?.(e.target.value)} style={{ minWidth: '120px' }}>
              <option value="">Any</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: '#8899aa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Parser</label>
            <select value={parser} onChange={e => setParser?.(e.target.value)} style={{ minWidth: '160px' }}>
              <option value="">Any Parser</option>
              <option value="cisco_asa">Cisco ASA</option>
              <option value="nginx">Nginx</option>
              <option value="cloud_json">Cloud JSON</option>
              <option value="syslog">Syslog</option>
              <option value="generic_kv">Generic KV</option>
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: '#8899aa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Source IP</label>
            <input
              value={sourceIp}
              onChange={e => setSourceIp?.(e.target.value)}
              placeholder="e.g. 10.0.0.1"
              style={{ minWidth: '130px' }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: '#8899aa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Dest IP</label>
            <input
              value={destIp}
              onChange={e => setDestIp?.(e.target.value)}
              placeholder="e.g. 192.168.1.1"
              style={{ minWidth: '130px' }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: '#8899aa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Dest Port</label>
            <input
              type="number"
              value={destPort}
              onChange={e => setDestPort?.(e.target.value)}
              placeholder="e.g. 443"
              style={{ minWidth: '90px' }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: '#8899aa', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Field Query Examples</label>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {[
                'source.ip=10.0.0.1',
                'destination.port=443',
                'network.transport=TCP',
                'outcome=failure',
                'event.category=web',
                'parser=nginx',
              ].map(ex => (
                <span
                  key={ex}
                  onClick={() => setValue(ex)}
                  style={{
                    fontSize: '11px', cursor: 'pointer',
                    background: 'rgba(47,158,244,0.15)',
                    border: '1px solid rgba(47,158,244,0.3)',
                    borderRadius: '4px',
                    padding: '2px 7px',
                    color: '#2f9ef4',
                    fontFamily: 'monospace',
                  }}
                  title="Click to use this filter"
                >
                  {ex}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
