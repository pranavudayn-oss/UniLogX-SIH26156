import React, { useEffect, useState } from 'react'
import { getEvents, getEvent } from '../api/client'
import EventTable from '../components/EventTable'
import EventDetailsModal from '../components/EventDetailsModal'
import SearchFilters from '../components/SearchFilters'

export default function Events({ refresh }) {
  const [events, setEvents] = useState([])
  const [q, setQ] = useState('')
  const [source, setSource] = useState('')
  const [outcome, setOutcome] = useState('')
  const [category, setCategory] = useState('')
  const [transport, setTransport] = useState('')
  const [parser, setParser] = useState('')
  const [sourceIp, setSourceIp] = useState('')
  const [destIp, setDestIp] = useState('')
  const [destPort, setDestPort] = useState('')
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    const params = {
      q: q || undefined,
      source: source || undefined,
      outcome: outcome || undefined,
      category: category || undefined,
      transport: transport || undefined,
      parser: parser || undefined,
      source_ip: sourceIp || undefined,
      destination_ip: destIp || undefined,
      destination_port: destPort ? Number(destPort) : undefined,
      limit: 200,
    }
    // Remove undefined keys
    Object.keys(params).forEach(k => params[k] === undefined && delete params[k])

    const t = setTimeout(() => {
      getEvents(params)
        .then(setEvents)
        .catch(() => {})
    }, 200)
    return () => clearTimeout(t)
  }, [q, source, outcome, category, transport, parser, sourceIp, destIp, destPort, refresh])

  // Build export URL with ALL active filters — same params used for the live search
  const buildExportParams = () => {
    const raw = {
      q,
      source,
      outcome,
      category,
      transport,
      parser,
      source_ip: sourceIp,
      destination_ip: destIp,
      destination_port: destPort,
    }
    return new URLSearchParams(Object.entries(raw).filter(([, v]) => v)).toString()
  }

  const activeFilterCount = [q, source, outcome, category, transport, parser, sourceIp, destIp, destPort]
    .filter(Boolean).length

  const exportParams = buildExportParams()
  const exportCsvUrl = `/api/v1/events/export/csv${exportParams ? '?' + exportParams : ''}`
  const exportJsonUrl = `/api/v1/events/export/json${exportParams ? '?' + exportParams : ''}`

  return (
    <section>
      <div className="section-head">
        <div>
          <h2>Event Explorer</h2>
          <p>Unified search and forensic filtering across heterogeneous security events.</p>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexDirection: 'column', alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            <a className="button-link" href={exportCsvUrl} download="unilogx-events.csv">
              Export CSV
            </a>
            <a
              className="button-link"
              style={{ background: '#173b5c', border: '1px solid #2f9ef4' }}
              href={exportJsonUrl}
              download="unilogx-events.json"
            >
              Export JSON
            </a>
          </div>
          {/* Export count indicator */}
          <div style={{ fontSize: '11px', color: '#667788', textAlign: 'right' }}>
            {activeFilterCount > 0
              ? `Exporting ${events.length} filtered event${events.length !== 1 ? 's' : ''}`
              : `Exporting all ${events.length} event${events.length !== 1 ? 's' : ''}`}
          </div>
        </div>
      </div>

      <SearchFilters
        value={q}
        setValue={setQ}
        source={source}
        setSource={setSource}
        outcome={outcome}
        setOutcome={setOutcome}
        category={category}
        setCategory={setCategory}
        transport={transport}
        setTransport={setTransport}
        parser={parser}
        setParser={setParser}
        sourceIp={sourceIp}
        setSourceIp={setSourceIp}
        destIp={destIp}
        setDestIp={setDestIp}
        destPort={destPort}
        setDestPort={setDestPort}
      />

      <div style={{ margin: '4px 0 8px', fontSize: '12px', color: '#667788' }}>
        {events.length} event{events.length !== 1 ? 's' : ''} found
        {activeFilterCount > 0 && (
          <span style={{ color: '#48b7ff', marginLeft: '8px' }}>
            ({activeFilterCount} filter{activeFilterCount !== 1 ? 's' : ''} active)
          </span>
        )}
      </div>

      <EventTable
        events={events}
        onSelect={(evt) => {
          setSelected(evt)
          if (evt?.event_id) {
            getEvent(evt.event_id)
              .then(full => { if (full) setSelected(full) })
              .catch(() => {})
          }
        }}
      />
      <EventDetailsModal event={selected} onClose={() => setSelected(null)} />
    </section>
  )
}
