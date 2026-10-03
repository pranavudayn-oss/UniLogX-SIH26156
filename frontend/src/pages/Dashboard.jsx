import React, { useEffect, useState } from 'react'
import { getMetrics, getEvents, getEvent } from '../api/client'
import MetricsCards from '../components/MetricsCards'
import AnalyticsCharts from '../components/AnalyticsCharts'
import EventTable from '../components/EventTable'
import EventDetailsModal from '../components/EventDetailsModal'
import UploadPanel from '../components/UploadPanel'
import SampleLogsCard from '../components/SampleLogsCard'

export default function Dashboard({ refresh }) {
  const [m, setM] = useState(null)
  const [events, setEvents] = useState([])
  const [selected, setSelected] = useState(null)

  const loadData = () => {
    getMetrics()
      .then(setM)
      .catch(() => {})
    getEvents({ limit: 8 })
      .then(setEvents)
      .catch(() => {})
  }

  useEffect(() => {
    loadData()
  }, [refresh])

  const handleSelect = (evt) => {
    setSelected(evt)
    if (evt?.event_id) {
      getEvent(evt.event_id)
        .then(full => {
          if (full) setSelected(full)
        })
        .catch(() => {})
    }
  }

  return (
    <section>
      {/* 1. TOP METRIC CARDS */}
      <MetricsCards metrics={m} />

      {/* 2. SAMPLE LOGS / JUDGE TESTING KIT */}
      <SampleLogsCard />

      {/* 3. LOG INGESTION DROPZONE */}
      <UploadPanel onDone={loadData} />

      {/* 3. OPERATIONAL ANALYTICS VISUALIZATIONS */}
      <AnalyticsCharts metrics={m} />

      {/* 4. RECENT ACTIVITY TIMELINE */}
      <div className="section-head" style={{ marginTop: '24px' }}>
        <div>
          <h2>Recent Activity</h2>
          <p>Real-time stream of normalized events processed through the pipeline.</p>
        </div>
      </div>

      <EventTable events={events} onSelect={handleSelect} />
      <EventDetailsModal event={selected} onClose={() => setSelected(null)} />
    </section>
  )
}
