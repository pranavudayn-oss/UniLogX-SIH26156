import React, { useEffect, useState } from 'react'
import QuarantineTable from '../components/QuarantineTable'
import QuarantineDetailsModal from '../components/QuarantineDetailsModal'
import { getQuarantines, getQuarantine, reprocessQuarantine, reprocessAllQuarantine } from '../api/client'

export default function Quarantine({ refresh }) {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [msg, setMsg] = useState('')
  const [selected, setSelected] = useState(null)

  const loadData = () => {
    getQuarantines()
      .then(data => {
        setItems(data)
        // If an item is currently selected in modal, keep its data fresh
        if (selected) {
          const fresh = data.find(x => x.id === selected.id)
          if (fresh) setSelected(fresh)
        }
      })
      .catch(() => {})
  }

  useEffect(() => {
    loadData()
  }, [refresh])

  const handleSelect = (item) => {
    setSelected(item)
    // Fetch full quarantine record details by ID to ensure freshest data
    if (item?.id) {
      getQuarantine(item.id)
        .then(full => { if (full) setSelected(full) })
        .catch(() => {})
    }
  }

  const reprocessAll = async () => {
    setLoading(true)
    setMsg('Reprocessing all quarantined events...')
    try {
      const res = await reprocessAllQuarantine()
      setMsg(`Reprocessing complete: ${res.reprocessed || 0} resolved into Events, ${res.failed || 0} remain quarantined.`)
      loadData()
    } catch (e) {
      setMsg('Reprocessing request failed.')
    } finally {
      setLoading(false)
    }
  }

  const reprocessOne = async (id) => {
    setLoading(true)
    try {
      const res = await reprocessQuarantine(id)
      if (res.reprocessed > 0) {
        setMsg(`Item #${id} reprocessed successfully and normalized into Events.`)
      } else {
        setMsg(`Item #${id} could not be parsed: Still unresolved.`)
      }
      loadData()
      return res
    } catch (e) {
      setMsg(`Failed to reprocess #${id}: ${e.message || 'Error'}`)
      throw e
    } finally {
      setLoading(false)
    }
  }

  const activeCount = items.filter(x => x.status !== 'reprocessed').length

  return (
    <section>
      <div className="section-head">
        <div>
          <h2>Quarantine Store</h2>
          <p>
            Unknown, malformed, or schema-invalid events are isolated while raw content is preserved.
            {activeCount > 0 && <span style={{ color: '#ff9aa8', marginLeft: '6px' }}>({activeCount} pending resolution)</span>}
          </p>
        </div>
        <button
          className="button-link"
          onClick={reprocessAll}
          disabled={loading || activeCount === 0}
          style={{ opacity: loading || activeCount === 0 ? 0.5 : 1 }}
        >
          {loading ? 'Reprocessing...' : 'Reprocess All Quarantined'}
        </button>
      </div>

      {msg && <div className="notice" style={{ marginBottom: '14px' }}>{msg}</div>}

      <QuarantineTable
        items={items}
        onSelect={handleSelect}
        onReprocessOne={reprocessOne}
      />

      <QuarantineDetailsModal
        item={selected}
        onClose={() => setSelected(null)}
        onReprocess={reprocessOne}
      />
    </section>
  )
}
