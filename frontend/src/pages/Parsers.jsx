import React, { useEffect, useState } from 'react'
import { getParsers, getParserDetail } from '../api/client'
import ParserStatus from '../components/ParserStatus'
import ParserDetailsModal from '../components/ParserDetailsModal'

export default function Parsers() {
  const [parsers, setParsers] = useState([])
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    getParsers()
      .then(setParsers)
      .catch(() => {})
  }, [])

  const handleSelect = parser => {
    setSelected(parser)
    if (parser?.name) {
      getParserDetail(parser.name)
        .then(full => {
          if (full) setSelected(full)
        })
        .catch(() => {})
    }
  }

  return (
    <section>
      <div className="section-head">
        <div>
          <h2>Parser Registry</h2>
          <p>
            Plug-and-play parsers are independently registered, versioned, and routed by the detector.
          </p>
        </div>
      </div>
      <ParserStatus parsers={parsers} onSelect={handleSelect} />
      <ParserDetailsModal parser={selected} onClose={() => setSelected(null)} />
    </section>
  )
}
