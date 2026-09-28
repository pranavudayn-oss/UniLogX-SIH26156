import React from 'react'
import { LayoutDashboard, Upload, List, ShieldAlert, Puzzle } from 'lucide-react'
const items=[['dashboard','Dashboard',LayoutDashboard],['ingest','Ingest Logs',Upload],['events','Events',List],['quarantine','Quarantine',ShieldAlert],['parsers','Parsers',Puzzle]]
export default function Sidebar({page,setPage}){return <aside className="sidebar"><div className="brand"><div className="brand-mark">U</div><div><b>UniLogX</b><small>Universal Log Pre-Processor</small></div></div><nav>{items.map(([id,label,Icon])=><button key={id} className={page===id?'nav active':'nav'} onClick={()=>setPage(id)}><Icon size={18}/>{label}</button>)}</nav><div className="side-foot"><span className="dot"/>Prototype • Offline ready</div></aside>}
