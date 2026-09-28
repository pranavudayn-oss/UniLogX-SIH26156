import React from 'react'
export default function Header({page}){return <header className="header"><div><div className="eyebrow">SECURITY LOG OPERATIONS</div><h1>{page==='dashboard'?'Dashboard':page==='ingest'?'Ingest Logs':page[0].toUpperCase()+page.slice(1)}</h1></div><div className="status"><span className="dot"/>Pipeline Online</div></header>}
