import React,{useState} from 'react'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import Dashboard from './pages/Dashboard'
import IngestLogs from './pages/IngestLogs'
import Events from './pages/Events'
import Quarantine from './pages/Quarantine'
import Parsers from './pages/Parsers'

export default function App(){
 const [page,setPage]=useState('dashboard')
 const [refresh,setRefresh]=useState(0)
 const view={dashboard:<Dashboard refresh={refresh}/>,ingest:<IngestLogs onDone={()=>setRefresh(x=>x+1)}/>,events:<Events refresh={refresh}/>,quarantine:<Quarantine refresh={refresh}/>,parsers:<Parsers/>}[page]
 return <div className="app-shell"><Sidebar page={page} setPage={setPage}/><main className="main"><Header page={page}/>{view}</main></div>
}
