from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import init_db
from .api.routes_health import router as health_router
from .api.routes_upload import router as upload_router
from .api.routes_events import router as events_router
from .api.routes_metrics import router as metrics_router
from .api.routes_parsers import router as parsers_router
from .api.routes_quarantine import router as quarantine_router

API_DESCRIPTION = """
## Universal Log Pre-Processing, Normalization & Forensic Traceability Framework

UniLogX ingests heterogeneous, high-volume security and system logs from disparate infrastructure sources, 
preserves untouched raw evidence, detects formats, normalizes fields into an Elastic Common Schema (ECS)-aligned 
taxonomy, enriches network port data offline, isolates malformed records in quarantine with diagnostic error causes, 
and exposes unified search, analytics, and filtered evidence exports.

---

### End-to-End Processing Pipeline Workflow

```text
Log Source (Syslog / Files / API Uploads)
    ↓
1. Ingestion (Multipart files, raw log lines)
    ↓
2. Raw Log Preservation (Byte-exact partitioned storage: raw_logs/YYYY/MM/DD/<ingest-id>/<file>)
    ↓
3. Format & Source Detection (Heuristic inspection: Cisco ASA, Nginx, CloudTrail, Syslog, Generic KV)
    ↓
4. Parser Selection & Routing (Modular plug-and-play parser registry)
    ↓
5. Field Extraction (Timestamp, IPs, ports, transport, action, outcome, category)
    ↓
6. Normalization (ECS-aligned taxonomy mapping)
    ↓
7. Forensic Traceability (UUID event_id, trace_id, SHA-256 raw_hash, raw_path, timestamps)
    ↓
8. Lightweight Offline Enrichment (Deterministic port-to-service mapping, e.g. 443→HTTPS, 22→SSH)
    ↓
9. Schema Validation (Pydantic contract enforcement; malformed logs routed to Quarantine)
    ↓
10. Storage & Indexing (Indexed SQLite database with full query filters)
    ↓
11. Unified Search, Dashboard Analytics & Filter-Aware Exports (CSV / JSON)
```

---

### Key Capabilities

- **Raw Evidence Preservation:** Raw logs are preserved byte-exact in local partitioned storage with SHA-256 integrity digests.
- **Unified Advanced Search:** Query via free-text or field=value syntax (e.g. `source.ip=10.0.0.1 destination.port=443 outcome=failure`).
- **Forensic Detail View:** Inspect normalized ECS fields alongside untouched original raw logs and custody chains.
- **Quarantine & Reprocessing:** Non-destructive isolation of unparseable logs with root-cause diagnostics and retry capability.
- **Offline Port Enrichment:** Built-in mapping for common IANA service ports without external network dependencies.
- **Filtered Evidence Export:** Export search results as CSV or JSON with complete traceability provenance.
- **Operational Analytics:** Real-time KPIs, parser traffic distribution, category taxonomy, and quarantine diagnostics.
"""

TAGS_METADATA = [
    {
        "name": "health",
        "description": "Liveness probe and active database connectivity verification.",
    },
    {
        "name": "ingestion",
        "description": "Raw log upload, date-partitioned raw evidence preservation, and pipeline dispatch.",
    },
    {
        "name": "events",
        "description": "Unified event search, ECS query filtering, forensic event retrieval, and CSV/JSON evidence export.",
    },
    {
        "name": "quarantine",
        "description": "Isolated malformed log inspection, root-cause diagnostic error reporting, and reprocessing workflow.",
    },
    {
        "name": "metrics",
        "description": "Real-time operational KPIs, parser and taxonomy distributions, quarantine diagnostics, and activity stream.",
    },
    {
        "name": "parsers",
        "description": "Runtime parser registry inventory, capability specifications, and field mapping metadata.",
    },
]

app = FastAPI(
    title="UniLogX - Universal Log Pre-Processing Framework",
    version="0.1.0",
    description=API_DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from .services.syslog_receiver import start_syslog_server

@app.on_event("startup")
async def startup():
    init_db()
    try:
        app.state.syslog_transport = await start_syslog_server()
    except Exception:
        pass

@app.on_event("shutdown")
def shutdown():
    transport = getattr(app.state, "syslog_transport", None)
    if transport:
        try:
            transport.close()
        except Exception:
            pass


app.include_router(health_router, prefix="/api/v1")
app.include_router(upload_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(metrics_router, prefix="/api/v1")
app.include_router(parsers_router, prefix="/api/v1")
app.include_router(quarantine_router, prefix="/api/v1")
