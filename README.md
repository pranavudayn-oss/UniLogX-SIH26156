# UniLogX

Universal Log Pre-Processing Framework — SIH26156 prototype.

## Prototype goal

UniLogX ingests heterogeneous logs, auto-detects the source format, routes each event to a parser plugin, extracts fields, normalizes them into a common event representation, validates the result, creates a UUID/SHA-256 trace chain, preserves the raw event, and quarantines unknown/malformed events instead of silently dropping them.

The implementation follows the project architecture supplied by the team and the SIH26156 solution: parser plugins, configuration mappings, common normalization, raw preservation, traceability, quarantine, local/offline storage, and a React dashboard. The SIH submission describes the need for heterogeneous-format ingestion, lossless raw preservation, common taxonomy, traceability, plug-and-play onboarding, air-gapped deployment, and container packaging. 

## Current MVP support

- Nginx access logs
- Cisco ASA-style firewall logs
- CloudTrail-like JSON events
- Syslog-style events
- Generic key=value logs
- Unknown/malformed event quarantine
- Common event normalization
- SHA-256 raw-event hashing + UUID event/trace IDs
- SQLite event store
- CSV export
- Search/filter dashboard
- Parser registry
- Docker Compose deployment

## Run locally

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs`.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

### Docker

```powershell
docker compose up --build
```

Then open `http://localhost:5173`.

## Demo sequence

1. Open Dashboard.
2. Go to Ingest Logs.
3. Upload `sample_logs/nginx_access.log`.
4. Upload `sample_logs/cisco_asa.log`.
5. Upload `sample_logs/cloudtrail.json`.
6. Upload `sample_logs/syslog.log`.
7. Upload `sample_logs/unknown_custom.log`.
8. Open Events and inspect normalized fields.
9. Click an event to show event ID, trace ID, raw SHA-256 and normalized JSON.
10. Open Quarantine to show unknown events were preserved rather than discarded.
11. Open Parsers to show the plug-in registry.

## Architecture mapping

`routes_upload.py` → ingestion API  
`detector.py` → format/source detection  
`parser_router.py` + `parsers/` → parser plugin routing  
`normalizer.py` → common field normalization  
`validator.py` → schema validation  
`traceability.py` → UUID + SHA-256 traceability  
`enrichment.py` → prototype-safe enrichment  
`quarantine.py` → raw failed-event preservation  
`pipeline.py` → end-to-end processing orchestration  
`event_service.py` → event search/read  
`analytics_service.py` → dashboard metrics  
`frontend/src/` → dashboard UI

## Next build stages

1. Add CEF/LEEF/CSV/XML parser plugins.
2. Add multiline-event handling.
3. Add configurable YAML mapping loader so new sources can be onboarded without changing parser code.
4. Add RFC5424 structured syslog support and stronger timestamp handling.
5. Add optional GeoLite2 enrichment behind a local/offline flag.
6. Add MinIO/OpenSearch adapters without making them mandatory for the offline prototype.
7. Add async/syslog socket receiver.
8. Add benchmark and high-volume batch processing.
9. Add audit logging and role-based access.
10. Add optional AI/ML analytics only after the deterministic preprocessing pipeline is stable.
