# UniLogX Enhanced Prototype (Additive Upgrade)

This enhancement is intentionally implemented as **new files only**. Existing UniLogX source files are not modified.

## Added capabilities

- 11 additional parser plugins:
  - Generic JSON
  - Windows Event JSON
  - Suricata EVE JSON
  - Snort alert
  - Linux authentication
  - Apache error
  - Docker JSON
  - MySQL
  - PostgreSQL
  - CSV structured events
  - Generic security text fallback
- Dependency-free Multinomial Naive Bayes classifier for uncertain log-type routing.
- Deterministic parser rules remain first; ML is used only when exact rules do not match.
- Generic fallback reduces unnecessary quarantine for recognizable security/system text.
- Existing parser registry is extended at runtime; existing parsers remain intact.
- `/api/v1/enhanced/classify` previews routing and confidence.
- `/api/v1/enhanced/clear-test-data?confirm=true` clears prototype event/quarantine data and generated test artifacts.
- `/enhanced` provides a small additive control dashboard.

## Start

From `backend`:

```powershell
python run_enhanced.py
```

or:

```powershell
uvicorn app.enhanced_main:app --reload
```

Then:
- Existing frontend: continue using it against this backend.
- Enhanced control page: `http://localhost:8000/enhanced`
- Swagger: `http://localhost:8000/docs`

## Routing strategy

```text
Incoming log
  -> deterministic exact signatures
  -> existing + new parser registry
  -> generic structured parsers
  -> ML classifier for uncertain logs
  -> generic security-text fallback
  -> quarantine only if still unsupported/invalid
```

The ML component is intentionally lightweight and offline so the MVP does not require a cloud AI key or an additional ML package.
