
"""
Enhanced UniLogX launcher.

This file is intentionally additive: no existing UniLogX source file is modified.
Start the backend with:
    uvicorn app.enhanced_main:app --reload
or:
    python run_enhanced.py

The original app remains available; this module only extends the runtime parser
registry, detection function, and adds optional prototype admin endpoints.
"""
import shutil
from pathlib import Path
from fastapi import HTTPException
from fastapi.responses import HTMLResponse

from .main import app
from .database import get_connection
from .config import DATA_DIR
from .parsers import PARSERS
from .pipeline_placeholder import install_enhancements

# Register additional parser plugins into the existing in-memory registry.
from .enhanced.parsers import (
    GenericJSONParser, WindowsEventJSONParser, SuricataEVEParser, SnortAlertParser,
    LinuxAuthParser, ApacheErrorParser, DockerJSONParser, MySQLLogParser,
    PostgreSQLLogParser, CSVEventParser, GenericTextParser
)

_NEW_PARSERS = [
    GenericJSONParser(), WindowsEventJSONParser(), SuricataEVEParser(),
    SnortAlertParser(), LinuxAuthParser(), ApacheErrorParser(), DockerJSONParser(),
    MySQLLogParser(), PostgreSQLLogParser(), CSVEventParser(), GenericTextParser()
]
for parser in _NEW_PARSERS:
    if not any(p.name == parser.name for p in PARSERS):
        PARSERS.append(parser)

# Replace only the runtime function reference used by the existing pipeline.
install_enhancements()

@app.post("/api/v1/enhanced/clear-test-data", tags=["prototype-admin"])
def clear_test_data(confirm: bool = False):
    """Clear prototype events/quarantines and generated test raw files.

    This is intentionally separate from the production forensic retention path.
    A confirmation flag is required so it cannot be triggered accidentally.
    """
    if not confirm:
        raise HTTPException(400, "Set confirm=true to clear prototype test data.")

    with get_connection() as conn:
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        quarantines = conn.execute("SELECT COUNT(*) FROM quarantines").fetchone()[0]
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM quarantines")
        conn.execute(
            "INSERT INTO audit_logs(action, details, created_at) VALUES (?, ?, datetime('now'))",
            ("prototype_clear_test_data", f"Cleared {events} events and {quarantines} quarantines"),
        )

    # Remove only generated ingestion/quarantine artifacts, keeping project sample files.
    removed = 0
    for dirname in ("raw_logs", "quarantine", "normalized_logs"):
        base = DATA_DIR / dirname
        if not base.exists():
            continue
        for child in list(base.iterdir()):
            if child.name in {"cloudtrail.json", "requirements.txt"}:
                continue
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
                removed += 1
            except Exception:
                pass

    return {"status":"cleared","events_removed":events,"quarantines_removed":quarantines,
            "storage_items_removed":removed}

@app.get("/api/v1/enhanced/classify", tags=["prototype-admin"])
def classify_log(q: str):
    """Preview how the enhanced detector would route a single log line."""
    from .enhanced.detector import detect_format_enhanced
    d=detect_format_enhanced(q)
    return {**d.to_dict(), "parser": getattr(d.parser,"name",None)}

@app.get("/enhanced", response_class=HTMLResponse, include_in_schema=False)
def enhanced_dashboard():
    return (Path(__file__).resolve().parents[2] / "enhanced_dashboard.html").read_text(encoding="utf-8")
