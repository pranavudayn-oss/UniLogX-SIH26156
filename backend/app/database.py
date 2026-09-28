import sqlite3
from contextlib import contextmanager
from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    parser_name TEXT NOT NULL,
    parser_version TEXT DEFAULT '1.0',
    timestamp TEXT,
    severity TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    category TEXT,
    transport TEXT,
    action TEXT,
    outcome TEXT,
    message TEXT,
    source_file TEXT,
    line_number INTEGER,
    ingested_at TEXT,
    processed_at TEXT,
    normalized_json TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    raw_hash TEXT NOT NULL,
    raw_path TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_destination_ip ON events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_events_trace_id ON events(trace_id);
CREATE TABLE IF NOT EXISTS quarantines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ingestion_id TEXT,
    source_file TEXT,
    source_type TEXT,
    line_number INTEGER,
    parser_attempted TEXT,
    status TEXT DEFAULT 'quarantined',
    reason TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    raw_hash TEXT NOT NULL,
    raw_path TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL
);
"""

@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        # Safe migration for existing DB
        cols_events = {r["name"] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
        new_cols_events = [
            ("parser_version", "TEXT DEFAULT '1.0'"),
            ("category", "TEXT"),
            ("transport", "TEXT"),
            ("source_file", "TEXT"),
            ("line_number", "INTEGER"),
            ("ingested_at", "TEXT"),
            ("processed_at", "TEXT"),
            ("raw_path", "TEXT"),
        ]
        for col, col_type in new_cols_events:
            if col not in cols_events:
                try:
                    conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")
                except Exception:
                    pass

        cols_quarantines = {r["name"] for r in conn.execute("PRAGMA table_info(quarantines)").fetchall()}
        new_cols_quarantines = [
            ("ingestion_id", "TEXT"),
            ("line_number", "INTEGER"),
            ("parser_attempted", "TEXT"),
            ("status", "TEXT DEFAULT 'quarantined'"),
            ("raw_path", "TEXT"),
        ]
        for col, col_type in new_cols_quarantines:
            if col not in cols_quarantines:
                try:
                    conn.execute(f"ALTER TABLE quarantines ADD COLUMN {col} {col_type}")
                except Exception:
                    pass
