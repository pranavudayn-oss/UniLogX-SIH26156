import csv
import io
import json
from pathlib import Path
from ..config import EXPORT_DIR

# Stable column order for CSV.  "normalized" is kept as JSON text so complex nested
# structures don't explode into hundreds of optional columns (MVP-appropriate).
CSV_FIELDS = [
    # Traceability / provenance
    "event_id",
    "trace_id",
    "raw_hash",
    "raw_path",
    "ingested_at",
    "processed_at",
    # Normalised identity
    "timestamp",
    "parser_name",
    "parser_version",
    "source_type",
    "source_file",
    "line_number",
    # Key network / security fields (flat columns for analyst convenience)
    "category",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "transport",
    "action",
    "outcome",
    "severity",
    "message",
    # Full normalised payload as JSON text (preserves all fields without column explosion)
    "normalized_json",
    # Original untouched raw log line
    "raw_event",
]


def _safe_str(value) -> str:
    """Convert any value to a CSV-safe string. Dicts/lists serialise as JSON text."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return str(value)


def _build_csv_row(event: dict) -> dict:
    """
    Build a flat row from a full event dict (DB columns + normalized + raw_event).
    Prefer DB-level flat columns; fall back to normalized dict for any missing values.
    """
    norm = event.get("normalized") or {}
    row = {}
    for field in CSV_FIELDS:
        if field == "normalized_json":
            # Serialise the full normalised payload as a JSON string column
            row[field] = _safe_str(norm if norm else event.get("normalized_json", ""))
        elif field == "raw_event":
            row[field] = _safe_str(event.get("raw_event") or norm.get("raw_event", ""))
        elif field in event and event[field] is not None:
            row[field] = _safe_str(event[field])
        else:
            # Fallback into the normalized sub-dict
            row[field] = _safe_str(norm.get(field, ""))
    return row


def export_csv(events: list, filename: str = "events.csv") -> Path:
    """
    Export a list of full event dicts to CSV.
    Each event should be a dict containing DB columns, a 'normalized' sub-dict, and 'raw_event'.
    All values are safely stringified; commas/quotes/newlines are handled by Python's csv module.
    Returns the Path of the written file.
    """
    path = EXPORT_DIR / filename
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for event in events:
            writer.writerow(_build_csv_row(event))
    return path


def export_json(events: list, filename: str = "events.json") -> Path:
    """
    Export a list of full event dicts to JSON.
    Each object preserves event_id, trace_id, timestamp, parser identity,
    traceability metadata, structured normalised data, and the original raw event.
    Returns the Path of the written file.
    """
    path = EXPORT_DIR / filename
    output = []
    for event in events:
        norm = event.get("normalized") or {}
        record = {
            # Identity
            "event_id": event.get("event_id"),
            "trace_id": event.get("trace_id"),
            # Timestamps / provenance
            "timestamp": event.get("timestamp") or norm.get("timestamp"),
            "ingested_at": event.get("ingested_at"),
            "processed_at": event.get("processed_at"),
            # Parser metadata
            "parser": event.get("parser_name") or norm.get("parser_name"),
            "parser_version": event.get("parser_version") or norm.get("parser_version"),
            # Source metadata
            "source_type": event.get("source_type"),
            "source_file": event.get("source_file"),
            "line_number": event.get("line_number"),
            # Integrity & Raw Storage
            "raw_hash": event.get("raw_hash"),
            "raw_path": event.get("raw_path"),
            # Full structured normalised payload
            "normalized": norm,
            # Original untouched raw log
            "raw_event": event.get("raw_event") or norm.get("raw_event", ""),
        }
        output.append(record)
    with path.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    return path
