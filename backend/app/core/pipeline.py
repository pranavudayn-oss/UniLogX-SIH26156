import json
import uuid
from typing import Optional
from ..database import get_connection
from ..utils.timestamp_utils import now_iso
from .detector import detect_format
from .normalizer import normalize
from .validator import validate_event
from .traceability import build_trace, build_traceability_metadata
from .enrichment import enrich
from .quarantine import quarantine
from ..services.storage_service import store_raw_log


def process_lines(
    lines: list[str],
    source_file: str = "upload",
    ingestion_id: Optional[str] = None,
    ingested_at: Optional[str] = None,
    raw_path: Optional[str] = None,
):
    if not ingestion_id:
        ingestion_id = f"ingest-{uuid.uuid4().hex[:8]}"
    if not ingested_at:
        ingested_at = now_iso()

    # Automatically store raw log into organized storage if not already stored
    if not raw_path and lines:
        try:
            _, rel_path, _ = store_raw_log(
                content="\n".join(lines),
                ingestion_id=ingestion_id,
                filename=source_file or "raw.log",
                timestamp_or_date=ingested_at,
            )
            raw_path = rel_path
        except Exception:
            raw_path = None

    processed = 0
    quarantined = 0
    event_ids = []
    parser_counts = {}

    for line_idx, line in enumerate(lines, start=1):
        raw = line.rstrip("\r\n")
        if not raw.strip():
            continue

        det = detect_format(raw)
        fmt, parser = det

        if parser is None:
            quarantine(
                raw_text=raw,
                reason=f"No matching parser found ({det.reason})",
                source_file=source_file,
                source_type=det.source,
                line_number=line_idx,
                ingestion_id=ingestion_id,
                parser_attempted="none",
                raw_path=raw_path,
            )
            quarantined += 1
            continue

        parser_name = parser.name
        parser_version = getattr(parser, "version", "1.0")
        parser_counts[parser_name] = parser_counts.get(parser_name, 0) + 1

        try:
            parsed = parser.parse_line(raw)
            event_id = f"evt-{uuid.uuid4().hex[:12]}"
            trace_id, raw_hash = build_trace(raw)
            processed_at = now_iso()

            # Normalization
            normalized = normalize(parsed, det.source, parser_name)

            # Forensic traceability metadata (Coexistence of raw and normalized)
            trace_meta = build_traceability_metadata(
                event_id=event_id,
                trace_id=trace_id,
                raw_text=raw,
                raw_hash=raw_hash,
                parser_name=parser_name,
                parser_version=parser_version,
                source_file=source_file,
                line_number=line_idx,
                ingested_at=ingested_at,
                processed_at=processed_at,
                raw_path=raw_path,
            )

            normalized.update(
                event_id=event_id,
                trace_id=trace_id,
                raw_hash=raw_hash,
                raw_event=raw,
                source_file=source_file,
                line_number=line_idx,
                ingested_at=ingested_at,
                processed_at=processed_at,
                parser_version=parser_version,
                raw_path=raw_path,
                ulx=trace_meta["ulx"],
            )

            # Ensure event container in normalized JSON has original and hash
            if "event" in normalized and isinstance(normalized["event"], dict):
                normalized["event"]["id"] = event_id
                normalized["event"]["original"] = raw
                normalized["event"]["hash"] = f"sha256:{raw_hash}"

            # Lightweight offline enrichment
            normalized = enrich(normalized)

            # Validation
            ok, validated, reason = validate_event(normalized)
            if not ok:
                quarantine(
                    raw_text=raw,
                    reason=f"Schema validation failed: {reason}",
                    source_file=source_file,
                    source_type=det.source,
                    line_number=line_idx,
                    ingestion_id=ingestion_id,
                    parser_attempted=parser_name,
                    raw_path=raw_path,
                )
                quarantined += 1
                continue

            data = validated.model_dump()
            with get_connection() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO events(
                        event_id, trace_id, source_type, parser_name, parser_version,
                        timestamp, severity, source_ip, destination_ip, source_port, destination_port,
                        category, transport, action, outcome, message,
                        source_file, line_number, ingested_at, processed_at,
                        normalized_json, raw_json, raw_hash, raw_path, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        data["event_id"],
                        data["trace_id"],
                        data["source_type"],
                        data["parser"],
                        data.get("parser_version", "1.0"),
                        data.get("timestamp"),
                        data.get("severity"),
                        data.get("source_ip"),
                        data.get("destination_ip"),
                        data.get("source_port"),
                        data.get("destination_port"),
                        data.get("category"),
                        data.get("transport"),
                        data.get("action"),
                        data.get("outcome"),
                        data.get("message"),
                        data.get("source_file"),
                        data.get("line_number"),
                        data.get("ingested_at"),
                        data.get("processed_at"),
                        json.dumps(data, default=str),
                        json.dumps(data.get("raw_event"), default=str),
                        data["raw_hash"],
                        raw_path,
                        processed_at,
                    ),
                )
            event_ids.append(event_id)
            processed += 1

        except Exception as exc:
            quarantine(
                raw_text=raw,
                reason=f"Parser error: {type(exc).__name__}: {exc}",
                source_file=source_file,
                source_type=det.source,
                line_number=line_idx,
                ingestion_id=ingestion_id,
                parser_attempted=parser_name,
                raw_path=raw_path,
            )
            quarantined += 1

    return {
        "processed": processed,
        "quarantined": quarantined,
        "event_ids": event_ids,
        "parser_counts": parser_counts,
        "ingestion_id": ingestion_id,
        "raw_path": raw_path,
    }
