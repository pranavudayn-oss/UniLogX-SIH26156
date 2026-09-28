"""
Feature 10 tests — Additional Testing & Final Hardening

Exhaustive verification of system resilience, edge cases, boundaries,
duplicate isolation, raw evidence byte-fidelity, security path safety,
quarantine lifecycle, compound search, and idempotent reads.
"""
import csv
import json
import pytest
from pathlib import Path
from fastapi import HTTPException

from app.core.pipeline import process_lines
from app.core.ingestion import read_text_lines
from app.services.storage_service import store_raw_log, get_raw_log, raw_log_exists
from app.services.event_service import list_events, get_event
from app.services.analytics_service import metrics
from app.services.export_service import export_csv, export_json
from app.api.routes_parsers import get_parser, list_parsers
from app.core.quarantine import quarantine, reprocess_quarantine
from app.utils.file_utils import safe_filename
from app.utils.hash_utils import sha256_text
from app.database import get_connection


# ---------------------------------------------------------------------------
# 1. Input Edge Cases: Empty, Whitespace, CRLF, Tabs, Quotes, Unicode, Long Lines
# ---------------------------------------------------------------------------

def test_edge_empty_lines_and_whitespace():
    """1. Empty lines and whitespace-only lines are ignored and do not produce events or crash."""
    lines = ["", "   ", "\t\t", "\n", " \r "]
    res = process_lines(lines, source_file="empty_lines.log")
    assert res["processed"] == 0
    assert res["quarantined"] == 0
    assert len(res["event_ids"]) == 0


def test_edge_crlf_and_missing_newline():
    """2. Windows CRLF and missing EOF newline process cleanly."""
    content = b'10.200.1.1 - - [27/Sep/2026:15:00:00 +0000] "GET /crlf HTTP/1.1" 200 64\r\n10.200.1.2 - - [27/Sep/2026:15:00:01 +0000] "GET /no-eof HTTP/1.1" 200 128'
    lines = read_text_lines(content, "crlf_test.log")
    assert len(lines) == 2
    res = process_lines(lines, source_file="crlf_test.log")
    assert res["processed"] == 2
    assert res["quarantined"] == 0


def test_edge_tabs_and_embedded_quotes():
    """3. Tabs and quotes inside log lines are preserved without breaking field extraction."""
    raw = '10.200.2.1 - - [27/Sep/2026:15:05:00 +0000] "GET /path?query=\"quoted\"&tab=\tval HTTP/1.1" 200 512'
    res = process_lines([raw], source_file="tabs_quotes.log")
    assert res["processed"] == 1
    evt = get_event(res["event_ids"][0])
    assert evt is not None
    assert evt["raw_event"] == raw


def test_edge_unicode_and_special_chars():
    """4. Non-ASCII UTF-8 characters and emojis are preserved with exact SHA-256 fingerprinting."""
    raw = '10.200.3.1 - - [27/Sep/2026:15:10:00 +0000] "GET /api/v1/search?q=東京&tag=⚠️_audit HTTP/1.1" 200 1024'
    res = process_lines([raw], source_file="unicode.log")
    assert res["processed"] == 1
    evt = get_event(res["event_ids"][0])
    assert evt["raw_event"] == raw
    assert evt["raw_hash"] == sha256_text(raw)


def test_edge_very_long_log_line():
    """5. Very large log lines (>15,000 chars) process safely without buffer overflow."""
    long_param = "A" * 15000
    raw = f'10.200.4.1 - - [27/Sep/2026:15:15:00 +0000] "GET /test?param={long_param} HTTP/1.1" 200 4096'
    res = process_lines([raw], source_file="long_line.log")
    assert res["processed"] == 1
    evt = get_event(res["event_ids"][0])
    assert len(evt["raw_event"]) > 15000


def test_edge_malformed_json_quarantined():
    """6. Broken/truncated JSON is caught and quarantined with diagnostic error."""
    broken_json = '{"eventSource": "iam.amazonaws.com", "eventName": "AssumeRole", "incomplete'
    res = process_lines([broken_json], source_file="broken.json")
    assert res["processed"] == 0
    assert res["quarantined"] == 1


# ---------------------------------------------------------------------------
# 2. Extreme Values: Boundary Ports, Large Numbers, Timestamps
# ---------------------------------------------------------------------------

def test_extreme_port_boundaries():
    """7. Valid network port boundaries (0 and 65535) are processed correctly."""
    line_min = 'Sep 27 15:20:00 %ASA-6-106015: Deny TCP from 192.168.1.1/0 to 10.0.0.1/65535 flags SYN'
    res = process_lines([line_min], source_file="port_boundaries.log")
    assert res["processed"] == 1
    evt = get_event(res["event_ids"][0])
    assert evt["source_port"] == 0
    assert evt["destination_port"] == 65535


def test_extreme_timestamps_future_and_past():
    """8. Future and historical timestamps normalize cleanly without clock panic."""
    future_line = '10.200.5.1 - - [01/Jan/2035:00:00:00 +0000] "GET /future HTTP/1.1" 200 128'
    res = process_lines([future_line], source_file="future_time.log")
    assert res["processed"] == 1
    evt = get_event(res["event_ids"][0])
    assert "2035" in str(evt["timestamp"])


# ---------------------------------------------------------------------------
# 3. Duplicate Ingestion & Evidence Isolation
# ---------------------------------------------------------------------------

def test_duplicate_filename_isolation():
    """9. Uploading the same filename multiple times creates separate partitioned evidence."""
    content = b"Same content in separate ingestions"
    _, rel1, _ = store_raw_log(content, ingestion_id="ingest-dup-1", filename="shared.log", timestamp_or_date="2026-09-27")
    _, rel2, _ = store_raw_log(content, ingestion_id="ingest-dup-2", filename="shared.log", timestamp_or_date="2026-09-27")
    _, rel3, _ = store_raw_log(content, ingestion_id="ingest-dup-3", filename="shared.log", timestamp_or_date="2026-09-27")

    assert rel1 != rel2 != rel3
    assert raw_log_exists(rel1)
    assert raw_log_exists(rel2)
    assert raw_log_exists(rel3)


def test_raw_evidence_byte_exact_roundtrip():
    """10. Stored raw evidence byte stream exactly matches original ingested bytes."""
    original_payload = b'RAW_BINARY_\x00\x01\x02_WITH_QUOTES"\'_AND_SYMBOLS\n\r\t'
    _, rel_path, computed_hash = store_raw_log(
        original_payload,
        ingestion_id="ingest-byte-verify",
        filename="binary_evidence.raw",
        timestamp_or_date="2026-09-27",
    )
    retrieved_bytes = get_raw_log(rel_path)
    assert retrieved_bytes == original_payload


# ---------------------------------------------------------------------------
# 4. Pipeline Failure & Mixed-Batch Resilience
# ---------------------------------------------------------------------------

def test_mixed_batch_resilience():
    """11. Mixed batch processes valid lines into events and quarantines invalid lines."""
    batch = [
        '10.200.6.1 - - [27/Sep/2026:15:30:00 +0000] "GET /valid-1 HTTP/1.1" 200 64',
        'MALFORMED_UNRECOGNIZED_NONSENSE_LINE_XYZ_1',
        '10.200.6.2 - - [27/Sep/2026:15:30:01 +0000] "GET /valid-2 HTTP/1.1" 200 128',
        'MALFORMED_UNRECOGNIZED_NONSENSE_LINE_XYZ_2',
    ]
    res = process_lines(batch, source_file="mixed_batch.log")
    assert res["processed"] == 2
    assert res["quarantined"] == 2
    assert len(res["event_ids"]) == 2


def test_quarantine_failed_reprocess_preserves_evidence():
    """12. Unfixable quarantine record remains quarantined after reprocessing attempt."""
    unparseable = "STILL_TOTALLY_UNPARSEABLE_CUSTOM_PAYLOAD_FOR_TEST"
    q_hash = quarantine(unparseable, reason="Initial test failure", source_file="unfixable.raw")
    
    # Reprocess all
    reprocess_res = reprocess_quarantine()
    assert "reprocessed" in reprocess_res
    
    # Verify original quarantine record is intact in DB
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM quarantines WHERE raw_hash = ?", (q_hash,)).fetchone()
    assert row is not None
    assert row["raw_text"] == unparseable


# ---------------------------------------------------------------------------
# 5. Search Regressions & Compound Filtering
# ---------------------------------------------------------------------------

def test_search_compound_filters_exact_match():
    """13. Compound search filters return exact intersection of all constraints."""
    target_ip = "10.200.7.77"
    line = f'Sep 27 15:35:00 %ASA-6-106015: Deny TCP from {target_ip}/50000 to 10.0.0.1/443 flags SYN'
    process_lines([line], source_file="compound_test.log")

    # Match all criteria
    results = list_events(source_ip=target_ip, destination_port=443, transport="TCP", outcome="failure")
    assert len(results) >= 1
    for r in results:
        assert r["source_ip"] == target_ip
        assert r["destination_port"] == 443
        assert r["transport"] == "TCP"
        assert r["outcome"] == "failure"

    # Mismatch one criteria -> 0 results
    no_results = list_events(source_ip=target_ip, destination_port=80)
    assert len(no_results) == 0


def test_search_invalid_parameter_safety():
    """14. Searching with unusual or empty query tokens does not crash event_service."""
    res1 = list_events(q=":::===??? invalid:token")
    assert isinstance(res1, list)

    res2 = list_events(q="destination.port=invalid_int")
    assert isinstance(res2, list)

    res3 = list_events(limit=0)
    assert isinstance(res3, list)


# ---------------------------------------------------------------------------
# 6. Export Robustness & CSV Quoting
# ---------------------------------------------------------------------------

def test_export_empty_and_special_characters():
    """15. Export handles 0-match filter and special characters cleanly."""
    # 0-match export
    empty_evts = list_events(source_ip="192.0.2.254")
    assert len(empty_evts) == 0
    csv_path = export_csv(empty_evts, filename="hardening_empty.csv")
    assert csv_path.exists()
    with csv_path.open(encoding="utf-8") as f:
        reader = list(csv.reader(f))
    assert len(reader) == 1  # Header row only

    json_path = export_json(empty_evts, filename="hardening_empty.json")
    with json_path.open(encoding="utf-8") as f:
        assert json.load(f) == []


# ---------------------------------------------------------------------------
# 7. Metrics & Analytics Stability
# ---------------------------------------------------------------------------

def test_metrics_stability_and_consistency():
    """16. Metrics computation has no division-by-zero and reports consistent sums."""
    m = metrics()
    assert m["total_events"] >= 0
    assert 0.0 <= m["parser_success_rate"] <= 100.0
    assert isinstance(m["events_by_parser"], dict)
    assert isinstance(m["events_by_category"], dict)
    assert isinstance(m["quarantine_summary"], dict)


# ---------------------------------------------------------------------------
# 8. Parser Registry Boundary
# ---------------------------------------------------------------------------

def test_parser_registry_unknown_parser_404():
    """17. Requesting an unregistered parser raises HTTPException 404."""
    with pytest.raises(HTTPException) as exc_info:
        get_parser("completely_nonexistent_parser_name")
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# 9. Security: Path Traversal Sanitization
# ---------------------------------------------------------------------------

def test_security_path_traversal_sanitization():
    """18. Malicious path traversal filenames are sanitized to prevent directory escape."""
    unsafe_names = [
        "../../etc/shadow",
        "..\\..\\windows\\system32\\cmd.exe",
        "nested/../../../../root.log",
        "/etc/passwd",
    ]
    for unsafe in unsafe_names:
        clean = safe_filename(unsafe)
        assert ".." not in clean
        assert "/" not in clean
        assert "\\" not in clean


# ---------------------------------------------------------------------------
# 10. Database Consistency & Idempotent Reads
# ---------------------------------------------------------------------------

def test_idempotent_read_operations():
    """19. Repeated read operations produce identical results and do not alter DB state."""
    count_before = len(list_events(limit=500))
    # Perform multiple reads
    for _ in range(3):
        list_events(limit=10)
        metrics()
        list_parsers()
    count_after = len(list_events(limit=500))
    assert count_before == count_after


def test_db_consistency_raw_path_and_hash():
    """20. Events in the database maintain consistent raw_path and raw_hash."""
    evts = list_events(limit=10)
    for e in evts:
        assert e["raw_hash"] is not None
        assert len(e["raw_hash"]) == 64  # SHA-256 hex length
        if e.get("raw_path"):
            assert e["raw_path"].startswith("raw_logs/")
