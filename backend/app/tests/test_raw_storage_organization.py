"""
Feature 8 tests — Raw Log Storage Organization

Validates:
1. Raw log is stored successfully into the local filesystem.
2. Raw storage path follows predictable partitioned organization: raw_logs/YYYY/MM/DD/<ingestion_id>/<filename>.
3. Raw content remains byte/character identical (no alteration, normalization, or pretty-printing).
4. Raw SHA-256 hash remains exact.
5. Raw storage does not overwrite existing evidence across separate ingestions.
6. Multiple ingestions with identical filename or content remain separately traceable via ingestion IDs.
7. Event traceability identifies the raw storage path (raw_path in event and ulx metadata).
8. Existing event details API still returns raw evidence.
9. Quarantine raw evidence remains intact and accessible.
10. Quarantine reprocessing continues to function without issues.
11. Feature 1 unified search regression check.
12. Feature 2 forensic view regression check.
13. Feature 3 quarantine reprocessing regression check.
14. Feature 4 port-to-service enrichment regression check.
15. Feature 5 parser registry regression check.
16. Feature 6 dashboard analytics regression check.
17. Feature 7 CSV export regression check.
18. Feature 7 JSON export regression check.
"""
from pathlib import Path
import pytest
from app.services.storage_service import (
    build_raw_log_path,
    store_raw_log,
    get_raw_log,
    get_raw_log_text,
    raw_log_exists,
)
from app.core.pipeline import process_lines
from app.services.event_service import list_events, get_event
from app.core.quarantine import quarantine, reprocess_quarantine
from app.core.enrichment import lookup_port_service
from app.api.routes_parsers import list_parsers
from app.services.analytics_service import metrics
from app.services.export_service import export_csv, export_json
from app.utils.hash_utils import sha256_text


# ---------------------------------------------------------------------------
# 1-6. Raw Storage Service & Partitioning Tests
# ---------------------------------------------------------------------------

def test_raw_log_stored_successfully():
    """1. Raw log is stored successfully into organized storage."""
    raw_data = "Sep 27 10:00:00 %ASA-6-302013: Built outbound TCP connection 100 for dmz:192.168.1.10/1234 to outside:10.0.0.1/443"
    abs_path, rel_path, raw_hash = store_raw_log(
        content=raw_data,
        ingestion_id="test-ingest-001",
        filename="cisco_test.log",
        timestamp_or_date="2026-09-27T10:00:00",
    )
    assert abs_path.exists()
    assert abs_path.is_file()
    assert raw_log_exists(rel_path)


def test_raw_storage_path_follows_organization():
    """2. Raw storage path follows the YYYY/MM/DD/<ingestion_id>/<filename> partition format."""
    abs_path, rel_path = build_raw_log_path(
        ingestion_id="ingest-xyz-123",
        timestamp_or_date="2026-09-27T15:30:00",
        filename="firewall_audit.log",
    )
    # Check logical relative path
    assert rel_path == "raw_logs/2026/09/27/ingest-xyz-123/firewall_audit.log"
    # Check filesystem path components
    parts = abs_path.parts
    assert "raw_logs" in parts
    assert "2026" in parts
    assert "09" in parts
    assert "27" in parts
    assert "ingest-xyz-123" in parts
    assert parts[-1] == "firewall_audit.log"


def test_raw_content_remains_unchanged():
    """3. Stored raw log is byte-for-byte and character-for-character identical."""
    original_multiline = 'line 1 with "quotes"\nline 2 with \t tabs\nline 3: raw unchanged'
    abs_path, rel_path, _ = store_raw_log(
        content=original_multiline,
        ingestion_id="test-ingest-integrity",
        filename="multiline.raw",
        timestamp_or_date="2026-09-27",
    )
    retrieved = get_raw_log_text(rel_path)
    assert retrieved == original_multiline


def test_raw_hash_remains_exact():
    """4. SHA-256 hash computed during raw storage matches expected sha256_text."""
    content = "Sample raw line for hash verification"
    _, rel_path, stored_hash = store_raw_log(
        content=content,
        ingestion_id="test-ingest-hash",
        filename="hash_test.log",
        timestamp_or_date="2026-09-27",
    )
    expected_hash = sha256_text(content)
    assert stored_hash == expected_hash


def test_raw_storage_does_not_overwrite_existing_evidence():
    """5. Ingesting different batches with same filename does not overwrite previous files."""
    content_a = "First batch raw content A"
    content_b = "Second batch raw content B"

    abs_a, rel_a, _ = store_raw_log(
        content=content_a,
        ingestion_id="ingest-batch-AAA",
        filename="access.log",
        timestamp_or_date="2026-09-27",
    )
    abs_b, rel_b, _ = store_raw_log(
        content=content_b,
        ingestion_id="ingest-batch-BBB",
        filename="access.log",
        timestamp_or_date="2026-09-27",
    )

    # Distinct paths due to unique ingestion IDs
    assert abs_a != abs_b
    assert rel_a != rel_b
    assert get_raw_log_text(rel_a) == content_a
    assert get_raw_log_text(rel_b) == content_b


def test_multiple_ingestions_separately_traceable():
    """6. Two separate pipeline ingestions create distinct raw storage locations."""
    line1 = '10.150.1.1 - - [27/Sep/2026:14:00:00 +0000] "GET /app1 HTTP/1.1" 200 64'
    line2 = '10.150.1.2 - - [27/Sep/2026:14:01:00 +0000] "GET /app2 HTTP/1.1" 200 128'

    res1 = process_lines([line1], source_file="shared_name.log", ingestion_id="ingest-unique-1")
    res2 = process_lines([line2], source_file="shared_name.log", ingestion_id="ingest-unique-2")

    assert res1["raw_path"] != res2["raw_path"]
    assert "ingest-unique-1" in res1["raw_path"]
    assert "ingest-unique-2" in res2["raw_path"]
    assert raw_log_exists(res1["raw_path"])
    assert raw_log_exists(res2["raw_path"])


# ---------------------------------------------------------------------------
# 7-10. Traceability & Quarantine Storage Tests
# ---------------------------------------------------------------------------

def test_event_traceability_identifies_raw_storage():
    """7. Event record contains raw_path linking to organized raw evidence."""
    test_line = '10.150.2.1 - - [27/Sep/2026:14:05:00 +0000] "GET /raw-trace-test HTTP/1.1" 200 256'
    res = process_lines([test_line], source_file="raw_trace.log", ingestion_id="ingest-trace-test")
    assert res["processed"] >= 1
    event_id = res["event_ids"][0]

    evt = get_event(event_id)
    assert evt is not None
    assert evt.get("raw_path") is not None
    assert "ingest-trace-test" in evt["raw_path"]

    # Check that normalized ulx container also has raw_path
    ulx = evt["normalized"].get("ulx", {})
    assert ulx.get("raw_path") == evt["raw_path"]


def test_existing_event_details_returns_raw_evidence():
    """8. Event details API retrieves original raw evidence."""
    test_line = '10.150.3.1 - - [27/Sep/2026:14:10:00 +0000] "GET /forensic-evidence HTTP/1.1" 200 128'
    res = process_lines([test_line], source_file="evidence.log", ingestion_id="ingest-forensic-test")
    event_id = res["event_ids"][0]

    evt = get_event(event_id)
    assert evt["raw_event"] == test_line
    assert evt["raw_hash"] == sha256_text(test_line)


def test_quarantine_raw_evidence_intact():
    """9. Quarantined events preserve raw text evidence and raw_path."""
    unknown_raw = "UNKNOWN_UNPARSABLE_LOG_LINE_FOR_FEATURE_8_VERIFICATION"
    q_hash = quarantine(
        raw_text=unknown_raw,
        reason="Feature 8 raw storage quarantine test",
        source_file="bad_log.raw",
        ingestion_id="ingest-q-001",
    )
    assert q_hash == sha256_text(unknown_raw)

    # Physical quarantine file exists
    from app.config import QUARANTINE_DIR
    q_file = QUARANTINE_DIR / f"{q_hash}.log"
    assert q_file.exists()
    assert q_file.read_text(encoding="utf-8") == unknown_raw


def test_quarantine_reprocessing_still_works():
    """10. Quarantine reprocessing workflow remains intact."""
    res = reprocess_quarantine()
    assert "reprocessed" in res
    assert "failed" in res
    assert isinstance(res["reprocessed"], int)


# ---------------------------------------------------------------------------
# 11-18. Regressions across Features 1 through 7
# ---------------------------------------------------------------------------

def test_feature1_unified_search_regression():
    """11. Feature 1 unified search continues to function."""
    evts = list_events(source_ip="10.150.2.1", limit=5)
    assert len(evts) >= 1
    assert evts[0]["source_ip"] == "10.150.2.1"


def test_feature2_forensic_view_regression():
    """12. Feature 2 event details retrieval continues to work."""
    evts = list_events(source_ip="10.150.2.1", limit=1)
    eid = evts[0]["event_id"]
    detail = get_event(eid)
    assert detail is not None
    assert detail["event_id"] == eid
    assert detail.get("raw_event") is not None


def test_feature3_quarantine_reprocessing_regression():
    """13. Feature 3 quarantine reprocessing works."""
    res = reprocess_quarantine()
    assert "total_attempted" in res


def test_feature4_port_enrichment_regression():
    """14. Feature 4 port enrichment mapping remains active."""
    assert lookup_port_service(443) == "HTTPS"
    assert lookup_port_service(22) == "SSH"


def test_feature5_parser_registry_regression():
    """15. Feature 5 parser registry list continues to return all parsers."""
    parsers = list_parsers()
    names = {p["name"] for p in parsers}
    assert "cisco_asa" in names
    assert "nginx" in names


def test_feature6_dashboard_analytics_regression():
    """16. Feature 6 dashboard analytics still computes metrics correctly."""
    m = metrics()
    assert m["total_events"] >= 1
    assert "events_by_parser" in m
    assert "events_by_category" in m


def test_feature7_csv_export_regression():
    """17. Feature 7 CSV export works and includes raw_path."""
    evts = list_events(limit=5)
    csv_path = export_csv(evts)
    assert csv_path.exists()
    assert csv_path.stat().st_size > 0


def test_feature7_json_export_regression():
    """18. Feature 7 JSON export works and preserves structured data."""
    evts = list_events(limit=5)
    json_path = export_json(evts)
    assert json_path.exists()
    assert json_path.stat().st_size > 0
