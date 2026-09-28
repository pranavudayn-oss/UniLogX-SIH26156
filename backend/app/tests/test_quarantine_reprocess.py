"""
Feature 3 tests — Quarantine Detail & Reprocessing

Tests that:
1. Quarantined records can be listed via API / service.
2. Quarantine details can be retrieved by ID via GET /quarantine/{quarantine_id}.
3. Quarantine detail contains the exact untouched original raw log.
4. Quarantine detail contains diagnostic reason and status.
5. Invalid quarantine ID returns 404 on both detail and reprocess endpoints.
6. An unparseable unknown log remains quarantined when reprocessed, preserving raw evidence.
7. A quarantined log for which a parser exists can be successfully reprocessed.
8. Successful reprocessing creates a normalized event in the Events store.
9. Original raw evidence remains untouched in quarantine audit storage after reprocessing.
10. Feature 1 unified search continues to function without regressions.
11. Feature 2 event details retrieval continues to function without regressions.
"""
import pytest
from fastapi import HTTPException
from app.core.pipeline import process_lines
from app.core.quarantine import quarantine, reprocess_quarantine
from app.api.routes_quarantine import (
    quarantines as list_quarantines_route,
    quarantine_detail as quarantine_detail_route,
    reprocess_one as reprocess_one_route,
    reprocess_all as reprocess_all_route,
)
from app.services.event_service import list_events, get_event
from app.database import get_connection

UNKNOWN_LOG_LINE = "UNKNOWN_PROTOCOL v99.0 INVALID_HEADER_CANNOT_PARSE [CORRUPTED_PAYLOAD]"
VALID_CISCO_LOG = "Sep 26 13:00:00 %ASA-6-302013: Built inbound TCP connection 9988 for inside:10.50.1.1/60000 to outside:1.1.1.1/443"


@pytest.fixture(scope="module")
def quarantined_unknown_id():
    """Seed an unparseable log into quarantine and return its ID."""
    process_lines([UNKNOWN_LOG_LINE], source_file="unknown_test.log")
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM quarantines WHERE raw_text = ? ORDER BY id DESC LIMIT 1",
            (UNKNOWN_LOG_LINE,),
        ).fetchone()
    assert row is not None
    return row["id"]


@pytest.fixture(scope="module")
def quarantined_reprocessable_id():
    """
    Manually insert a valid log into quarantine with status='quarantined'
    (simulating a log that arrived before its parser was registered).
    """
    raw_hash = quarantine(
        raw_text=VALID_CISCO_LOG,
        reason="Parser not registered at ingestion time",
        source_file="deferred_cisco.log",
        source_type="firewall",
        line_number=42,
        ingestion_id="ingest-defer-01",
        parser_attempted="none",
    )
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM quarantines WHERE raw_hash = ? AND status = 'quarantined' ORDER BY id DESC LIMIT 1",
            (raw_hash,),
        ).fetchone()
    assert row is not None
    return row["id"]


def test_list_quarantine_records(quarantined_unknown_id):
    """1. List quarantined records returns a non-empty list containing our record."""
    records = list_quarantines_route(limit=100)
    assert isinstance(records, list)
    assert len(records) >= 1
    assert any(r["id"] == quarantined_unknown_id for r in records)


def test_fetch_quarantine_detail(quarantined_unknown_id):
    """2. Fetch quarantine detail by ID via GET /quarantine/{id}."""
    detail = quarantine_detail_route(quarantined_unknown_id)
    assert detail is not None
    assert detail["id"] == quarantined_unknown_id


def test_detail_contains_original_raw_log(quarantined_unknown_id):
    """3. Quarantine detail exposes the exact, untouched raw log evidence."""
    detail = quarantine_detail_route(quarantined_unknown_id)
    assert detail["raw_text"] == UNKNOWN_LOG_LINE
    assert detail["raw_hash"] is not None and len(detail["raw_hash"]) == 64


def test_detail_contains_reason_and_status(quarantined_unknown_id):
    """4. Quarantine detail contains diagnostic error reason and status."""
    detail = quarantine_detail_route(quarantined_unknown_id)
    assert detail["status"] == "quarantined"
    assert "reason" in detail and len(detail["reason"]) > 0
    assert detail["source_file"] == "unknown_test.log"


def test_invalid_quarantine_id_returns_404():
    """9. Nonexistent quarantine ID raises 404 HTTPException on detail and reprocess routes."""
    with pytest.raises(HTTPException) as exc_detail:
        quarantine_detail_route(99999999)
    assert exc_detail.value.status_code == 404

    with pytest.raises(HTTPException) as exc_reprocess:
        reprocess_one_route(99999999)
    assert exc_reprocess.value.status_code == 404


def test_failed_unknown_reprocessing_remains_quarantined(quarantined_unknown_id):
    """7 & 8. Reprocessing an unknown log fails, leaves status as 'quarantined', and leaves raw evidence untouched."""
    res = reprocess_one_route(quarantined_unknown_id)
    assert res["reprocessed"] == 0
    assert res["failed"] == 1

    # Verify status is still 'quarantined'
    detail = quarantine_detail_route(quarantined_unknown_id)
    assert detail["status"] == "quarantined"
    # Verify raw text is unchanged
    assert detail["raw_text"] == UNKNOWN_LOG_LINE


def test_reprocess_quarantine_record_successfully(quarantined_reprocessable_id):
    """5. Reprocess a quarantined record for which a parser exists."""
    res = reprocess_one_route(quarantined_reprocessable_id)
    assert res["reprocessed"] == 1
    assert res["failed"] == 0
    assert quarantined_reprocessable_id in res["reprocessed_ids"]

    # Verify status in database is now 'reprocessed'
    detail = quarantine_detail_route(quarantined_reprocessable_id)
    assert detail["status"] == "reprocessed"


def test_successful_reprocessing_creates_normalized_event(quarantined_reprocessable_id):
    """6. Successful reprocessing creates a normalized event in Events store."""
    events = list_events(source_ip="10.50.1.1", destination_port=443, limit=10)
    assert len(events) >= 1
    evt = events[0]
    assert evt["parser_name"] == "cisco_asa"
    assert evt["source_ip"] == "10.50.1.1"
    assert evt["destination_ip"] == "1.1.1.1"
    assert evt["destination_port"] == 443
    assert evt["action"] == "allowed"
    assert evt["outcome"] == "success"


def test_original_raw_evidence_remains_unchanged(quarantined_reprocessable_id):
    """8. Original quarantine evidence and raw hash remain intact after successful reprocessing."""
    detail = quarantine_detail_route(quarantined_reprocessable_id)
    assert detail["raw_text"] == VALID_CISCO_LOG
    assert detail["status"] == "reprocessed"


def test_reprocess_all_route():
    """Bulk reprocessing endpoint POST /quarantine/reprocess works cleanly."""
    res = reprocess_all_route()
    assert "reprocessed" in res
    assert "failed" in res
    assert "total_attempted" in res


def test_feature1_search_still_works():
    """10. Feature 1 advanced search continues to function."""
    res = list_events(q="source.ip=10.50.1.1 destination.port=443", limit=5)
    assert len(res) >= 1
    assert res[0]["source_ip"] == "10.50.1.1"


def test_feature2_event_details_still_works():
    """11. Feature 2 event details retrieval continues to function."""
    res = list_events(source_ip="10.50.1.1", limit=1)
    assert len(res) >= 1
    evt_id = res[0]["event_id"]
    detail = get_event(evt_id)
    assert detail is not None
    assert detail["event_id"] == evt_id
    assert detail["raw_event"] == VALID_CISCO_LOG
