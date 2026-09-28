"""
Feature 2 tests — Event Details / Forensic View

Tests that:
- An existing event can be retrieved by its ID via service and API route.
- The returned event contains its event ID, trace ID, and timestamp.
- The returned event contains structured normalized data (normalized JSON / dict).
- The returned event contains the exact, untouched original raw log (raw_event).
- The returned event contains full provenance & traceability metadata (source_file, line_number, ingested_at, processed_at, raw_hash).
- Attempting to retrieve a nonexistent event raises HTTP 404 (HTTPException).
- Unified search from Feature 1 continues to function correctly.
"""
import pytest
from fastapi import HTTPException
from app.core.pipeline import process_lines
from app.services.event_service import get_event, list_events
from app.api.routes_events import event as get_event_route

TEST_RAW_LOG = '192.168.1.99 - - [26/Sep/2026:12:00:00 +0000] "GET /api/v1/forensics HTTP/1.1" 200 4096'


@pytest.fixture(scope="module")
def seeded_event_id():
    """Ingest a single deterministic log and return its event_id."""
    res = process_lines([TEST_RAW_LOG], source_file="test_forensics.log")
    assert res["processed"] == 1
    assert len(res["event_ids"]) == 1
    return res["event_ids"][0]


def test_fetch_existing_event_by_id(seeded_event_id):
    """Test retrieving an existing event by ID returns a valid event dict."""
    evt = get_event(seeded_event_id)
    assert evt is not None
    assert evt["event_id"] == seeded_event_id


def test_returned_event_contains_identity(seeded_event_id):
    """Event identity must include event_id, trace_id, and timestamp."""
    evt = get_event(seeded_event_id)
    assert evt["event_id"] == seeded_event_id
    assert evt["trace_id"] is not None and len(evt["trace_id"]) > 0
    assert evt["timestamp"] is not None


def test_returned_event_contains_normalized_data(seeded_event_id):
    """Event must contain the structured normalized dict with ECS-compatible fields."""
    evt = get_event(seeded_event_id)
    assert "normalized" in evt
    norm = evt["normalized"]
    assert isinstance(norm, dict)
    assert norm.get("source_ip") == "192.168.1.99"
    assert norm.get("outcome") == "success"
    assert norm.get("category") == "web"
    assert norm.get("parser") == "nginx"


def test_returned_event_contains_original_raw_log(seeded_event_id):
    """The original raw event must remain untouched and uncorrupted."""
    evt = get_event(seeded_event_id)
    assert "raw_event" in evt
    assert evt["raw_event"] == TEST_RAW_LOG
    # Ensure normalized dict also carries the untouched raw log
    assert evt["normalized"].get("raw_event") == TEST_RAW_LOG


def test_returned_event_contains_traceability(seeded_event_id):
    """Traceability metadata: source_file, line_number, timestamps, and SHA-256 hash."""
    evt = get_event(seeded_event_id)
    assert evt.get("source_file") == "test_forensics.log"
    assert evt.get("line_number") == 1
    assert evt.get("ingested_at") is not None
    assert evt.get("processed_at") is not None
    assert evt.get("raw_hash") is not None and len(evt["raw_hash"]) == 64


def test_api_route_fetches_event_details(seeded_event_id):
    """The GET /events/{event_id} route handler returns the complete event model."""
    result = get_event_route(seeded_event_id)
    assert result is not None
    assert result["event_id"] == seeded_event_id
    assert result["raw_event"] == TEST_RAW_LOG
    assert result["normalized"]["source_ip"] == "192.168.1.99"


def test_nonexistent_event_returns_404():
    """Requesting a nonexistent event must raise a 404 HTTPException."""
    # Test service returns None
    assert get_event("evt-does-not-exist-99999") is None

    # Test route raises HTTPException with status 404
    with pytest.raises(HTTPException) as exc_info:
        get_event_route("evt-does-not-exist-99999")
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Event not found"


def test_verify_feature1_search_still_works(seeded_event_id):
    """Verify that unified search filters continue to work after Feature 2 changes."""
    # Search by source IP in q
    results = list_events(q="source.ip=192.168.1.99", limit=10)
    assert any(e["event_id"] == seeded_event_id for e in results)

    # Search by category and outcome
    cat_results = list_events(category="web", outcome="success", limit=10)
    assert any(e["event_id"] == seeded_event_id for e in cat_results)

    # Search by event ID
    id_results = list_events(q=f"event.id={seeded_event_id}", limit=10)
    assert len(id_results) == 1
    assert id_results[0]["event_id"] == seeded_event_id
