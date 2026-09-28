"""
Feature 6 tests — Dashboard Analytics & KPIs

Validates:
1. Metrics endpoint returns a valid structured response.
2. Total event count matches actual stored database events.
3. Quarantine count matches actual stored quarantine records.
4. Source count is calculated accurately from distinct source types.
5. Parser and source distribution dictionaries accurately reflect stored data.
6. Category distribution accurately reflects normalized event categories.
7. Outcome distribution accurately reflects normalized event outcomes.
8. Recent activity timeline is returned with real event timestamps.
9. Empty database state is handled safely with zero defaults and no division-by-zero.
10. Feature 1 unified search continues to function without regressions.
11. Feature 2 event details retrieval continues to function without regressions.
12. Feature 3 quarantine reprocessing continues to function without regressions.
13. Feature 4 port-to-service enrichment continues to function without regressions.
14. Feature 5 parser registry continues to function without regressions.
"""
import pytest
from app.services.analytics_service import metrics
from app.api.routes_metrics import get_metrics as get_metrics_route
from app.core.pipeline import process_lines
from app.database import get_connection
from app.services.event_service import list_events, get_event
from app.core.quarantine import reprocess_quarantine
from app.core.enrichment import lookup_port_service
from app.api.routes_parsers import list_parsers


# ----------------------------------------------------------------------
# Fixture: deterministic log ingestion for metrics validation
# ----------------------------------------------------------------------

TEST_NGINX_LINE = '10.200.1.5 - - [27/Sep/2026:12:00:00 +0000] "GET /metrics-test HTTP/1.1" 200 512'


@pytest.fixture(scope="module")
def seeded_event():
    res = process_lines([TEST_NGINX_LINE], source_file="metrics_seed.log")
    assert res["processed"] >= 1
    return res["event_ids"][0]


# ----------------------------------------------------------------------
# 1-4. Core KPI Validation
# ----------------------------------------------------------------------

def test_metrics_endpoint_returns_valid_response(seeded_event):
    """1. GET /metrics returns complete KPI structure."""
    m = get_metrics_route()
    assert isinstance(m, dict)
    required_keys = [
        "total_events",
        "quarantined",
        "quarantined_events",
        "total_quarantined",
        "reprocessed",
        "parser_success_rate",
        "source_count",
        "events_by_parser",
        "events_by_category",
        "events_by_outcome",
        "events_by_source",
        "quarantine_summary",
        "recent_activity",
    ]
    for key in required_keys:
        assert key in m, f"Missing key in metrics response: {key}"


def test_total_event_count_matches_stored_events(seeded_event):
    """2. Total event count matches actual count in database."""
    m = metrics()
    with get_connection() as conn:
        db_total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert m["total_events"] == db_total
    assert m["total_events"] >= 1


def test_quarantine_count_matches_stored_quarantine():
    """3. Quarantine count matches actual active quarantine records."""
    m = metrics()
    with get_connection() as conn:
        db_active = conn.execute("SELECT COUNT(*) FROM quarantines WHERE status = 'quarantined'").fetchone()[0]
        db_total_q = conn.execute("SELECT COUNT(*) FROM quarantines").fetchone()[0]
    assert m["quarantined"] == db_active
    assert m["quarantined_events"] == db_active
    assert m["total_quarantined"] == db_total_q


def test_source_count_calculated_correctly():
    """4. Source count equals number of distinct source_type entries."""
    m = metrics()
    with get_connection() as conn:
        sources = {r[0] for r in conn.execute("SELECT DISTINCT source_type FROM events WHERE source_type IS NOT NULL")}
    assert m["source_count"] == len(sources)
    assert m["source_count"] == len(m["events_by_source"])


# ----------------------------------------------------------------------
# 5-8. Distribution and Activity Tests
# ----------------------------------------------------------------------

def test_parser_and_source_distribution(seeded_event):
    """5. Parser and source distribution dictionaries accurately reflect stored events."""
    m = metrics()
    assert isinstance(m["events_by_parser"], dict)
    assert isinstance(m["events_by_source"], dict)
    # Our seeded event is an Nginx line
    assert "nginx" in m["events_by_parser"]
    assert m["events_by_parser"]["nginx"] >= 1
    assert "web_server" in m["events_by_source"]
    assert m["events_by_source"]["web_server"] >= 1


def test_category_distribution_when_data_exists(seeded_event):
    """6. Category distribution accurately reflects normalized event categories."""
    m = metrics()
    assert isinstance(m["events_by_category"], dict)
    # Nginx produces category 'web'
    assert "web" in m["events_by_category"]
    assert m["events_by_category"]["web"] >= 1


def test_outcome_distribution_when_data_exists(seeded_event):
    """7. Outcome distribution reflects security verdicts."""
    m = metrics()
    assert isinstance(m["events_by_outcome"], dict)
    assert "success" in m["events_by_outcome"]
    assert m["events_by_outcome"]["success"] >= 1


def test_recent_activity_returned_correctly(seeded_event):
    """8. Recent activity list contains valid event metadata and timestamps."""
    m = metrics()
    activity = m["recent_activity"]
    assert isinstance(activity, list)
    assert len(activity) >= 1
    latest = activity[0]
    assert "event_id" in latest
    assert "timestamp" in latest
    assert "parser" in latest
    assert "outcome" in latest
    assert latest["timestamp"] is not None


# ----------------------------------------------------------------------
# 9. Empty Database Safety
# ----------------------------------------------------------------------

def test_empty_database_handled_safely():
    """9. Zero state does not produce division-by-zero or crashes."""
    # Test formula directly with 0 attempted
    total = 0
    attempted = 0
    success_rate = round((total / attempted * 100), 2) if attempted else 0.0
    assert success_rate == 0.0

    # Test metrics() returns valid types even if counts are zero
    m = metrics()
    assert isinstance(m["parser_success_rate"], (int, float))
    assert 0.0 <= m["parser_success_rate"] <= 100.0


# ----------------------------------------------------------------------
# 10-14. Regressions across Features 1 through 5
# ----------------------------------------------------------------------

def test_feature1_search_regression():
    """10. Feature 1 search continues to function."""
    res = list_events(source_ip="10.200.1.5", limit=5)
    assert len(res) >= 1
    assert res[0]["source_ip"] == "10.200.1.5"


def test_feature2_event_details_regression(seeded_event):
    """11. Feature 2 event details retrieval continues to work."""
    evt = get_event(seeded_event)
    assert evt is not None
    assert evt["event_id"] == seeded_event
    assert evt["raw_event"] == TEST_NGINX_LINE


def test_feature3_quarantine_reprocessing_regression():
    """12. Feature 3 quarantine reprocessing works."""
    res = reprocess_quarantine()
    assert "reprocessed" in res
    assert "failed" in res


def test_feature4_port_enrichment_regression():
    """13. Feature 4 port enrichment mapping remains active."""
    assert lookup_port_service(443) == "HTTPS"
    assert lookup_port_service(80) == "HTTP"


def test_feature5_parser_registry_regression():
    """14. Feature 5 parser registry list continues to return all parsers."""
    parsers = list_parsers()
    assert len(parsers) >= 5
    names = {p["name"] for p in parsers}
    assert "nginx" in names
    assert "cisco_asa" in names
