"""
Feature 1 tests — Advanced Unified Search

Tests that the list_events() function correctly filters on all 14 unified search fields
using both the `q` field=value parser and the dedicated filter params.
"""
from app.core.pipeline import process_lines
from app.core.ingestion import read_text_lines
from app.services.event_service import list_events

# ------------------------------------------------------------------
# Fixtures — ingest known sample logs so we have deterministic data
# ------------------------------------------------------------------

CISCO_ASA_LINES = [
    "Sep 26 10:00:00 %ASA-6-302013: Built inbound TCP connection 1001 for inside:10.1.1.5/55000 to outside:8.8.8.8/443",
]
NGINX_LINES = [
    '172.16.0.5 - - [26/Sep/2026:10:00:00 +0000] "GET /health HTTP/1.1" 200 512',
]
SYSLOG_LINES = [
    "Sep 26 10:00:00 myhost sshd[1234]: Accepted password for alice from 192.168.50.10 port 22",
]


def _ingest(lines, fname):
    res = process_lines(lines, source_file=fname)
    return res


def setup_module(module):
    """Ingest test fixtures once before all tests in this module."""
    _ingest(CISCO_ASA_LINES, "search_test_cisco.log")
    _ingest(NGINX_LINES, "search_test_nginx.log")
    _ingest(SYSLOG_LINES, "search_test_syslog.log")


# ------------------------------------------------------------------
# source.ip filtering
# ------------------------------------------------------------------

def test_search_by_source_ip_dedicated_param():
    results = list_events(source_ip="10.1.1.5", limit=50)
    assert any(e["source_ip"] == "10.1.1.5" for e in results), \
        f"Expected source_ip=10.1.1.5, got: {[e.get('source_ip') for e in results]}"


def test_search_by_source_ip_in_q():
    results = list_events(q="source.ip=10.1.1.5", limit=50)
    assert any(e["source_ip"] == "10.1.1.5" for e in results)


def test_search_by_source_ip_alias_src():
    results = list_events(q="src=10.1.1.5", limit=50)
    assert any(e["source_ip"] == "10.1.1.5" for e in results)


# ------------------------------------------------------------------
# destination.ip + destination.port filtering
# ------------------------------------------------------------------

def test_search_by_destination_ip():
    results = list_events(destination_ip="8.8.8.8", limit=50)
    assert any(e["destination_ip"] == "8.8.8.8" for e in results)


def test_search_by_destination_port_dedicated():
    results = list_events(destination_port=443, limit=50)
    assert any(e["destination_port"] == 443 for e in results)


def test_search_by_destination_port_in_q():
    results = list_events(q="destination.port=443", limit=50)
    assert any(e["destination_port"] == 443 for e in results)


def test_search_by_destination_port_alias_dpt():
    results = list_events(q="dpt=443", limit=50)
    assert any(e["destination_port"] == 443 for e in results)


# ------------------------------------------------------------------
# network.transport
# ------------------------------------------------------------------

def test_search_by_transport_dedicated():
    results = list_events(transport="TCP", limit=50)
    assert any(e.get("transport") == "TCP" for e in results)


def test_search_by_transport_in_q():
    results = list_events(q="network.transport=TCP", limit=50)
    assert any(e.get("transport") == "TCP" for e in results)


# ------------------------------------------------------------------
# outcome / category / parser
# ------------------------------------------------------------------

def test_search_by_outcome_dedicated():
    results = list_events(outcome="success", limit=100)
    assert all(e.get("outcome") == "success" for e in results)


def test_search_by_category_dedicated():
    results = list_events(category="web", limit=50)
    assert all(e.get("category") == "web" for e in results)


def test_search_by_parser_dedicated():
    results = list_events(parser="cisco_asa", limit=50)
    assert all(e.get("parser_name") == "cisco_asa" for e in results)


def test_search_by_parser_in_q():
    results = list_events(q="parser=nginx", limit=50)
    assert all(e.get("parser_name") == "nginx" for e in results)


# ------------------------------------------------------------------
# Combined multi-field query via q
# ------------------------------------------------------------------

def test_search_multi_field_q():
    """Source.ip AND destination.port in same q string."""
    results = list_events(q="source.ip=10.1.1.5 destination.port=443", limit=50)
    assert any(
        e["source_ip"] == "10.1.1.5" and e["destination_port"] == 443
        for e in results
    )


# ------------------------------------------------------------------
# Free-text fallback
# ------------------------------------------------------------------

def test_free_text_search():
    results = list_events(q="alice", limit=50)
    # Should match the syslog line containing "alice"
    assert len(results) >= 1
    combined = " ".join(str(e.get("message", "")) + str(e.get("normalized_json", "")) for e in results)
    assert "alice" in combined.lower()


# ------------------------------------------------------------------
# Negative: impossible filter returns empty
# ------------------------------------------------------------------

def test_impossible_filter_returns_empty():
    results = list_events(source_ip="0.0.0.0", destination_ip="0.0.0.0", limit=10)
    assert results == []


# ------------------------------------------------------------------
# source filter (source_type)
# ------------------------------------------------------------------

def test_search_by_source_type():
    results = list_events(source="web_server", limit=50)
    assert all(e.get("source_type") == "web_server" for e in results)
