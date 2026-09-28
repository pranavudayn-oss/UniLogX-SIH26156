"""
Feature 5 tests — Parser Registry and Onboarding

Validates:
1. GET /parsers returns the full parser registry list.
2. Registry contains all 5 currently implemented concrete parsers.
3. Each parser entry contains required metadata (name, display_name, vendor, version, format, source, description, status).
4. Parser names in the registry are unique.
5. Parser status is exposed correctly as 'Active'.
6. Individual parser detail works via GET /parsers/{parser_name}.
7. Requesting an unknown parser returns a 404 HTTPException.
8. Existing parser routing and dynamic onboarding (register_parser/unregister_parser) work properly.
9. Existing sample logs still process cleanly through the pipeline.
10. Feature 1 unified search continues to function without regressions.
11. Feature 2 event details retrieval continues to function without regressions.
12. Feature 3 quarantine reprocessing continues to function without regressions.
13. Feature 4 port-to-service enrichment continues to function without regressions.
"""
import pytest
from fastapi import HTTPException
from app.api.routes_parsers import list_parsers, get_parser as get_parser_route
from app.core.parser_router import get_parser, get_all_parsers, register_parser, unregister_parser
from app.parsers.base_parser import BaseParser
from app.core.pipeline import process_lines
from app.services.event_service import list_events, get_event
from app.core.quarantine import quarantine, reprocess_quarantine
from app.core.enrichment import lookup_port_service


# ----------------------------------------------------------------------
# 1-5. Parser Registry Inventory Tests
# ----------------------------------------------------------------------

def test_get_parsers_returns_registry():
    """1. GET /parsers returns a non-empty list of registered parsers."""
    parsers = list_parsers()
    assert isinstance(parsers, list)
    assert len(parsers) >= 5


def test_registry_contains_actual_implemented_parsers():
    """2. Registry contains the actual 5 concrete parsers in the project."""
    parsers = list_parsers()
    names = {p["name"] for p in parsers}
    expected_parsers = {"cisco_asa", "nginx", "cloud_json", "syslog", "generic_kv"}
    assert expected_parsers.issubset(names), f"Missing parsers: {expected_parsers - names}"


def test_registry_entry_contains_required_metadata():
    """3. Each entry contains all required discovery and specification metadata."""
    parsers = list_parsers()
    for p in parsers:
        assert p.get("name"), "Parser missing name"
        assert p.get("display_name"), f"Parser {p.get('name')} missing display_name"
        assert p.get("vendor"), f"Parser {p.get('name')} missing vendor"
        assert p.get("version"), f"Parser {p.get('name')} missing version"
        assert p.get("format") or p.get("supported_format"), f"Parser {p.get('name')} missing format"
        assert p.get("source") or p.get("supported_source"), f"Parser {p.get('name')} missing source"
        assert p.get("description"), f"Parser {p.get('name')} missing description"
        assert "processed_count" in p, f"Parser {p.get('name')} missing processed_count"


def test_parser_names_are_unique():
    """4. All parser names in the registry must be strictly unique."""
    parsers = list_parsers()
    names = [p["name"] for p in parsers]
    assert len(names) == len(set(names)), f"Duplicate parser names found: {names}"


def test_parser_status_is_exposed():
    """5. Parser status is exposed and active."""
    parsers = list_parsers()
    for p in parsers:
        assert p.get("status") in ("Active", "active"), f"Unexpected status in {p.get('name')}: {p.get('status')}"
        assert p.get("enabled") is True


# ----------------------------------------------------------------------
# 6 & 7. Individual Parser Details & 404 Handling
# ----------------------------------------------------------------------

def test_individual_parser_detail_endpoint():
    """6. GET /parsers/{parser_name} returns full specification for an individual parser."""
    cisco = get_parser_route("cisco_asa")
    assert cisco["name"] == "cisco_asa"
    assert cisco["display_name"] == "Cisco ASA"
    assert cisco["vendor"] == "Cisco"
    assert cisco["format"] == "cisco_asa"
    assert cisco["mapping_file"] == "cisco_asa.yaml"
    assert "source_ip" in cisco["supported_fields"]
    assert "destination_ip" in cisco["supported_fields"]


def test_unknown_parser_detail_returns_404():
    """7. Requesting an unknown parser raises a 404 HTTPException."""
    with pytest.raises(HTTPException) as exc_info:
        get_parser_route("nonexistent_unknown_parser_99")
    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.detail.lower()


# ----------------------------------------------------------------------
# 8. Parser Router & Dynamic Onboarding Mechanism
# ----------------------------------------------------------------------

class MockCustomFirewallParser(BaseParser):
    name = "mock_firewall"
    display_name = "Mock Firewall Appliance"
    vendor = "MockSec"
    format = "mock_fw"
    version = "2.1"
    supported_source = "firewall"
    description = "Mock custom firewall parser for onboarding verification"
    supported_fields = ["source_ip", "destination_ip", "action"]
    mapping_file = "mock_fw.yaml"

    def can_parse(self, text: str) -> bool:
        return "MOCK_FW:" in text

    def parse_line(self, line: str):
        return {
            "source_ip": "192.168.10.10",
            "destination_ip": "10.0.0.1",
            "action": "allow",
            "category": "network",
        }


def test_parser_router_and_onboarding():
    """8. Test router retrieval, onboarding a new parser, and clean unregistration."""
    # Existing router works
    nginx = get_parser("nginx")
    assert nginx is not None
    assert nginx.name == "nginx"

    # Onboard new parser
    mock_p = MockCustomFirewallParser()
    register_parser(mock_p)
    try:
        found = get_parser("mock_firewall")
        assert found is not None
        assert found.display_name == "Mock Firewall Appliance"
        assert found.vendor == "MockSec"

        # Check API exposes the newly onboarded parser
        api_detail = get_parser_route("mock_firewall")
        assert api_detail["name"] == "mock_firewall"
        assert api_detail["vendor"] == "MockSec"
    finally:
        # Unregister to keep environment clean
        unregister_parser("mock_firewall")
        assert get_parser("mock_firewall") is None


# ----------------------------------------------------------------------
# 9. Existing Sample Logs Still Process
# ----------------------------------------------------------------------

def test_existing_sample_logs_still_process():
    """9. Pipeline continues to process sample logs with registry in place."""
    line = '10.0.0.99 - - [27/Sep/2026:10:00:00 +0000] "GET /registry-test HTTP/1.1" 200 128'
    res = process_lines([line], source_file="registry_test.log")
    assert res["processed"] == 1
    assert res["parser_counts"].get("nginx") == 1


# ----------------------------------------------------------------------
# 10-13. Regressions for Features 1, 2, 3, 4
# ----------------------------------------------------------------------

def test_feature1_search_regression():
    """10. Feature 1 unified search continues to function."""
    res = list_events(source_ip="10.0.0.99", limit=5)
    assert len(res) >= 1
    assert res[0]["source_ip"] == "10.0.0.99"


def test_feature2_event_details_regression():
    """11. Feature 2 event details retrieval continues to work."""
    events = list_events(source_ip="10.0.0.99", limit=1)
    assert len(events) >= 1
    detail = get_event(events[0]["event_id"])
    assert detail is not None
    assert detail["event_id"] == events[0]["event_id"]
    assert detail["source_ip"] == "10.0.0.99"


def test_feature3_quarantine_reprocessing_regression():
    """12. Feature 3 quarantine reprocessing works."""
    raw_hash = quarantine(
        raw_text="NON_EXISTENT_LOG_FOR_REGISTRY_TEST",
        reason="Registry test quarantine",
        source_file="quarantine_reg.log",
    )
    assert raw_hash is not None
    res = reprocess_quarantine()
    assert "reprocessed" in res
    assert "failed" in res


def test_feature4_port_enrichment_regression():
    """13. Feature 4 port enrichment mapping remains active."""
    assert lookup_port_service(443) == "HTTPS"
    assert lookup_port_service(22) == "SSH"
    assert lookup_port_service(3306) == "MySQL"
