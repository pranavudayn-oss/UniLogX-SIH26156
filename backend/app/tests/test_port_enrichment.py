"""
Feature 4 tests — Port-to-Service Enrichment

Tests that:
1. Port 22 -> SSH
2. Port 80 -> HTTP
3. Port 443 -> HTTPS
4. Port 53 -> DNS
5. Port 3306 -> MySQL
6. Source port enrichment populates source.service and source_service.
7. Destination port enrichment populates destination.service and destination_service.
8. Unknown/invalid ports do not crash and do not set a service.
9. Original numeric port remains strictly an integer and is never replaced by the service string.
10. Raw event content is never modified by enrichment.
11. Full pipeline processing with enrichment works end-to-end.
12. Feature 1 search still works.
13. Feature 2 event details still work.
14. Feature 3 quarantine and reprocessing still work.
"""
import pytest
from app.core.enrichment import lookup_port_service, enrich, PORT_TO_SERVICE
from app.core.pipeline import process_lines
from app.services.event_service import list_events, get_event
from app.core.quarantine import reprocess_quarantine, quarantine
from app.api.routes_quarantine import quarantine_detail as quarantine_detail_route


# ----------------------------------------------------------------------
# 1-5. Specific Port-to-Service Lookup Tests
# ----------------------------------------------------------------------

def test_port_22_ssh():
    """1. Port 22 -> SSH"""
    assert lookup_port_service(22) == "SSH"
    assert lookup_port_service("22") == "SSH"


def test_port_80_http():
    """2. Port 80 -> HTTP"""
    assert lookup_port_service(80) == "HTTP"
    assert lookup_port_service("80") == "HTTP"


def test_port_443_https():
    """3. Port 443 -> HTTPS"""
    assert lookup_port_service(443) == "HTTPS"
    assert lookup_port_service("443") == "HTTPS"


def test_port_53_dns():
    """4. Port 53 -> DNS"""
    assert lookup_port_service(53) == "DNS"
    assert lookup_port_service("53") == "DNS"


def test_port_3306_mysql():
    """5. Port 3306 -> MySQL"""
    assert lookup_port_service(3306) == "MySQL"
    assert lookup_port_service("3306") == "MySQL"


# ----------------------------------------------------------------------
# Additional Well-Known Port Lookups
# ----------------------------------------------------------------------

def test_additional_well_known_ports():
    """Verify SMTP, POP3, IMAP, PostgreSQL, Redis mappings."""
    assert lookup_port_service(25) == "SMTP"
    assert lookup_port_service(110) == "POP3"
    assert lookup_port_service(143) == "IMAP"
    assert lookup_port_service(5432) == "PostgreSQL"
    assert lookup_port_service(6379) == "Redis"


# ----------------------------------------------------------------------
# 6 & 7. Source & Destination Port Enrichment
# ----------------------------------------------------------------------

def test_source_port_enrichment():
    """6. Source port enrichment properly enriches source object and top-level alias."""
    raw = "test source port log"
    event = {
        "source_port": 22,
        "source": {"ip": "10.0.0.1", "port": 22},
        "raw_event": raw,
    }
    enriched = enrich(event)
    assert enriched["source"]["service"] == "SSH"
    assert enriched["source_service"] == "ssh"
    assert enriched["source"]["port"] == 22
    assert enriched["source_port"] == 22


def test_destination_port_enrichment():
    """7. Destination port enrichment properly enriches destination object and top-level alias."""
    raw = "test destination port log"
    event = {
        "destination_port": 443,
        "destination": {"ip": "203.0.113.1", "port": 443},
        "raw_event": raw,
    }
    enriched = enrich(event)
    assert enriched["destination"]["service"] == "HTTPS"
    assert enriched["destination_service"] == "https"
    assert enriched["destination"]["port"] == 443
    assert enriched["destination_port"] == 443


# ----------------------------------------------------------------------
# 8. Unknown Ports & Edge Cases Do Not Crash
# ----------------------------------------------------------------------

def test_unknown_port_does_not_crash():
    """8. Unknown ports (e.g. ephemeral 54321), None, or invalid values safely remain unmapped."""
    assert lookup_port_service(54321) is None
    assert lookup_port_service(99999) is None
    assert lookup_port_service(None) is None
    assert lookup_port_service("not-a-port") is None

    event = {
        "source_port": 54321,
        "destination_port": 65000,
        "source": {"port": 54321},
        "destination": {"port": 65000},
        "raw_event": "ephemeral log",
    }
    enriched = enrich(event)
    assert "service" not in enriched["source"]
    assert "service" not in enriched["destination"]
    assert "source_service" not in enriched
    assert "destination_service" not in enriched


# ----------------------------------------------------------------------
# 9. Original Numeric Port Remains Numeric
# ----------------------------------------------------------------------

def test_original_numeric_port_remains_unchanged():
    """9. The original numeric port must remain integer and not be overwritten by service string."""
    event = {
        "destination_port": 80,
        "destination": {"ip": "1.2.3.4", "port": 80},
    }
    enriched = enrich(event)
    assert isinstance(enriched["destination_port"], int)
    assert enriched["destination_port"] == 80
    assert isinstance(enriched["destination"]["port"], int)
    assert enriched["destination"]["port"] == 80
    assert enriched["destination"]["service"] == "HTTP"


# ----------------------------------------------------------------------
# 10. Raw Event Remains Strictly Untouched
# ----------------------------------------------------------------------

def test_raw_event_remains_unchanged():
    """10. Raw event content must never be modified by the enrichment step."""
    raw = "Sep 26 10:20:01 %ASA-6-302013: Built inbound TCP connection to outside:203.0.113.10/443"
    event = {
        "destination_port": 443,
        "destination": {"port": 443},
        "raw_event": raw,
    }
    enriched = enrich(event)
    assert enriched["raw_event"] == raw
    assert enriched["raw_event"] is raw


# ----------------------------------------------------------------------
# 11. End-to-End Pipeline Ingestion with Port Enrichment
# ----------------------------------------------------------------------

def test_existing_normalized_event_processing_still_works():
    """11. Pipeline correctly extracts, normalizes, and enriches ports on ingest."""
    log_line = "Sep 26 14:00:00 %ASA-6-302013: Built inbound TCP connection 7711 for inside:10.10.10.10/22 to outside:8.8.4.4/53"
    res = process_lines([log_line], source_file="enrich_test.log")
    assert res["processed"] == 1

    events = list_events(source_ip="10.10.10.10", limit=5)
    assert len(events) >= 1
    evt = events[0]
    assert evt["source_port"] == 22
    assert evt["destination_port"] == 53
    # Check normalized JSON container
    norm = evt["normalized"]
    assert norm["destination"]["port"] == 53
    assert norm["destination"]["service"] == "DNS"
    assert norm["source"]["port"] == 22
    assert norm["source"]["service"] == "SSH"


# ----------------------------------------------------------------------
# 12. Regression: Feature 1 Search Still Works
# ----------------------------------------------------------------------

def test_feature1_search_still_works():
    """12. Feature 1 unified search continues to function properly."""
    res = list_events(q="source.ip=10.10.10.10 destination.port=53", limit=5)
    assert len(res) >= 1
    assert res[0]["source_ip"] == "10.10.10.10"
    assert res[0]["destination_port"] == 53


# ----------------------------------------------------------------------
# 13. Regression: Feature 2 Event Details Still Work
# ----------------------------------------------------------------------

def test_feature2_event_details_still_works():
    """13. Feature 2 event details retrieval continues to return full details and service enrichment."""
    events = list_events(source_ip="10.10.10.10", limit=1)
    assert len(events) >= 1
    evt_id = events[0]["event_id"]
    detail = get_event(evt_id)
    assert detail is not None
    assert detail["event_id"] == evt_id
    assert detail["normalized"]["destination"]["service"] == "DNS"


# ----------------------------------------------------------------------
# 14. Regression: Feature 3 Quarantine & Reprocessing Still Work
# ----------------------------------------------------------------------

def test_feature3_quarantine_reprocessing_still_works():
    """14. Feature 3 quarantine and reprocessing continue to function without regressions."""
    raw_hash = quarantine(
        raw_text="UNKNOWN_LOG_ENRICH_CHECK",
        reason="Unknown parser check",
        source_file="quarantine_enrich_check.log",
    )
    assert raw_hash is not None
    reprocess_res = reprocess_quarantine()
    assert "reprocessed" in reprocess_res
    assert "failed" in reprocess_res
