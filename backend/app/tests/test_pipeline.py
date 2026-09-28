from app.core.detector import detect_format
from app.core.normalizer import normalize
from app.core.traceability import build_trace

def test_detect_nginx():
    line='192.168.1.1 - - [26/Sep/2026:10:15:22 +0000] "GET / HTTP/1.1" 200 100'
    fmt, parser=detect_format(line)
    assert fmt == 'nginx'
    assert parser.name == 'nginx'

def test_trace_hash_is_deterministic():
    _, h1=build_trace('abc')
    _, h2=build_trace('abc')
    assert h1 == h2

def test_extreme_port_is_safely_null():
    data=normalize({'src_port':'99999','dst_port':'1','src':'10.0.0.1'}, 'generic_kv','generic_kv')
    assert data['source_port'] is None
    assert data['destination_port'] == 1

def test_syslog_timestamp_year_handling():
    from app.utils.timestamp_utils import normalize_timestamp
    ts = normalize_timestamp("Sep 26 10:23:15", context_year=2026)
    assert ts is not None
    assert ts.startswith("2026-09-26T10:23:15")
    assert not ts.startswith("1900")

def test_structured_detection():
    line = 'Sep 26 10:20:01 %ASA-6-302013: Built inbound TCP connection 123 for inside:192.168.1.10/51522 to outside:203.0.113.10/443'
    det = detect_format(line)
    assert det.format == 'cisco_asa'
    assert det.source == 'firewall'
    assert det.confidence >= 0.9
    assert "Cisco ASA" in det.reason
    # Unpack compatibility
    fmt, parser = det
    assert fmt == 'cisco_asa'
    assert parser.name == 'cisco_asa'

def test_port_enrichment():
    from app.core.enrichment import enrich
    event = {"source_port": 22, "destination_port": 443, "source_ip": "10.0.0.1"}
    enriched = enrich(event)
    assert enriched["source_service"] == "ssh"
    assert enriched["destination_service"] == "https"
    assert enriched["source_ip_scope"] == "private"

def test_pipeline_cisco_asa_traceability():
    from app.core.pipeline import process_lines
    from app.services.event_service import get_event
    line = 'Sep 26 10:20:05 %ASA-4-106023: Deny tcp src inside:10.0.0.8/4444 dst outside:198.51.100.20/22 by access-group'
    res = process_lines([line], source_file="test_asa.log")
    assert res["processed"] == 1
    assert len(res["event_ids"]) == 1
    event_id = res["event_ids"][0]
    evt = get_event(event_id)
    assert evt is not None
    assert evt["source_ip"] == "10.0.0.8"
    assert evt["destination_ip"] == "198.51.100.20"
    assert evt["destination_port"] == 22
    assert evt["action"] == "denied"
    assert evt["outcome"] == "failure"
    assert evt["source_file"] == "test_asa.log"
    assert evt["line_number"] == 1
    assert evt["raw_hash"] is not None
    # Forensic coexistence:
    assert evt["raw_json"] is not None
    assert "evt-" in evt["event_id"]
    assert "ulx" in evt["normalized"]
    assert evt["normalized"]["ulx"]["parser_name"] == "cisco_asa"

def test_unknown_log_quarantined_and_reprocessed():
    from app.core.pipeline import process_lines
    from app.core.quarantine import reprocess_quarantine
    from app.database import get_connection

    unknown_line = "THIS_IS_UNKNOWN_NON_LOG_GARBAGE_123456789"
    res = process_lines([unknown_line], source_file="bad.log")
    assert res["quarantined"] == 1
    assert res["processed"] == 0

    with get_connection() as conn:
        q_row = conn.execute("SELECT * FROM quarantines WHERE raw_text = ?", (unknown_line,)).fetchone()
        assert q_row is not None
        assert "No matching parser" in q_row["reason"]
        assert q_row["status"] == "quarantined"

    # Test reprocessing mechanism
    reprocess_res = reprocess_quarantine()
    assert "reprocessed" in reprocess_res
    assert "failed" in reprocess_res

def test_unified_search_by_fields():
    from app.core.pipeline import process_lines
    from app.services.event_service import list_events
    line = '192.168.1.99 - - [26/Sep/2026:10:15:22 +0000] "GET /test-search HTTP/1.1" 200 100'
    process_lines([line], source_file="web.log")
    # Search by source.ip syntax
    results = list_events(q="source.ip=192.168.1.99")
    assert len(results) >= 1
    assert results[0]["source_ip"] == "192.168.1.99"
    # Search by outcome syntax
    results_outcome = list_events(q="outcome=success", source_ip="192.168.1.99")
    assert len(results_outcome) >= 1


