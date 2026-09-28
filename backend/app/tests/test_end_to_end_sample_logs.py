import os
from pathlib import Path
from app.core.pipeline import process_lines
from app.core.ingestion import read_text_lines
from app.services.event_service import list_events, get_event
from app.services.analytics_service import metrics
from app.core.quarantine import reprocess_quarantine
from app.services.export_service import export_csv, export_json

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_logs"

def test_ingest_cisco_asa_sample():
    file_path = SAMPLE_DIR / "cisco_asa.log"
    assert file_path.exists()
    content = file_path.read_bytes()
    lines = read_text_lines(content, file_path.name)
    res = process_lines(lines, source_file="cisco_asa.log")
    assert res["processed"] == 2
    assert res["quarantined"] == 0

    evts = list_events(source="firewall", limit=10)
    assert len(evts) >= 2
    for e in evts[:2]:
        assert e["parser_name"] == "cisco_asa"
        assert e["raw_hash"] is not None
        assert e["source_file"] == "cisco_asa.log"
        assert e["line_number"] in (1, 2)
        assert e["normalized"]["event"]["category"] == "network"

def test_ingest_cloudtrail_sample():
    file_path = SAMPLE_DIR / "cloudtrail.json"
    assert file_path.exists()
    content = file_path.read_bytes()
    lines = read_text_lines(content, file_path.name)
    res = process_lines(lines, source_file="cloudtrail.json")
    assert res["processed"] == 2
    assert res["quarantined"] == 0

    evts = list_events(source="cloud_provider", limit=10)
    assert len(evts) >= 2
    outcomes = {e["outcome"] for e in evts[:2]}
    assert "success" in outcomes
    assert "failure" in outcomes

def test_ingest_extreme_values_sample():
    file_path = SAMPLE_DIR / "extreme_values.log"
    assert file_path.exists()
    content = file_path.read_bytes()
    lines = read_text_lines(content, file_path.name)
    # Must not crash even with extreme byte numbers or ports > 65535
    res = process_lines(lines, source_file="extreme_values.log")
    assert res["processed"] == 2
    assert res["quarantined"] == 0

def test_ingest_nginx_sample():
    file_path = SAMPLE_DIR / "nginx_access.log"
    assert file_path.exists()
    content = file_path.read_bytes()
    lines = read_text_lines(content, file_path.name)
    res = process_lines(lines, source_file="nginx_access.log")
    assert res["processed"] == 3
    assert res["quarantined"] == 0

def test_ingest_syslog_sample():
    file_path = SAMPLE_DIR / "syslog.log"
    assert file_path.exists()
    content = file_path.read_bytes()
    lines = read_text_lines(content, file_path.name)
    res = process_lines(lines, source_file="syslog.log")
    assert res["processed"] == 2
    assert res["quarantined"] == 0

    evts = list_events(source="syslog_host", limit=5)
    for e in evts[:2]:
        # Timestamp must not be year 1900
        assert not str(e["timestamp"]).startswith("1900")

def test_ingest_unknown_custom_sample():
    file_path = SAMPLE_DIR / "unknown_custom.log"
    assert file_path.exists()
    content = file_path.read_bytes()
    lines = read_text_lines(content, file_path.name)
    res = process_lines(lines, source_file="unknown_custom.log")
    assert res["quarantined"] == 2
    assert res["processed"] == 0

def test_metrics_and_exports():
    m = metrics()
    assert m["total_events"] > 0
    assert m["quarantined"] > 0
    assert m["parser_success_rate"] > 0.0

    evts = list_events(limit=10)
    csv_path = export_csv(evts)
    assert csv_path.exists()
    assert csv_path.stat().st_size > 0

    json_path = export_json(evts)
    assert json_path.exists()
    assert json_path.stat().st_size > 0

