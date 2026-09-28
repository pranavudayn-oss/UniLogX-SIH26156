
from ..core.detector import DetectionResult
from ..parsers import PARSERS
from ..parsers.generic_kv_parser import PAIR
from .ml_classifier import CLASSIFIER
import json

def _p(name):
    return next((p for p in PARSERS if p.name == name), None)

def _result(fmt, source, confidence, reason, parser):
    return DetectionResult(fmt, source, confidence, reason, parser)

def detect_format_enhanced(line: str) -> DetectionResult:
    text=line.strip()
    if not text:
        return _result("unknown","unknown",0.0,"Empty line",None)

    # Deterministic high-confidence signatures first.
    p=_p("cisco_asa")
    if p and p.can_parse(text): return _result(p.format,"firewall",0.99,"Cisco ASA signature matched",p)

    p=_p("suricata_eve")
    if p and p.can_parse(text): return _result(p.format,"ids_ips",0.99,"Suricata EVE JSON signature matched",p)

    p=_p("windows_event_json")
    if p and p.can_parse(text): return _result(p.format,"windows",0.98,"Windows Event JSON structure matched",p)

    p=_p("docker_json")
    if p and p.can_parse(text): return _result(p.format,"container",0.98,"Docker json-file structure matched",p)

    p=_p("cloud_json")
    if p and p.can_parse(text): return _result(p.format,"cloud_provider",0.98,"CloudTrail/AWS JSON structure matched",p)

    p=_p("nginx")
    if p and p.can_parse(text): return _result(p.format,"web_server",0.96,"HTTP common access-log pattern matched",p)

    p=_p("apache_error")
    if p and p.can_parse(text): return _result(p.format,"web_server",0.94,"Apache error-log pattern matched",p)

    p=_p("snort_alert")
    if p and p.can_parse(text): return _result(p.format,"ids_ips",0.94,"Snort alert signature matched",p)

    p=_p("linux_auth")
    if p and p.can_parse(text): return _result(p.format,"linux",0.94,"Linux authentication log pattern matched",p)

    p=_p("mysql_log")
    if p and p.can_parse(text): return _result(p.format,"database",0.91,"MySQL log signature matched",p)

    p=_p("postgresql_log")
    if p and p.can_parse(text): return _result(p.format,"database",0.91,"PostgreSQL log signature matched",p)

    if "CEF:" in text:
        p=_p("generic_kv")
        if p and p.can_parse(text): return _result("cef","security_device",0.95,"CEF header plus key/value extension detected",p)

    if len(PAIR.findall(text)) >= 2:
        p=_p("generic_kv")
        if p: return _result("generic_kv","network_device",0.88,"Generic key=value structure detected",p)

    p=_p("syslog")
    if p and p.can_parse(text):
        return _result("syslog","syslog_host",0.91,"RFC3164/RFC5424 syslog header detected",p)

    # Structured JSON that is not CloudTrail.
    if text.startswith("{") and text.endswith("}"):
        try:
            obj=json.loads(text)
            if isinstance(obj,dict):
                p=_p("generic_json")
                if p: return _result("json_generic","application",0.90,"Valid JSON object; no vendor-specific schema matched",p)
        except Exception:
            pass

    # CSV-like rows.
    p=_p("csv_event")
    if p and p.can_parse(text):
        return _result("csv","application",0.72,"Structured CSV-like event detected",p)

    # ML-assisted classification for uncertain logs.
    predictions=CLASSIFIER.predict(text,top_k=3)
    for label, confidence in predictions:
        p=_p(label)
        if p and confidence >= 0.34:
            # Require the selected parser to be able to parse where possible.
            try:
                if p.can_parse(text):
                    source=getattr(p,"supported_source","generic")
                    return _result(p.format,source,max(0.34,confidence),
                                   f"ML classifier selected {p.name} (confidence {confidence:.1%})",p)
            except Exception:
                pass

    # Safe generic fallback for recognizable security/system text.
    p=_p("generic_text")
    if p and p.can_parse(text):
        top=predictions[0][1] if predictions else 0.0
        confidence=max(0.45,min(0.70,top))
        return _result("generic_text","generic",confidence,
                       "Generic fallback parser selected after deterministic/ML detection",p)

    return _result("unknown","unknown",0.0,"No supported parser or safe fallback matched",None)
