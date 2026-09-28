import json
from typing import Optional
from ..parsers import PARSERS
from ..parsers.cloud_json_parser import CloudJSONParser
from ..parsers.cisco_asa_parser import CiscoASAParser
from ..parsers.nginx_parser import NginxParser
from ..parsers.syslog_parser import SyslogParser
from ..parsers.generic_kv_parser import GenericKVParser, PAIR

class DetectionResult:
    def __init__(
        self,
        detected_format: str,
        detected_source: str,
        confidence: float,
        reason: str,
        parser: Optional[object] = None,
    ):
        self.format = detected_format
        self.source = detected_source
        self.confidence = confidence
        self.reason = reason
        self.parser = parser

    def __iter__(self):
        # Backward compatibility: allows `fmt, parser = detect_format(line)`
        yield self.format
        yield self.parser

    def to_dict(self):
        return {
            "detected_format": self.format,
            "detected_source": self.source,
            "confidence": self.confidence,
            "reason": self.reason,
        }

    def __repr__(self):
        return f"<DetectionResult format={self.format} source={self.source} confidence={self.confidence}>"

def detect_format(line: str) -> DetectionResult:
    text = line.strip()
    if not text:
        return DetectionResult("unknown", "unknown", 0.0, "Empty line", None)

    # 1. JSON Detection (CloudTrail, AWS, Application JSON)
    if text.startswith("{") and text.endswith("}"):
        try:
            parsed_json = json.loads(text)
            if isinstance(parsed_json, dict):
                cloud_parser = next((p for p in PARSERS if p.name == "cloud_json"), None)
                if cloud_parser and cloud_parser.can_parse(text):
                    return DetectionResult("json", "cloud_provider", 0.98, "Matches CloudTrail/AWS JSON schema", cloud_parser)
                # Generic JSON fallback using cloud_json or generic_kv
                return DetectionResult("json", "application_json", 0.90, "Valid JSON object", cloud_parser)
        except Exception:
            pass

    # 2. Cisco ASA Firewall Detection
    if "%ASA-" in text:
        cisco_parser = next((p for p in PARSERS if p.name == "cisco_asa"), None)
        return DetectionResult("cisco_asa", "firewall", 0.99, "Matched Cisco ASA firewall event code pattern", cisco_parser)

    # 3. CEF (Common Event Format) Detection
    if "CEF:" in text:
        kv_parser = next((p for p in PARSERS if p.name == "generic_kv"), None)
        return DetectionResult("cef", "firewall", 0.95, "Common Event Format (CEF) header identified", kv_parser)

    # 4. Nginx / Apache Access Log Detection
    nginx_parser = next((p for p in PARSERS if p.name == "nginx"), None)
    if nginx_parser and nginx_parser.can_parse(text):
        return DetectionResult("nginx", "web_server", 0.96, "Matched Common Log Format / Nginx access log pattern", nginx_parser)

    # 5. Syslog Detection (RFC 3164 / RFC 5424)
    syslog_parser = next((p for p in PARSERS if p.name == "syslog"), None)
    if syslog_parser and syslog_parser.can_parse(text):
        # Check if syslog also wraps key=value pairs
        if len(PAIR.findall(text)) >= 2:
            kv_parser = next((p for p in PARSERS if p.name == "generic_kv"), None)
            return DetectionResult("syslog_kv", "network_device", 0.92, "Syslog message containing key=value attributes", kv_parser or syslog_parser)
        return DetectionResult("syslog", "syslog_host", 0.91, "Matched RFC3164/5424 syslog header", syslog_parser)

    # 6. Generic Key=Value Detection
    if len(PAIR.findall(text)) >= 2:
        kv_parser = next((p for p in PARSERS if p.name == "generic_kv"), None)
        return DetectionResult("generic_kv", "network_device", 0.88, "Extracted key=value pairs", kv_parser)

    # 7. Fallback to registered parser loop
    for parser in PARSERS:
        try:
            if parser.can_parse(text):
                source = getattr(parser, "supported_source", "generic")
                return DetectionResult(parser.format, source, 0.75, f"Matched parser plugin: {parser.name}", parser)
        except Exception:
            continue

    return DetectionResult("unknown", "unknown", 0.0, "No parser matched the event pattern", None)

