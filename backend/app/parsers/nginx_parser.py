import re
from .base_parser import BaseParser

PATTERN = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>[^ ]+) (?P<proto>[^"]+)" (?P<status>\d{3}) (?P<bytes>\S+)')

class NginxParser(BaseParser):
    name = "nginx"
    display_name = "Nginx Access Log"
    vendor = "Nginx"
    format = "nginx"
    version = "1.0"
    supported_source = "web_server"
    description = "Nginx/HTTP web server access and request log parser"
    supported_fields = [
        "source_ip", "destination_port", "action", "status_code",
        "outcome", "bytes", "protocol", "transport", "category", "event_type"
    ]
    mapping_file = "nginx.yaml"
    status = "Active"

    def can_parse(self, text: str) -> bool:
        return bool(PATTERN.search(text.strip()))

    def parse_line(self, line: str):
        m = PATTERN.search(line.strip())
        if not m:
            raise ValueError("Not a valid Nginx access log line")
        d = m.groupdict()
        status_num = int(d["status"])
        outcome = "success" if status_num < 400 else "failure"
        return {
            "source_ip": d["ip"],
            "timestamp": d["ts"],
            "action": d["method"],
            "message": f"{d['method']} {d['path']}",
            "outcome": outcome,
            "status_code": status_num,
            "bytes": d["bytes"],
            "protocol": d["proto"],
            "category": "web",
            "event_type": "access",
            "transport": "TCP",
            "destination_port": 80,
        }
