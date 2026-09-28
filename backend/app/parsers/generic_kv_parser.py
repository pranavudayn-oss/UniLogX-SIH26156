import re
from .base_parser import BaseParser

PAIR = re.compile(r'(?P<key>[A-Za-z_][\w.-]*)=(?:"(?P<quoted>[^"]*)"|(?P<bare>\S+))')

TS_PREFIX = re.compile(r'^(?:<(?P<pri>\d+)>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<app>[^:]+):\s*')

class GenericKVParser(BaseParser):
    name = "generic_kv"
    display_name = "Generic Key-Value"
    vendor = "Generic"
    format = "generic_kv"
    version = "1.0"
    supported_source = "network_device"
    description = "Generic key=value and firewall/security appliance log parser"
    supported_fields = [
        "source_ip", "source_port", "destination_ip", "destination_port",
        "transport", "category", "event_type"
    ]
    mapping_file = "generic_kv.yaml"
    status = "Active"

    def can_parse(self, text: str) -> bool:
        return len(PAIR.findall(text)) >= 2

    def parse_line(self, line: str):
        pairs = PAIR.findall(line)
        if not pairs:
            raise ValueError("No key=value pairs found")
        data = {k: q if q != "" else b for k, q, b in pairs}

        # Check if line had syslog header before KV pairs
        ts_m = TS_PREFIX.search(line)
        if ts_m and "timestamp" not in data and "time" not in data:
            data["timestamp"] = ts_m.group("ts")
            data["hostname"] = ts_m.group("host")

        if any(k in data for k in ("src", "dst", "src_ip", "dst_ip", "source_ip", "proto", "dpt", "spt")):
            data.setdefault("category", "network")
            data.setdefault("event_type", "traffic")

        return data
