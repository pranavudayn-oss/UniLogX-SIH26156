import re
from .base_parser import BaseParser

PATTERN = re.compile(r'^(?P<ts>\S+\s+\d{1,2}\s+\S+)\s+%ASA-\d-(?P<code>\d+):\s+(?P<message>.*)$')
IP_PAIR = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<port>\d+)')

class CiscoASAParser(BaseParser):
    name = "cisco_asa"
    display_name = "Cisco ASA"
    vendor = "Cisco"
    format = "cisco_asa"
    version = "1.0"
    supported_source = "firewall"
    description = "Cisco ASA firewall connection and security event parser"
    supported_fields = [
        "source_ip", "source_port", "destination_ip", "destination_port",
        "action", "outcome", "transport", "category", "event_type"
    ]
    mapping_file = "cisco_asa.yaml"
    status = "Active"

    def can_parse(self, text: str) -> bool:
        return "%ASA-" in text

    def parse_line(self, line: str):
        m = PATTERN.search(line.strip())
        if not m:
            raise ValueError("Not a valid Cisco ASA message")
        d = m.groupdict()
        msg = d["message"]
        out = {
            "timestamp": d["ts"],
            "event_code": d["code"],
            "message": msg,
            "category": "network",
            "event_type": "connection",
        }
        # Check action & outcome
        lower_msg = msg.lower()
        if "deny" in lower_msg or "blocked" in lower_msg:
            out["action"] = "deny"
            out["outcome"] = "failure"
        elif "built" in lower_msg or "permit" in lower_msg or "allow" in lower_msg:
            out["action"] = "allow"
            out["outcome"] = "success"

        # Check transport
        for proto in ("tcp", "udp", "icmp"):
            if proto in lower_msg:
                out["transport"] = proto.upper()
                break

        pairs = IP_PAIR.findall(msg)
        if len(pairs) >= 2:
            out.update(
                source_ip=pairs[0][0],
                source_port=int(pairs[0][1]),
                destination_ip=pairs[1][0],
                destination_port=int(pairs[1][1]),
            )
        return out
