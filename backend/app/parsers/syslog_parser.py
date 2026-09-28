import re
from .base_parser import BaseParser

PATTERN = re.compile(r'^(?:<(?P<pri>\d+)>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$')

IP_PATTERN = re.compile(r'\b(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b')
PORT_PATTERN = re.compile(r'\bport\s+(?P<port>\d+)\b', re.IGNORECASE)
USER_PATTERN = re.compile(r'\b(?:user(?:=|\s+)|for\s+)(?P<user>[A-Za-z0-9_-]+)\b', re.IGNORECASE)

class SyslogParser(BaseParser):
    name = "syslog"
    display_name = "Standard Syslog"
    vendor = "IETF (RFC 5424/3164)"
    format = "syslog"
    version = "1.0"
    supported_source = "syslog_host"
    description = "RFC5424/RFC3164 standard syslog and authentication event parser"
    supported_fields = [
        "source_ip", "source_port", "hostname", "user", "severity",
        "priority", "action", "outcome", "category", "event_type"
    ]
    mapping_file = None
    status = "Active"

    def can_parse(self, text: str) -> bool:
        return bool(PATTERN.search(text.strip()))

    def parse_line(self, line: str):
        m = PATTERN.search(line.strip())
        if not m:
            raise ValueError("Not a valid syslog line")
        d = m.groupdict()
        pri = int(d["pri"]) if d["pri"] else None
        severity = None
        if pri is not None:
            severity = str(pri % 8)

        msg = d["msg"]
        lower_msg = msg.lower()

        out = {
            "timestamp": d["ts"],
            "hostname": d["host"],
            "message": msg,
            "severity": severity,
            "priority": pri,
            "category": "system",
            "event_type": "log",
        }

        # IP extraction from message
        ip_matches = IP_PATTERN.findall(msg)
        if ip_matches:
            out["source_ip"] = ip_matches[0]

        # Port extraction
        port_match = PORT_PATTERN.search(msg)
        if port_match:
            try:
                out["source_port"] = int(port_match.group("port"))
            except ValueError:
                pass

        # User extraction
        user_match = USER_PATTERN.search(msg)
        if user_match:
            candidate_user = user_match.group("user")
            if candidate_user.lower() not in {"from", "port", "invalid", "password"}:
                out["user"] = candidate_user

        # Outcome & action detection
        if any(w in lower_msg for w in ("failed", "failure", "denied", "error", "rejected")):
            out["outcome"] = "failure"
            out["action"] = "deny"
        elif any(w in lower_msg for w in ("success", "successful", "accepted", "built", "allowed")):
            out["outcome"] = "success"
            out["action"] = "allow"

        if any(w in lower_msg for w in ("sshd", "login", "password", "auth")):
            out["category"] = "authentication"
            out["event_type"] = "user_login"

        return out
