from typing import Any, Optional

# Deterministic offline port-to-service mapping (Canonical uppercase display names)
PORT_TO_SERVICE: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-ALT",
    8080: "HTTP-Proxy",
    8443: "HTTPS-ALT",
    9200: "OpenSearch",
}

# Backward-compatible lowercase lookup dictionary
PORT_SERVICES: dict[int, str] = {port: name.lower() for port, name in PORT_TO_SERVICE.items()}


def lookup_port_service(port: Any) -> Optional[str]:
    """
    Offline deterministic lookup of a well-known network port to its standard service name.
    Returns canonical uppercase service name (e.g., 443 -> 'HTTPS', 22 -> 'SSH', 3306 -> 'MySQL').
    Returns None if port is unknown, invalid, or unmapped.
    """
    try:
        p = int(port)
        return PORT_TO_SERVICE.get(p)
    except (ValueError, TypeError):
        return None


def enrich(event: dict) -> dict:
    """
    Offline deterministic enrichment for normalized events.
    - Preserves all original numeric ports without modification.
    - Preserves raw event evidence without modification.
    - Classifies RFC 1918 private vs public IP scope.
    - Enriches destination.port and source.port with well-known service names.
    """
    # 1. Source IP Scope Classification (offline RFC 1918)
    ip = event.get("source_ip")
    if ip:
        event["source_ip_scope"] = "private" if str(ip).startswith((
            "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
        )) else "public_or_unknown"

    # 2. Destination Port Service Enrichment
    dst_port = event.get("destination_port")
    if dst_port is None and isinstance(event.get("destination"), dict):
        dst_port = event["destination"].get("port")

    dst_service = lookup_port_service(dst_port)
    if dst_service:
        # Maintain backward-compatible lowercase alias
        event["destination_service"] = dst_service.lower()
        # Add to structured destination object
        if isinstance(event.get("destination"), dict):
            event["destination"]["service"] = dst_service

    # 3. Source Port Service Enrichment
    src_port = event.get("source_port")
    if src_port is None and isinstance(event.get("source"), dict):
        src_port = event["source"].get("port")

    src_service = lookup_port_service(src_port)
    if src_service:
        # Maintain backward-compatible lowercase alias
        event["source_service"] = src_service.lower()
        # Add to structured source object
        if isinstance(event.get("source"), dict):
            event["source"]["service"] = src_service

    return event
