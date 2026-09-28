import ipaddress
from typing import Optional

def normalize_ip(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().strip("[]")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text or None
