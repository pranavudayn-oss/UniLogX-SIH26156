from datetime import datetime, timezone
from typing import Optional

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def normalize_timestamp(value: Optional[str], context_year: Optional[int] = None) -> Optional[str]:
    if not value:
        return None
    text = str(value).strip()
    year_to_use = context_year or datetime.now(timezone.utc).year

    # Common formats with explicit year
    explicit_year_formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
        "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S",
        "%b %d %Y %H:%M:%S",
    ]
    for fmt in explicit_year_formats:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    # Yearless formats (e.g. Syslog RFC3164 / Cisco ASA: "Sep 26 10:20:01" or "Sep  4 10:20:01")
    yearless_formats = [
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
    ]
    # Normalize double space in month-day if present
    normalized_spaces = " ".join(text.split())
    for fmt in yearless_formats:
        for candidate_str in (text, normalized_spaces):
            try:
                dt = datetime.strptime(candidate_str, fmt)
                dt = dt.replace(year=year_to_use)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            except ValueError:
                pass

    return text
