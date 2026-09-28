from typing import Any, Optional
from ..utils.ip_utils import normalize_ip
from ..utils.timestamp_utils import normalize_timestamp

FIELD_ALIASES = {
    "src": "source_ip", "src_ip": "source_ip", "client_ip": "source_ip",
    "sourceAddress": "source_ip", "sourceIPAddress": "source_ip", "origin": "source_ip",

    "dst": "destination_ip", "dst_ip": "destination_ip", "destinationAddress": "destination_ip",
    "targetIPAddress": "destination_ip", "target": "destination_ip", "server_ip": "destination_ip",

    "srcport": "source_port", "src_port": "source_port", "sourcePort": "source_port", "spt": "source_port",
    "dstport": "destination_port", "dst_port": "destination_port", "destinationPort": "destination_port", "dpt": "destination_port",

    "time": "timestamp", "eventTime": "timestamp", "date": "timestamp",
    "msg": "message", "log": "message", "description": "message",
    "userName": "user", "username": "user", "principal": "user",

    "proto": "transport", "protocol": "transport",
    "act": "action", "verdict": "action", "method": "action",
    "status": "outcome", "result": "outcome",
}

def _safe_int(v):
    try:
        i = int(str(v).strip())
        return i if 0 <= i <= 65535 else None
    except Exception:
        return None

def normalize(parsed: dict[str, Any], source_type: str, parser_name: str, context_year: Optional[int] = None) -> dict[str, Any]:
    out = {
        "source_type": source_type,
        "parser": parser_name,
        "category": parsed.get("category", "general"),
        "event_type": parsed.get("event_type", "log"),
    }
    extras = {}

    for key, value in parsed.items():
        canonical = FIELD_ALIASES.get(key, key)
        if canonical in {"source_ip", "destination_ip"}:
            norm_ip = normalize_ip(value)
            out[canonical] = norm_ip if norm_ip else value
        elif canonical == "timestamp":
            out[canonical] = normalize_timestamp(value, context_year=context_year)
        elif canonical in {"source_port", "destination_port"}:
            out[canonical] = _safe_int(value)
        elif canonical == "transport":
            out[canonical] = str(value).upper()
        elif canonical in {"raw_fields"}:
            extras.update(value if isinstance(value, dict) else {canonical: value})
        elif canonical in {"event_id", "trace_id", "raw_hash"}:
            continue
        else:
            out[canonical] = value

    # Action & Outcome Normalization
    action_raw = str(out.get("action") or "").lower()
    if action_raw in {"deny", "denied", "block", "blocked", "drop", "dropped", "reject"}:
        out["action"] = "denied"
        out.setdefault("outcome", "failure")
    elif action_raw in {"allow", "allowed", "permit", "permitted", "accept", "accepted", "built"}:
        out["action"] = "allowed"
        out.setdefault("outcome", "success")

    if "outcome" in out:
        text = str(out["outcome"]).lower()
        if text in {"0", "200", "201", "202", "204", "success", "succeeded", "ok", "allowed"}:
            out["outcome"] = "success"
        elif text in {"400", "401", "403", "404", "500", "502", "503", "failure", "failed", "error", "denied", "accessdenied"}:
            out["outcome"] = "failure"

    # Common canonical structured layout (PDF Spec)
    ts = out.get("timestamp")
    out["@timestamp"] = ts
    out["event"] = {
        "category": out.get("category", "general"),
        "type": out.get("event_type", "log"),
        "outcome": out.get("outcome", "unknown"),
    }
    out["source"] = {
        "ip": out.get("source_ip"),
        "port": out.get("source_port"),
    }
    out["destination"] = {
        "ip": out.get("destination_ip"),
        "port": out.get("destination_port"),
    }
    out["network"] = {
        "transport": out.get("transport"),
        "action": out.get("action"),
    }

    if extras:
        out["extra_fields"] = extras
    return out
