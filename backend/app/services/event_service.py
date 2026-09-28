import json
import re
from typing import Optional
from ..database import get_connection

def list_events(
    q: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    outcome: Optional[str] = None,
    category: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    transport: Optional[str] = None,
    action: Optional[str] = None,
    event_type: Optional[str] = None,
    parser: Optional[str] = None,
    timestamp_from: Optional[str] = None,
    timestamp_to: Optional[str] = None,
    limit: int = 100,
):
    clauses = []
    params = []

    # Handle structured field queries from `q`
    # Supports: field=value or field:value syntax for all normalized fields
    free_text_terms = []
    FIELD_MAP = {
        # source IP aliases
        "source.ip": ("source_ip", "eq"),
        "source_ip": ("source_ip", "eq"),
        "src": ("source_ip", "eq"),
        "src_ip": ("source_ip", "eq"),
        "client_ip": ("source_ip", "eq"),
        "sourceipaddress": ("source_ip", "eq"),
        # destination IP aliases
        "destination.ip": ("destination_ip", "eq"),
        "destination_ip": ("destination_ip", "eq"),
        "dst": ("destination_ip", "eq"),
        "dst_ip": ("destination_ip", "eq"),
        "dest.ip": ("destination_ip", "eq"),
        # source port
        "source.port": ("source_port", "eq_int"),
        "source_port": ("source_port", "eq_int"),
        "src.port": ("source_port", "eq_int"),
        "spt": ("source_port", "eq_int"),
        "sport": ("source_port", "eq_int"),
        # destination port
        "destination.port": ("destination_port", "eq_int"),
        "destination_port": ("destination_port", "eq_int"),
        "dst.port": ("destination_port", "eq_int"),
        "dpt": ("destination_port", "eq_int"),
        "dport": ("destination_port", "eq_int"),
        # category
        "event.category": ("category", "eq_lower"),
        "category": ("category", "eq_lower"),
        # event type
        "event.type": ("normalized_json", "json_like"),
        "event_type": ("normalized_json", "json_like"),
        # outcome
        "event.outcome": ("outcome", "eq_lower"),
        "outcome": ("outcome", "eq_lower"),
        # transport
        "network.transport": ("transport", "eq_upper"),
        "transport": ("transport", "eq_upper"),
        "proto": ("transport", "eq_upper"),
        # action
        "network.action": ("action", "eq_lower"),
        "action": ("action", "eq_lower"),
        # parser
        "parser": ("parser_name", "eq"),
        "parser.name": ("parser_name", "eq"),
        # trace
        "trace.id": ("trace_id", "like"),
        "trace_id": ("trace_id", "like"),
        "trace": ("trace_id", "like"),
        # event id
        "event.id": ("event_id", "eq"),
        "event_id": ("event_id", "eq"),
        "id": ("event_id", "eq"),
        # source type
        "source": ("source_type", "eq"),
        "source_type": ("source_type", "eq"),
        # timestamp
        "timestamp_from": ("timestamp", "gte"),
        "timestamp_to": ("timestamp", "lte"),
        "after": ("timestamp", "gte"),
        "before": ("timestamp", "lte"),
    }

    if q:
        tokens = q.strip().split()
        for token in tokens:
            m = re.match(r'^([\w.]+)[=:](.+)$', token)
            if m:
                field_key = m.group(1).lower()
                val = m.group(2).strip()
                if field_key in FIELD_MAP:
                    col, op = FIELD_MAP[field_key]
                    if op == "eq":
                        clauses.append(f"{col} = ?")
                        params.append(val)
                    elif op == "eq_lower":
                        clauses.append(f"{col} = ?")
                        params.append(val.lower())
                    elif op == "eq_upper":
                        clauses.append(f"{col} = ?")
                        params.append(val.upper())
                    elif op == "eq_int":
                        try:
                            parsed_int = int(val)
                            clauses.append(f"{col} = ?")
                            params.append(parsed_int)
                        except ValueError:
                            free_text_terms.append(token)
                    elif op == "like":
                        clauses.append(f"{col} LIKE ?")
                        params.append(f"%{val}%")
                    elif op == "json_like":
                        clauses.append("normalized_json LIKE ?")
                        params.append(f"%{val}%")
                    elif op == "gte":
                        clauses.append(f"{col} >= ?")
                        params.append(val)
                    elif op == "lte":
                        clauses.append(f"{col} <= ?")
                        params.append(val)
                else:
                    free_text_terms.append(token)
            else:
                free_text_terms.append(token)

    if free_text_terms:
        combined_term = " ".join(free_text_terms)
        clauses.append(
            "(message LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR trace_id LIKE ? OR event_id LIKE ? OR normalized_json LIKE ?)"
        )
        params += [f"%{combined_term}%"] * 6

    # Dedicated filter params (complement q parsing)
    if source:
        clauses.append("source_type = ?")
        params.append(source)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome.lower())
    if category:
        clauses.append("category = ?")
        params.append(category.lower())
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    if destination_ip:
        clauses.append("destination_ip = ?")
        params.append(destination_ip)
    if source_port is not None:
        clauses.append("source_port = ?")
        params.append(source_port)
    if destination_port is not None:
        clauses.append("destination_port = ?")
        params.append(destination_port)
    if transport:
        clauses.append("transport = ?")
        params.append(transport.upper())
    if action:
        clauses.append("action = ?")
        params.append(action.lower())
    if event_type:
        clauses.append("normalized_json LIKE ?")
        params.append(f"%{event_type}%")
    if parser:
        clauses.append("parser_name = ?")
        params.append(parser)
    if timestamp_from:
        clauses.append("timestamp >= ?")
        params.append(timestamp_from)
    if timestamp_to:
        clauses.append("timestamp <= ?")
        params.append(timestamp_to)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM events{where} ORDER BY created_at DESC LIMIT ?",
            (*params, min(max(limit, 1), 500)),
        ).fetchall()

    events = []
    for r in rows:
        item = dict(r)
        try:
            norm = json.loads(item["normalized_json"])
        except Exception:
            norm = {}
        item["normalized"] = norm
        try:
            raw_val = json.loads(item["raw_json"]) if item.get("raw_json") else None
            item["raw_event"] = raw_val if raw_val is not None else norm.get("raw_event", "")
        except Exception:
            item["raw_event"] = item.get("raw_json") or norm.get("raw_event", "")
        events.append(item)
    return events

def get_event(event_id: str):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    try:
        d["normalized"] = json.loads(d["normalized_json"])
    except Exception:
        d["normalized"] = {}
    try:
        raw_val = json.loads(d["raw_json"]) if d.get("raw_json") else None
        d["raw_event"] = raw_val if raw_val is not None else d["normalized"].get("raw_event", "")
    except Exception:
        d["raw_event"] = d.get("raw_json") or d["normalized"].get("raw_event", "")
    return d

