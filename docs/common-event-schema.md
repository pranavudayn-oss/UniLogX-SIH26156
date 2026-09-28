# Common Event Schema

Core fields: event_id, trace_id, timestamp, source_type, parser, severity, source_ip, destination_ip, source_port, destination_port, user, action, outcome, message, raw_hash, raw_event.

Unknown source-specific attributes are retained under `extra_fields` when the parser exposes them.
