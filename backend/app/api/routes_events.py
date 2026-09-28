from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Path as FastAPIPath
from fastapi.responses import FileResponse
from ..services.event_service import list_events, get_event
from ..services.export_service import export_csv, export_json

router = APIRouter(tags=["events"])


@router.get(
    "/events",
    summary="List and search normalized events",
    description=(
        "Unified search across all normalized events stored in the UniLogX database.\n\n"
        "**Search Capabilities:**\n"
        "- **Free-Text Search:** Pass arbitrary terms to search across messages, IPs, and payload data.\n"
        "- **Field-Specific Queries via `q`:** Supports `field=value` and `field:value` syntax with Elastic Common Schema (ECS) aliases "
        "(e.g. `source.ip=10.0.0.1`, `destination.port=443`, `network.transport=TCP`, `outcome=failure`, `event.category=web`).\n"
        "- **Dedicated Filter Query Parameters:** Combine structured parameters (`source_ip`, `destination_ip`, `parser`, `outcome`, etc.) for precise filtering.\n"
        "- **Time Range Filtering:** Limit events with `timestamp_from` and `timestamp_to` ISO strings."
    ),
    response_description="Array of normalized event objects with full forensic provenance and original raw logs.",
    status_code=200,
)
def events(
    q: Optional[str] = Query(None, description="Free-text or field=value search (e.g. source.ip=10.0.0.1 outcome=failure)"),
    source: Optional[str] = Query(None, description="Filter by source domain (firewall, web_server, cloud_provider, syslog_host, network_device)"),
    severity: Optional[str] = Query(None, description="Filter by syslog severity level"),
    outcome: Optional[str] = Query(None, description="Filter by event outcome verdict (success, failure, unknown)"),
    category: Optional[str] = Query(None, description="Filter by ECS event category (network, web, cloud, authentication, system)"),
    source_ip: Optional[str] = Query(None, description="Filter by origin IP address"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP address"),
    source_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by source network port (0-65535)"),
    destination_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by destination network port (0-65535)"),
    transport: Optional[str] = Query(None, description="Filter by network transport protocol (TCP, UDP, ICMP)"),
    action: Optional[str] = Query(None, description="Filter by network action (allowed, denied, allow, deny)"),
    event_type: Optional[str] = Query(None, description="Filter by event type classifier (access, connection, iam_activity, authentication)"),
    parser: Optional[str] = Query(None, description="Filter by originating parser name (cisco_asa, nginx, cloud_json, syslog, generic_kv)"),
    timestamp_from: Optional[str] = Query(None, description="Filter events occurring on or after this ISO timestamp"),
    timestamp_to: Optional[str] = Query(None, description="Filter events occurring on or before this ISO timestamp"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of events to return (1-500)"),
):
    # Safely extract values if route function is called directly in Python tests
    val_q = q if isinstance(q, str) else None
    val_source = source if isinstance(source, str) else None
    val_severity = severity if isinstance(severity, str) else None
    val_outcome = outcome if isinstance(outcome, str) else None
    val_category = category if isinstance(category, str) else None
    val_source_ip = source_ip if isinstance(source_ip, str) else None
    val_destination_ip = destination_ip if isinstance(destination_ip, str) else None
    val_source_port = source_port if isinstance(source_port, int) else None
    val_destination_port = destination_port if isinstance(destination_port, int) else None
    val_transport = transport if isinstance(transport, str) else None
    val_action = action if isinstance(action, str) else None
    val_event_type = event_type if isinstance(event_type, str) else None
    val_parser = parser if isinstance(parser, str) else None
    val_timestamp_from = timestamp_from if isinstance(timestamp_from, str) else None
    val_timestamp_to = timestamp_to if isinstance(timestamp_to, str) else None
    val_limit = limit if isinstance(limit, int) else 100

    return list_events(
        q=val_q,
        source=val_source,
        severity=val_severity,
        outcome=val_outcome,
        category=val_category,
        source_ip=val_source_ip,
        destination_ip=val_destination_ip,
        source_port=val_source_port,
        destination_port=val_destination_port,
        transport=val_transport,
        action=val_action,
        event_type=val_event_type,
        parser=val_parser,
        timestamp_from=val_timestamp_from,
        timestamp_to=val_timestamp_to,
        limit=val_limit,
    )


@router.get(
    "/events/export/csv",
    summary="Export filtered events as CSV",
    description=(
        "Exports events matching the active search criteria as a formatted CSV file.\n\n"
        "**Traceability & Forensics:**\n"
        "- Includes full chain-of-custody headers: `event_id`, `trace_id`, `raw_hash`, `raw_path`, `ingested_at`, `processed_at`, `source_file`, `line_number`.\n"
        "- Includes primary normalized fields: `source_ip`, `destination_ip`, `source_port`, `destination_port`, `transport`, `action`, `outcome`, `severity`, `message`.\n"
        "- Preserves full normalized structure as JSON text in `normalized_json` column.\n"
        "- Preserves untouched raw log line in `raw_event` column.\n"
        "- Strictly respects all active query filters (does not dump entire database when filters are active)."
    ),
    response_description="Streamed CSV file attachment with complete evidence headers.",
    status_code=200,
)
def export_events_csv(
    q: Optional[str] = Query(None, description="Free-text or field=value query"),
    source: Optional[str] = Query(None, description="Filter by source domain"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    outcome: Optional[str] = Query(None, description="Filter by event outcome verdict"),
    category: Optional[str] = Query(None, description="Filter by ECS category"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    source_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by source port"),
    destination_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by destination port"),
    transport: Optional[str] = Query(None, description="Filter by network transport"),
    action: Optional[str] = Query(None, description="Filter by network action"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    parser: Optional[str] = Query(None, description="Filter by parser name"),
    timestamp_from: Optional[str] = Query(None, description="Filter events on or after timestamp"),
    timestamp_to: Optional[str] = Query(None, description="Filter events on or before timestamp"),
):
    val_q = q if isinstance(q, str) else None
    val_source = source if isinstance(source, str) else None
    val_severity = severity if isinstance(severity, str) else None
    val_outcome = outcome if isinstance(outcome, str) else None
    val_category = category if isinstance(category, str) else None
    val_source_ip = source_ip if isinstance(source_ip, str) else None
    val_destination_ip = destination_ip if isinstance(destination_ip, str) else None
    val_source_port = source_port if isinstance(source_port, int) else None
    val_destination_port = destination_port if isinstance(destination_port, int) else None
    val_transport = transport if isinstance(transport, str) else None
    val_action = action if isinstance(action, str) else None
    val_event_type = event_type if isinstance(event_type, str) else None
    val_parser = parser if isinstance(parser, str) else None
    val_timestamp_from = timestamp_from if isinstance(timestamp_from, str) else None
    val_timestamp_to = timestamp_to if isinstance(timestamp_to, str) else None

    evts = list_events(
        q=val_q, source=val_source, severity=val_severity, outcome=val_outcome, category=val_category,
        source_ip=val_source_ip, destination_ip=val_destination_ip,
        source_port=val_source_port, destination_port=val_destination_port,
        transport=val_transport, action=val_action, event_type=val_event_type,
        parser=val_parser, timestamp_from=val_timestamp_from, timestamp_to=val_timestamp_to,
        limit=5000,
    )
    path = export_csv(evts)
    return FileResponse(path, media_type="text/csv", filename="unilogx-events.csv")


@router.get(
    "/events/export/json",
    summary="Export filtered events as JSON",
    description=(
        "Exports events matching the active search criteria as a structured JSON array.\n\n"
        "**Schema Integrity:**\n"
        "- Each exported element is a complete, structured JSON object (not flattened or double-escaped).\n"
        "- Preserves top-level metadata: `event_id`, `trace_id`, `raw_hash`, `raw_path`, `parser`, `source_type`.\n"
        "- Preserves `normalized` sub-dictionary with ECS-aligned security fields.\n"
        "- Preserves untouched original log line in `raw_event`.\n"
        "- Strictly respects all active query filters."
    ),
    response_description="Streamed JSON array file attachment.",
    status_code=200,
)
def export_events_json(
    q: Optional[str] = Query(None, description="Free-text or field=value query"),
    source: Optional[str] = Query(None, description="Filter by source domain"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    outcome: Optional[str] = Query(None, description="Filter by event outcome verdict"),
    category: Optional[str] = Query(None, description="Filter by ECS category"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    source_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by source port"),
    destination_port: Optional[int] = Query(None, ge=0, le=65535, description="Filter by destination port"),
    transport: Optional[str] = Query(None, description="Filter by network transport"),
    action: Optional[str] = Query(None, description="Filter by network action"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    parser: Optional[str] = Query(None, description="Filter by parser name"),
    timestamp_from: Optional[str] = Query(None, description="Filter events on or after timestamp"),
    timestamp_to: Optional[str] = Query(None, description="Filter events on or before timestamp"),
):
    val_q = q if isinstance(q, str) else None
    val_source = source if isinstance(source, str) else None
    val_severity = severity if isinstance(severity, str) else None
    val_outcome = outcome if isinstance(outcome, str) else None
    val_category = category if isinstance(category, str) else None
    val_source_ip = source_ip if isinstance(source_ip, str) else None
    val_destination_ip = destination_ip if isinstance(destination_ip, str) else None
    val_source_port = source_port if isinstance(source_port, int) else None
    val_destination_port = destination_port if isinstance(destination_port, int) else None
    val_transport = transport if isinstance(transport, str) else None
    val_action = action if isinstance(action, str) else None
    val_event_type = event_type if isinstance(event_type, str) else None
    val_parser = parser if isinstance(parser, str) else None
    val_timestamp_from = timestamp_from if isinstance(timestamp_from, str) else None
    val_timestamp_to = timestamp_to if isinstance(timestamp_to, str) else None

    evts = list_events(
        q=val_q, source=val_source, severity=val_severity, outcome=val_outcome, category=val_category,
        source_ip=val_source_ip, destination_ip=val_destination_ip,
        source_port=val_source_port, destination_port=val_destination_port,
        transport=val_transport, action=val_action, event_type=val_event_type,
        parser=val_parser, timestamp_from=val_timestamp_from, timestamp_to=val_timestamp_to,
        limit=5000,
    )
    path = export_json(evts)
    return FileResponse(path, media_type="application/json", filename="unilogx-events.json")


@router.get(
    "/events/{event_id}",
    summary="Get a single event by ID",
    description=(
        "Retrieves a single event record by its unique identifier (`event_id`).\n\n"
        "Returns the complete normalized representation, the original untouched raw log, "
        "and comprehensive forensic traceability metadata (SHA-256 fingerprint, partition path, parser version, ingestion timestamps)."
    ),
    response_description="Complete forensic event record object.",
    status_code=200,
    responses={
        404: {
            "description": "Event ID not found in database.",
            "content": {"application/json": {"example": {"detail": "Event not found"}}},
        },
    },
)
def event(
    event_id: str = FastAPIPath(..., description="Unique event identifier (e.g. evt-123456789abc)", examples=["evt-123456789abc"])
):
    result = get_event(event_id)
    if not result:
        raise HTTPException(404, "Event not found")
    return result
