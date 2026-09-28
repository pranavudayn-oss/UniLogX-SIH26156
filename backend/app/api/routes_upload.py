import uuid
from fastapi import APIRouter, UploadFile, File, HTTPException
from ..core.ingestion import read_text_lines
from ..core.pipeline import process_lines
from ..config import RAW_LOG_DIR
from ..schemas.upload_schema import UploadResponse
from ..utils.file_utils import safe_filename
from ..utils.timestamp_utils import now_iso
from ..services.storage_service import store_raw_log

router = APIRouter(tags=["ingestion"])


@router.post(
    "/upload",
    response_model=UploadResponse,
    summary="Ingest and process log file",
    description=(
        "Accepts raw log files (.log, .txt, .json, .csv) for ingestion through the UniLogX pipeline.\n\n"
        "**Workflow Stages Triggered:**\n"
        "1. **Raw Log Preservation:** Exact raw bytes are written untouched to partitioned local storage "
        "(`raw_logs/YYYY/MM/DD/<ingestion_id>/<filename>`) and assigned a SHA-256 fingerprint.\n"
        "2. **Format Detection:** Inspects content and headers to identify log format (Cisco ASA, Nginx, CloudTrail JSON, Syslog, Generic KV).\n"
        "3. **Parser Selection:** Routes to the matching plug-and-play parser plugin.\n"
        "4. **Field Extraction & Normalization:** Maps native vendor fields into the unified ECS-aligned schema.\n"
        "5. **Traceability:** Links each event with `event_id`, `trace_id`, `raw_hash`, `raw_path`, and pipeline timestamps.\n"
        "6. **Enrichment:** Deterministic offline port-to-service mapping.\n"
        "7. **Validation & Storage:** Validates schema integrity; valid events are stored in the database, "
        "while unrecognized or malformed logs are quarantined for forensic review."
    ),
    response_description="Ingestion execution summary including total lines, processed count, quarantined count, and assigned IDs.",
    status_code=200,
    responses={
        400: {
            "description": "Validation error — uploaded file is missing a filename or content cannot be read.",
            "content": {"application/json": {"example": {"detail": "Filename is required"}}},
        },
    },
)
async def upload_log(file: UploadFile = File(..., description="Multipart log file upload (.log, .txt, .json, .csv)")):
    if not file.filename:
        raise HTTPException(400, "Filename is required")
    content = await file.read()
    name = safe_filename(file.filename)
    ingestion_id = f"ingest-{uuid.uuid4().hex[:8]}"
    ingested_at = now_iso()

    # Legacy flat copy for backward compatibility
    try:
        (RAW_LOG_DIR / name).write_bytes(content)
    except Exception:
        pass

    # Organized date- and ingestion-partitioned raw log storage
    _, rel_path, _ = store_raw_log(
        content=content,
        ingestion_id=ingestion_id,
        filename=name,
        timestamp_or_date=ingested_at,
    )

    # Decode according to format (.log, .txt, .json, .csv)
    lines = read_text_lines(content, name)
    result = process_lines(
        lines=lines,
        source_file=name,
        ingestion_id=ingestion_id,
        ingested_at=ingested_at,
        raw_path=rel_path,
    )

    detected = "mixed/unknown"
    if result["parser_counts"]:
        detected = max(result["parser_counts"], key=result["parser_counts"].get)
    parser = detected

    return UploadResponse(
        filename=name,
        detected_format=detected,
        parser=parser,
        total_lines=len(lines),
        processed=result["processed"],
        quarantined=result["quarantined"],
        event_ids=result["event_ids"],
        ingestion_id=ingestion_id,
        raw_path=rel_path,
    )
