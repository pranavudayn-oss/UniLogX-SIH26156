from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Path as FastAPIPath
from ..database import get_connection
from ..core.quarantine import reprocess_quarantine
from ..schemas.quarantine_schema import QuarantineRecord, ReprocessResponse

router = APIRouter(tags=["quarantine"])


@router.get(
    "/quarantine",
    response_model=List[QuarantineRecord],
    summary="List quarantined records",
    description=(
        "Retrieves log records that failed format detection, parser extraction, or schema validation.\n\n"
        "Each record preserves the exact, untouched raw log text, the diagnostic root-cause error reason, "
        "and provenance information (`source_file`, `line_number`, `ingestion_id`, `raw_path`, `raw_hash`)."
    ),
    response_description="Array of quarantined records with diagnostic failure details.",
    status_code=200,
)
def quarantines(
    limit: int = Query(100, ge=1, le=500, description="Maximum number of quarantine records to retrieve (1-500)"),
):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM quarantines ORDER BY created_at DESC LIMIT ?",
            (min(max(limit, 1), 500),)
        ).fetchall()
    return [dict(r) for r in rows]


@router.get(
    "/quarantine/{quarantine_id}",
    response_model=QuarantineRecord,
    summary="Get quarantine record details",
    description=(
        "Retrieves a single quarantined record by its internal database ID.\n\n"
        "Provides the untouched original log text, diagnostic root cause, parser attempted, "
        "and physical evidence storage path."
    ),
    response_description="Detailed forensic quarantine record.",
    status_code=200,
    responses={
        404: {
            "description": "Quarantine record ID not found in database.",
            "content": {"application/json": {"example": {"detail": "Quarantine record #999 not found"}}},
        },
    },
)
def quarantine_detail(
    quarantine_id: int = FastAPIPath(..., description="Unique database ID of the quarantine record", examples=[1]),
):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM quarantines WHERE id = ?", (quarantine_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Quarantine record #{quarantine_id} not found")
    return dict(row)


@router.post(
    "/quarantine/reprocess",
    response_model=ReprocessResponse,
    summary="Reprocess all quarantined records",
    description=(
        "Re-runs all pending quarantined records (`status = 'quarantined'`) through the active parser registry and normalization pipeline.\n\n"
        "Records that succeed are promoted to normalized events and their quarantine status updated to `'reprocessed'`, "
        "preserving the original raw evidence and audit history."
    ),
    response_description="Summary of reprocessing outcomes (counts reprocessed and failed).",
    status_code=200,
)
def reprocess_all():
    result = reprocess_quarantine()
    return result


@router.post(
    "/quarantine/{quarantine_id}/reprocess",
    response_model=ReprocessResponse,
    summary="Reprocess a single quarantined record",
    description=(
        "Re-runs a specific quarantined record through the detection and parsing pipeline.\n\n"
        "If parsing succeeds, creates a normalized event in the events store and updates status to `'reprocessed'`."
    ),
    response_description="Reprocessing outcome for the targeted record.",
    status_code=200,
    responses={
        404: {
            "description": "Quarantine record ID not found in database.",
            "content": {"application/json": {"example": {"detail": "Quarantine record #999 not found"}}},
        },
    },
)
def reprocess_one(
    quarantine_id: int = FastAPIPath(..., description="Unique database ID of the quarantine record to reprocess", examples=[1]),
):
    result = reprocess_quarantine(quarantine_id=quarantine_id)
    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail=f"Quarantine record #{quarantine_id} not found")
    return result
