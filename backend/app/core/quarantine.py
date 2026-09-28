from typing import Optional
from ..database import get_connection
from ..config import QUARANTINE_DIR
from ..utils.hash_utils import sha256_text
from ..utils.timestamp_utils import now_iso

def quarantine(
    raw_text: str,
    reason: str,
    source_file: Optional[str] = None,
    source_type: str = "unknown",
    line_number: Optional[int] = None,
    ingestion_id: Optional[str] = None,
    parser_attempted: Optional[str] = None,
    status: str = "quarantined",
    raw_path: Optional[str] = None,
) -> str:
    raw_hash = sha256_text(raw_text)
    path = QUARANTINE_DIR / f"{raw_hash}.log"
    try:
        path.write_text(raw_text, encoding="utf-8")
    except Exception:
        pass

    stored_raw_path = raw_path or f"quarantine/{raw_hash}.log"

    with get_connection() as conn:
        conn.execute(
            """INSERT INTO quarantines(
                ingestion_id, source_file, source_type, line_number,
                parser_attempted, status, reason, raw_text, raw_hash, raw_path, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ingestion_id,
                source_file,
                source_type,
                line_number,
                parser_attempted,
                status,
                reason,
                raw_text,
                raw_hash,
                stored_raw_path,
                now_iso(),
            ),
        )
    return raw_hash

def reprocess_quarantine(quarantine_id: Optional[int] = None) -> dict:
    from .pipeline import process_lines

    with get_connection() as conn:
        if quarantine_id is not None:
            record = conn.execute("SELECT * FROM quarantines WHERE id = ?", (quarantine_id,)).fetchone()
            if not record:
                return {
                    "reprocessed": 0,
                    "failed": 0,
                    "error": "not_found",
                    "total_attempted": 0,
                    "message": f"Quarantine record #{quarantine_id} not found",
                }
            rows = [record]
        else:
            rows = conn.execute(
                "SELECT * FROM quarantines WHERE status = 'quarantined'"
            ).fetchall()

    if not rows:
        return {"reprocessed": 0, "failed": 0, "total_attempted": 0, "message": "No quarantined items to reprocess"}

    reprocessed = 0
    failed = 0
    reprocessed_ids = []

    for r in rows:
        row_id = r["id"]
        raw = r["raw_text"]
        source_file = r["source_file"] or "reprocess"

        # Record max quarantine id before running pipeline to avoid duplicate evidence rows on failure
        with get_connection() as conn:
            max_q_before = conn.execute("SELECT COALESCE(MAX(id), 0) FROM quarantines").fetchone()[0]

        res = process_lines(
            [raw],
            source_file=f"reprocessed_{source_file}",
            ingestion_id=r["ingestion_id"],
            raw_path=r["raw_path"] if "raw_path" in r.keys() else None,
        )
        
        if res.get("processed", 0) > 0:
            reprocessed += 1
            reprocessed_ids.append(row_id)
            with get_connection() as conn:
                conn.execute(
                    "UPDATE quarantines SET status = 'reprocessed' WHERE id = ?",
                    (row_id,),
                )
        else:
            failed += 1
            # Deduplicate any duplicate entry created by pipeline during failed reprocess
            with get_connection() as conn:
                conn.execute(
                    "DELETE FROM quarantines WHERE id > ? AND raw_hash = ?",
                    (max_q_before, r["raw_hash"]),
                )

    return {
        "reprocessed": reprocessed,
        "failed": failed,
        "reprocessed_ids": reprocessed_ids,
        "total_attempted": len(rows),
    }
