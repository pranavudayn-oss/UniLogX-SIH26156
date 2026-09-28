import uuid
from typing import Optional
from ..utils.hash_utils import sha256_text

def build_trace(raw_text: str):
    raw_hash = sha256_text(raw_text)
    return str(uuid.uuid4()), raw_hash

def build_traceability_metadata(
    event_id: str,
    trace_id: str,
    raw_text: str,
    raw_hash: str,
    parser_name: str,
    parser_version: str = "1.0",
    source_file: str = "upload",
    line_number: Optional[int] = None,
    ingested_at: Optional[str] = None,
    processed_at: Optional[str] = None,
    raw_path: Optional[str] = None,
) -> dict:
    meta = {
        "event": {
            "id": event_id,
            "original": raw_text,
            "hash": f"sha256:{raw_hash}",
        },
        "ulx": {
            "parser_name": parser_name,
            "parser_version": parser_version,
            "source_file": source_file,
            "line_number": line_number,
            "ingested_at": ingested_at,
            "processed_at": processed_at,
        }
    }
    if raw_path:
        meta["ulx"]["raw_path"] = raw_path
    return meta
