from pydantic import BaseModel
from typing import Optional

class UploadResponse(BaseModel):
    filename: str
    detected_format: str
    parser: str
    total_lines: int
    processed: int
    quarantined: int
    event_ids: list[str]
    ingestion_id: str = ""
    raw_path: Optional[str] = None
