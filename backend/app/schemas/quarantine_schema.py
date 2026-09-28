from typing import Optional
from pydantic import BaseModel, Field

class QuarantineRecord(BaseModel):
    id: int = Field(..., description="Unique internal database ID of the quarantine record", examples=[1])
    ingestion_id: Optional[str] = Field(None, description="Ingestion batch identifier", examples=["ingest-a1b2c3d4"])
    source_file: Optional[str] = Field(None, description="Original source filename uploaded or ingested", examples=["bad_payload.log"])
    source_type: Optional[str] = Field("unknown", description="Detected or default source category", examples=["unknown"])
    line_number: Optional[int] = Field(None, description="1-indexed line position in the source file", examples=[42])
    parser_attempted: Optional[str] = Field(None, description="Parser that attempted and failed extraction, or 'none'", examples=["cisco_asa"])
    status: str = Field("quarantined", description="Current status: 'quarantined' or 'reprocessed'", examples=["quarantined"])
    reason: str = Field(..., description="Root-cause diagnostic error describing why the log failed validation or parsing", examples=["No matching parser found (No matching format detected)"])
    raw_text: str = Field(..., description="Exact, untouched original raw log line preserved as evidence", examples=["CUSTOM_DEVICE_100: invalid log"])
    raw_hash: str = Field(..., description="SHA-256 cryptographic digest of the raw log text", examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])
    raw_path: Optional[str] = Field(None, description="Relative logical path to the preserved raw evidence file", examples=["raw_logs/2026/09/27/ingest-a1b2c3d4/bad_payload.log"])
    created_at: str = Field(..., description="ISO 8601 timestamp of quarantine insertion", examples=["2026-09-27T10:30:00Z"])


class ReprocessResponse(BaseModel):
    reprocessed: int = Field(..., description="Number of quarantined records successfully parsed and promoted to events", examples=[3])
    failed: int = Field(..., description="Number of quarantined records that still failed parsing", examples=[0])
    reprocessed_ids: list[int] = Field(default_factory=list, description="IDs of quarantine records that were updated to 'reprocessed'", examples=[[1, 2, 3]])
    total_attempted: int = Field(..., description="Total quarantine records evaluated during the run", examples=[3])
