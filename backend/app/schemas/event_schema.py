from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict

class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: str
    trace_id: str
    timestamp: Optional[str] = None
    source_type: str
    parser: str
    parser_version: Optional[str] = "1.0"
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    category: Optional[str] = None
    transport: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    message: Optional[str] = None
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    ingested_at: Optional[str] = None
    processed_at: Optional[str] = None
    raw_hash: str
    raw_event: Any
    raw_path: Optional[str] = None
