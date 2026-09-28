from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class QuarantineSummary(BaseModel):
    total: int = Field(..., description="Total quarantine records ever captured", examples=[12])
    active: int = Field(..., description="Current pending quarantined records", examples=[2])
    reprocessed: int = Field(..., description="Quarantined records successfully reprocessed into events", examples=[10])
    by_reason: Dict[str, int] = Field(default_factory=dict, description="Distribution of quarantine events grouped by failure diagnosis", examples=[{"No matching parser found (No matching format detected)": 2}])


class RecentActivityItem(BaseModel):
    event_id: str = Field(..., description="Normalized event identifier", examples=["evt-abc123def456"])
    timestamp: Optional[str] = Field(None, description="Event occurrence timestamp", examples=["2026-09-27T10:30:00Z"])
    parser: str = Field(..., description="Parser that processed the event", examples=["cisco_asa"])
    source_type: str = Field(..., description="Event domain / source", examples=["firewall"])
    action: Optional[str] = Field(None, description="Network action verdict", examples=["allow"])
    outcome: Optional[str] = Field(None, description="Event outcome verdict", examples=["success"])
    category: Optional[str] = Field(None, description="ECS event category", examples=["network"])


class TimelineItem(BaseModel):
    time: str = Field(..., description="Time bucket interval (YYYY-MM-DD HH:MM)", examples=["2026-09-27 10:30"])
    count: int = Field(..., description="Number of events ingested in this time bucket", examples=[15])


class MetricsResponse(BaseModel):
    total_events: int = Field(..., description="Total successfully processed and normalized events in database", examples=[150])
    quarantined: int = Field(..., description="Active records currently isolated in quarantine", examples=[2])
    quarantined_events: int = Field(..., description="Alias for active quarantined count", examples=[2])
    total_quarantined: int = Field(..., description="Cumulative count of all records quarantined", examples=[12])
    reprocessed: int = Field(..., description="Count of quarantine records successfully reprocessed", examples=[10])
    parser_success_rate: float = Field(..., description="Percentage of processing attempts that succeeded: total / (total + active_quarantined) * 100", examples=[98.68])
    source_count: int = Field(..., description="Count of distinct log source types actively represented", examples=[4])
    sources: Dict[str, int] = Field(default_factory=dict, description="Count of events grouped by source type", examples=[{"firewall": 50, "web_server": 60, "cloud_provider": 40}])
    events_by_source: Dict[str, int] = Field(default_factory=dict, description="Explicit alias for events by source type")
    events_by_parser: Dict[str, int] = Field(default_factory=dict, description="Count of events grouped by parser name", examples=[{"cisco_asa": 50, "nginx": 60, "cloud_json": 40}])
    events_by_category: Dict[str, int] = Field(default_factory=dict, description="Count of events grouped by ECS category", examples=[{"network": 50, "web": 60, "cloud": 40}])
    events_by_outcome: Dict[str, int] = Field(default_factory=dict, description="Count of events grouped by security outcome verdict", examples=[{"success": 120, "failure": 30}])
    severities: Dict[str, int] = Field(default_factory=dict, description="Count of events grouped by syslog severity level")
    parsers: Dict[str, int] = Field(default_factory=dict, description="Backward-compatible alias for events_by_parser")
    categories: Dict[str, int] = Field(default_factory=dict, description="Backward-compatible alias for events_by_category")
    outcomes: Dict[str, int] = Field(default_factory=dict, description="Backward-compatible alias for events_by_outcome")
    quarantine_summary: QuarantineSummary = Field(..., description="Root-cause diagnostic breakdown of isolated logs")
    recent_activity: List[RecentActivityItem] = Field(default_factory=list, description="Latest normalized events stream with timestamps and verdicts")
    timeline: List[TimelineItem] = Field(default_factory=list, description="Time-series event volume intervals for trend charting")


# Legacy alias
Metrics = MetricsResponse
