from typing import Optional, List
from pydantic import BaseModel, Field

class ParserRegistryItem(BaseModel):
    name: str = Field(..., description="Unique machine identifier of the parser plugin", examples=["cisco_asa"])
    display_name: str = Field(..., description="Human-readable title of the parser", examples=["Cisco ASA"])
    vendor: str = Field(..., description="Originating technology vendor or RFC specification", examples=["Cisco"])
    version: str = Field("1.0", description="Semantic version of the parser implementation", examples=["1.0"])
    format: str = Field(..., description="Detected log format identifier", examples=["cisco_asa"])
    supported_format: str = Field(..., description="Alias identifier for format compatibility", examples=["cisco_asa"])
    source: str = Field(..., description="Source infrastructure domain", examples=["firewall"])
    supported_source: str = Field(..., description="Alias identifier for source domain compatibility", examples=["firewall"])
    description: str = Field(..., description="Detailed description of parser capabilities and log types handled", examples=["Cisco ASA firewall connection and security event parser"])
    supported_fields: List[str] = Field(default_factory=list, description="Target normalized schema fields extracted by this parser", examples=[["source_ip", "source_port", "destination_ip", "destination_port", "action"]])
    mapping_file: Optional[str] = Field(None, description="Filename of associated field alias YAML mapping specification", examples=["cisco_asa.yaml"])
    status: str = Field("Active", description="Runtime registration status of the parser plugin", examples=["Active"])
    enabled: bool = Field(True, description="Whether the parser is active in runtime detection", examples=[True])
    processed_count: int = Field(0, description="Total number of events in storage parsed by this parser", examples=[47])


# Legacy alias
ParserInfo = ParserRegistryItem
