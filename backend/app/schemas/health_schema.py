from pydantic import BaseModel, Field

class HealthResponse(BaseModel):
    status: str = Field("ok", description="Operational health status of the service", examples=["ok"])
    service: str = Field("unilogx", description="Service identifier", examples=["unilogx"])
