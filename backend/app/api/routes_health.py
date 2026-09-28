from fastapi import APIRouter
from ..database import get_connection
from ..schemas.health_schema import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check",
    description="Verifies API operational availability and active SQLite database connectivity.",
    response_description="Health status object indicating service availability.",
    status_code=200,
)
def health():
    with get_connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "service": "unilogx"}
