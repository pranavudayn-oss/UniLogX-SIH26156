from fastapi import APIRouter
from ..services.analytics_service import metrics
from ..schemas.metrics_schema import MetricsResponse

router = APIRouter(tags=["metrics"])


@router.get(
    "/metrics",
    response_model=MetricsResponse,
    summary="Get operational dashboard analytics",
    description=(
        "Returns live operational KPIs and distributions calculated directly from SQLite storage:\n\n"
        "- **Event Counts:** Total successfully normalized events and current active quarantined records.\n"
        "- **Parser Success Rate:** Calculated as `total / (total + active_quarantined) * 100`.\n"
        "- **Source Counts:** Number of distinct log sources actively ingested.\n"
        "- **Categorical Distributions:** Breakdown of events across parsers, ECS categories, source domains, and security outcome verdicts.\n"
        "- **Quarantine Diagnostics:** Root-cause error summary of all isolated logs.\n"
        "- **Recent Activity & Trends:** Recent normalized events timeline with timestamps and verdicts."
    ),
    response_description="Comprehensive operational metrics and diagnostic aggregations.",
    status_code=200,
)
def get_metrics():
    return metrics()
