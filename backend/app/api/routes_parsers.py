from typing import List
from fastapi import APIRouter, HTTPException, Path as FastAPIPath
from ..parsers import PARSERS
from ..database import get_connection
from ..schemas.parser_schema import ParserRegistryItem

router = APIRouter(tags=["parsers"])


def _get_event_counts() -> dict[str, int]:
    """Retrieve processed event counts grouped by parser from the database."""
    try:
        with get_connection() as conn:
            return {
                r["parser_name"]: r["n"]
                for r in conn.execute(
                    "SELECT parser_name, COUNT(*) n FROM events GROUP BY parser_name"
                ).fetchall()
            }
    except Exception:
        return {}


@router.get(
    "/parsers",
    response_model=List[ParserRegistryItem],
    summary="List all registered parsers",
    description=(
        "Returns the complete runtime parser registry inventory.\n\n"
        "Each entry includes the parser's machine name, display name, vendor/standard, "
        "supported format, source domain, version, runtime status, mapping file specification, "
        "supported target schema fields, and the live count of events parsed."
    ),
    response_description="List of active plug-and-play parser plugin specifications.",
    status_code=200,
)
def list_parsers():
    counts = _get_event_counts()
    return [p.to_registry_dict(processed_count=counts.get(p.name, 0)) for p in PARSERS]


@router.get(
    "/parsers/{parser_name}",
    response_model=ParserRegistryItem,
    summary="Get individual parser details",
    description=(
        "Retrieves the complete technical specification, supported normalized fields, "
        "and mapping metadata for a specific registered parser by its unique name."
    ),
    response_description="Parser plugin specification and capability definition.",
    status_code=200,
    responses={
        404: {
            "description": "Parser plugin name not found in active registry.",
            "content": {"application/json": {"example": {"detail": "Parser 'unknown_parser' not found in registry"}}},
        },
    },
)
def get_parser(
    parser_name: str = FastAPIPath(
        ...,
        description="Machine identifier of the parser plugin (e.g. cisco_asa, nginx, cloud_json, syslog, generic_kv)",
        examples=["cisco_asa"],
    )
):
    counts = _get_event_counts()
    for p in PARSERS:
        if p.name == parser_name:
            return p.to_registry_dict(processed_count=counts.get(p.name, 0))
    raise HTTPException(status_code=404, detail=f"Parser '{parser_name}' not found in registry")
