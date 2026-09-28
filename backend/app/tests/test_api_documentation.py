"""
Feature 9 tests — API Documentation & OpenAPI Specification

Validates:
1.  FastAPI application metadata exists (title, version, description, openapi_tags).
2.  OpenAPI generation functions successfully and produces valid dictionary.
3.  OpenAPI info block matches the application title, version, and pipeline workflow.
4.  All required API tags exist and are documented with descriptions.
5.  All core system endpoints appear in the OpenAPI schema paths.
6.  Documented HTTP methods match actual route handlers (GET, POST).
7.  Endpoint summaries and technical descriptions are populated.
8.  Parameter descriptions and constraints are documented in OpenAPI schema.
9.  Response status codes and models (200, 400, 404) are registered in OpenAPI schema.
10. Swagger UI (/docs) route is enabled and configured.
11. ReDoc (/redoc) route is enabled and configured.
12. OpenAPI description explicitly documents the end-to-end processing pipeline workflow.
13. Health route handler executes and returns status 200 with HealthResponse structure.
14. Parsers route handler executes and returns active registry inventory.
15. Metrics route handler executes and returns operational aggregations.
16. Quarantine route handler executes and returns quarantined record structures.
17. Events route handler executes and returns normalized event structures.
"""
import pytest
from app.main import app
from app.api.routes_health import health
from app.api.routes_parsers import list_parsers, get_parser
from app.api.routes_metrics import get_metrics
from app.api.routes_quarantine import quarantines
from app.api.routes_events import events


@pytest.fixture(scope="module")
def openapi_schema():
    """Generate the complete OpenAPI schema in-memory directly from the FastAPI application."""
    return app.openapi()


def test_fastapi_app_metadata_exists():
    """1. Application metadata contains descriptive title, version, and tags."""
    assert "UniLogX" in app.title
    assert app.version == "0.1.0"
    assert app.description is not None
    assert len(app.description) > 100
    assert app.openapi_tags is not None
    assert len(app.openapi_tags) >= 6


def test_openapi_schema_generation(openapi_schema):
    """2. OpenAPI schema generates successfully with standard top-level keys."""
    assert "openapi" in openapi_schema
    assert "info" in openapi_schema
    assert "paths" in openapi_schema
    assert openapi_schema["openapi"].startswith("3.")


def test_openapi_info_contains_title_and_version(openapi_schema):
    """3. OpenAPI info block matches the application specification."""
    info = openapi_schema["info"]
    assert "UniLogX" in info["title"]
    assert info["version"] == "0.1.0"
    assert "Pipeline Workflow" in info["description"]


def test_openapi_tags_exist(openapi_schema):
    """4. All required operational tags are present in OpenAPI documentation."""
    tag_names = {t["name"] for t in openapi_schema.get("tags", [])}
    expected_tags = {"health", "ingestion", "events", "quarantine", "metrics", "parsers"}
    assert expected_tags.issubset(tag_names)


def test_core_endpoints_present_in_paths(openapi_schema):
    """5. All active API routes are registered in OpenAPI paths."""
    paths = openapi_schema["paths"]
    expected_routes = [
        "/api/v1/health",
        "/api/v1/upload",
        "/api/v1/events",
        "/api/v1/events/export/csv",
        "/api/v1/events/export/json",
        "/api/v1/events/{event_id}",
        "/api/v1/quarantine",
        "/api/v1/quarantine/{quarantine_id}",
        "/api/v1/quarantine/reprocess",
        "/api/v1/quarantine/{quarantine_id}/reprocess",
        "/api/v1/metrics",
        "/api/v1/parsers",
        "/api/v1/parsers/{parser_name}",
    ]
    for route in expected_routes:
        assert route in paths, f"Missing route in OpenAPI paths: {route}"


def test_http_methods_documented(openapi_schema):
    """6. Documented HTTP verbs match the implemented functionality."""
    paths = openapi_schema["paths"]

    assert "get" in paths["/api/v1/health"]
    assert "post" in paths["/api/v1/upload"]
    assert "get" in paths["/api/v1/events"]
    assert "get" in paths["/api/v1/events/export/csv"]
    assert "get" in paths["/api/v1/events/export/json"]
    assert "get" in paths["/api/v1/events/{event_id}"]
    assert "get" in paths["/api/v1/quarantine"]
    assert "post" in paths["/api/v1/quarantine/reprocess"]
    assert "get" in paths["/api/v1/metrics"]
    assert "get" in paths["/api/v1/parsers"]


def test_endpoint_summaries_and_descriptions(openapi_schema):
    """7. Critical endpoints have non-empty summaries and descriptions."""
    paths = openapi_schema["paths"]

    upload_spec = paths["/api/v1/upload"]["post"]
    assert upload_spec.get("summary")
    assert len(upload_spec.get("description", "")) > 50

    events_spec = paths["/api/v1/events"]["get"]
    assert events_spec.get("summary")
    assert "Unified search" in events_spec.get("description", "")

    metrics_spec = paths["/api/v1/metrics"]["get"]
    assert metrics_spec.get("summary")


def test_parameter_documentation(openapi_schema):
    """8. Query parameters on the events endpoint are documented with descriptions."""
    paths = openapi_schema["paths"]
    events_params = paths["/api/v1/events"]["get"].get("parameters", [])
    param_names = {p["name"] for p in events_params}
    assert "q" in param_names
    assert "source_ip" in param_names
    assert "destination_port" in param_names
    assert "parser" in param_names

    # Check that parameter descriptions are present
    for p in events_params:
        assert p.get("description"), f"Missing description on parameter: {p['name']}"


def test_error_responses_documented(openapi_schema):
    """9. Documented error responses exist for endpoints with validation/lookups."""
    paths = openapi_schema["paths"]

    # 400 on upload
    upload_responses = paths["/api/v1/upload"]["post"]["responses"]
    assert "400" in upload_responses

    # 404 on event detail
    event_detail_responses = paths["/api/v1/events/{event_id}"]["get"]["responses"]
    assert "404" in event_detail_responses

    # 404 on parser detail
    parser_detail_responses = paths["/api/v1/parsers/{parser_name}"]["get"]["responses"]
    assert "404" in parser_detail_responses

    # 404 on quarantine detail
    quarantine_detail_responses = paths["/api/v1/quarantine/{quarantine_id}"]["get"]["responses"]
    assert "404" in quarantine_detail_responses


def test_swagger_and_redoc_routes_configured():
    """10-11. Swagger UI (/docs) and ReDoc (/redoc) routes are explicitly enabled."""
    assert app.docs_url == "/docs"
    assert app.redoc_url == "/redoc"
    assert app.openapi_url == "/openapi.json"

    # Verify routes exist in app.routes
    route_paths = {r.path for r in app.routes}
    assert "/docs" in route_paths
    assert "/redoc" in route_paths
    assert "/openapi.json" in route_paths


def test_pipeline_workflow_in_documentation(openapi_schema):
    """12. Main pipeline stages are explicitly documented in OpenAPI info description."""
    info = openapi_schema["info"]
    desc = info.get("description", "")
    assert "1. Ingestion" in desc
    assert "Raw Log Preservation" in desc
    assert "Format & Source Detection" in desc
    assert "Normalization" in desc
    assert "Traceability" in desc
    assert "Enrichment" in desc
    assert "Validation" in desc


def test_health_api_runtime_behavior():
    """13. Health check API returns 200 OK and conforms to HealthResponse schema."""
    res = health()
    assert isinstance(res, dict)
    assert res["status"] == "ok"
    assert res["service"] == "unilogx"


def test_parsers_api_runtime_behavior():
    """14. Parsers API returns active registry inventory."""
    items = list_parsers()
    assert isinstance(items, list)
    assert len(items) >= 5
    for item in items:
        assert "name" in item
        assert "display_name" in item
        assert "vendor" in item
        assert "supported_fields" in item


def test_metrics_api_runtime_behavior():
    """15. Metrics API returns valid operational aggregations."""
    data = get_metrics()
    assert "total_events" in data
    assert "parser_success_rate" in data
    assert "quarantine_summary" in data


def test_quarantine_api_runtime_behavior():
    """16. Quarantine listing API returns records."""
    records = quarantines(limit=5)
    assert isinstance(records, list)


def test_events_api_runtime_behavior():
    """17. Events API returns normalized records with traceability."""
    res = events(limit=5)
    assert isinstance(res, list)
    if res:
        evt = res[0]
        assert "event_id" in evt
        assert "normalized" in evt
        assert "raw_event" in evt
