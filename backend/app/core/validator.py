from pydantic import ValidationError
from ..schemas.event_schema import NormalizedEvent

def validate_event(event: dict):
    try:
        return True, NormalizedEvent(**event), None
    except ValidationError as exc:
        return False, None, str(exc)
