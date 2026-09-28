from .event_service import list_events

def search_events(q=None, source=None, severity=None, limit=100):
    return list_events(q=q, source=source, severity=severity, limit=limit)
