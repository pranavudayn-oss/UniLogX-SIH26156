from ..database import get_connection

def metrics() -> dict:
    """
    Computes real-time operational dashboard analytics and KPIs directly from stored events and quarantines.
    Handles empty database state safely with zero defaults.
    """
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] or 0
        quarantined = conn.execute("SELECT COUNT(*) FROM quarantines").fetchone()[0] or 0
        active_quarantined = conn.execute(
            "SELECT COUNT(*) FROM quarantines WHERE status = 'quarantined'"
        ).fetchone()[0] or 0
        reprocessed = conn.execute(
            "SELECT COUNT(*) FROM quarantines WHERE status = 'reprocessed'"
        ).fetchone()[0] or 0

        sources = {
            r["source_type"]: r["n"]
            for r in conn.execute(
                "SELECT source_type, COUNT(*) n FROM events WHERE source_type IS NOT NULL GROUP BY source_type"
            )
        }
        severities = {
            str(r["severity"]): r["n"]
            for r in conn.execute(
                "SELECT severity, COUNT(*) n FROM events WHERE severity IS NOT NULL GROUP BY severity"
            )
        }
        outcomes = {
            str(r["outcome"]): r["n"]
            for r in conn.execute(
                "SELECT outcome, COUNT(*) n FROM events WHERE outcome IS NOT NULL GROUP BY outcome"
            )
        }
        categories = {
            str(r["category"]): r["n"]
            for r in conn.execute(
                "SELECT category, COUNT(*) n FROM events WHERE category IS NOT NULL GROUP BY category"
            )
        }
        parsers = {
            r["parser_name"]: r["n"]
            for r in conn.execute(
                "SELECT parser_name, COUNT(*) n FROM events WHERE parser_name IS NOT NULL GROUP BY parser_name"
            )
        }

        # Quarantine root-cause diagnostic breakdown
        quarantine_reasons = {
            r["reason"]: r["n"]
            for r in conn.execute(
                "SELECT reason, COUNT(*) n FROM quarantines GROUP BY reason ORDER BY n DESC LIMIT 10"
            )
        }

        # Recent activity (timeline of latest 10 normalized events)
        recent_rows = conn.execute(
            """SELECT event_id, timestamp, parser_name, source_type, action, outcome, category, created_at
               FROM events ORDER BY created_at DESC LIMIT 10"""
        ).fetchall()
        recent_activity = [
            {
                "event_id": r["event_id"],
                "timestamp": r["timestamp"] or r["created_at"],
                "parser": r["parser_name"],
                "source_type": r["source_type"],
                "action": r["action"],
                "outcome": r["outcome"],
                "category": r["category"],
            }
            for r in recent_rows
        ]

        # Activity timeline (time slots with counts for trend visualization)
        timeline_rows = conn.execute(
            """SELECT substr(created_at, 1, 16) as time_slot, COUNT(*) as count
               FROM events
               GROUP BY time_slot
               ORDER BY time_slot DESC
               LIMIT 12"""
        ).fetchall()
        timeline = [{"time": r["time_slot"], "count": r["count"]} for r in reversed(timeline_rows)]

    attempted = total + active_quarantined
    success_rate = round((total / attempted * 100), 2) if attempted else 0.0

    return {
        "total_events": total,
        "quarantined": active_quarantined,
        "quarantined_events": active_quarantined,
        "total_quarantined": quarantined,
        "reprocessed": reprocessed,
        "parser_success_rate": success_rate,
        "source_count": len(sources),
        # Backward-compatible keys
        "sources": sources,
        "severities": severities,
        "outcomes": outcomes,
        "categories": categories,
        "parsers": parsers,
        # Feature 6 explicit normalized keys
        "events_by_source": sources,
        "events_by_parser": parsers,
        "events_by_category": categories,
        "events_by_outcome": outcomes,
        "quarantine_summary": {
            "total": quarantined,
            "active": active_quarantined,
            "reprocessed": reprocessed,
            "by_reason": quarantine_reasons,
        },
        "recent_activity": recent_activity,
        "timeline": timeline,
    }
