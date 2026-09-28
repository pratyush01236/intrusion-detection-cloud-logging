from datetime import datetime, timezone

def normalize_event(event):
    """Convert an incoming event into a consistent logging structure."""
    normalized = dict(event)
    normalized.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    normalized.setdefault("source", "demo-application")
    normalized.setdefault("environment", "educational-demo")
    return normalized
