import json
from collections import defaultdict
from pathlib import Path

FAILED_LOGIN_THRESHOLD = 3

def detect_events(events):
    alerts = []
    failed_logins = defaultdict(int)

    for event in events:
        event_type = event.get("event_type", "")
        user = event.get("user", "unknown")
        resource = event.get("resource", "")

        if event_type == "login_failed":
            failed_logins[user] += 1
            if failed_logins[user] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "rule": "REPEATED_FAILED_LOGIN",
                    "severity": "HIGH",
                    "user": user,
                    "message": f"{failed_logins[user]} failed login attempts detected"
                })

        if event_type == "resource_access" and resource.startswith("/restricted"):
            alerts.append({
                "rule": "RESTRICTED_RESOURCE_ACCESS",
                "severity": "MEDIUM",
                "user": user,
                "resource": resource,
                "message": "Access to a restricted test resource detected"
            })

        if event.get("test_signature") == "SUSPICIOUS_DEMO_SIGNATURE":
            alerts.append({
                "rule": "SUSPICIOUS_TEST_SIGNATURE",
                "severity": "MEDIUM",
                "user": user,
                "message": "Authorized synthetic suspicious signature detected"
            })

    return alerts

def main():
    path = Path(__file__).resolve().parent.parent / "data" / "sample_events.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    alerts = detect_events(events)

    print("Intrusion Detection System - Demo")
    print("=" * 40)
    if not alerts:
        print("No alerts generated.")
        return

    for alert in alerts:
        print(f"[{alert['severity']}] {alert['rule']} - {alert['message']}")

if __name__ == "__main__":
    main()
