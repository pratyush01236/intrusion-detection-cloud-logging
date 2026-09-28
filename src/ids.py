import json
import time
from collections import defaultdict
from pathlib import Path

import requests


FAILED_LOGIN_THRESHOLD = 3

# Loki running through Docker
LOKI_URL = "http://localhost:3100/loki/api/v1/push"


def detect_events(events):
    alerts = []
    failed_logins = defaultdict(int)

    for event in events:
        event_type = event.get("event_type", "")
        user = event.get("user", "unknown")
        resource = event.get("resource", "")

        # Rule 1: Repeated failed login
        if event_type == "login_failed":
            failed_logins[user] += 1

            if failed_logins[user] >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "rule": "REPEATED_FAILED_LOGIN",
                    "severity": "HIGH",
                    "user": user,
                    "message": f"{failed_logins[user]} failed login attempts detected"
                })

        # Rule 2: Restricted resource access
        if event_type == "resource_access" and resource.startswith("/restricted"):
            alerts.append({
                "rule": "RESTRICTED_RESOURCE_ACCESS",
                "severity": "MEDIUM",
                "user": user,
                "resource": resource,
                "message": "Access to a restricted test resource detected"
            })

        # Rule 3: Suspicious test signature
        if event.get("test_signature") == "SUSPICIOUS_DEMO_SIGNATURE":
            alerts.append({
                "rule": "SUSPICIOUS_TEST_SIGNATURE",
                "severity": "MEDIUM",
                "user": user,
                "message": "Authorized synthetic suspicious signature detected"
            })

    return alerts


def save_alerts(alerts):
    """Save IDS alerts into a JSON file."""

    output_file = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "ids_alerts.json"
    )

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    return output_file


def send_to_loki(alerts):
    """Send IDS alerts to the local Loki server."""

    if not alerts:
        return False

    values = []

    for alert in alerts:
        timestamp_ns = str(time.time_ns())
        log_message = json.dumps(alert)

        values.append([
            timestamp_ns,
            log_message
        ])
        payload = {
        "streams": [
            {
                "stream": {
                    "job": "ids",
                    "source": "python-ids"
                },
                "values": values
            }
        ]
    }

    try:
        response = requests.post(
            LOKI_URL,
            json=payload,
            timeout=10
        )

        response.raise_for_status()

        print("Alerts successfully sent to Loki.")
        return True

    except requests.RequestException as error:
        print(f"Could not send alerts to Loki: {error}")
        return False


def main():
    input_file = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "sample_events.json"
    )

    with open(input_file, "r", encoding="utf-8") as file:
        events = json.load(file)

    alerts = detect_events(events)

    output_file = save_alerts(alerts)

    print("Intrusion Detection System - Demo")
    print("=" * 40)

    if not alerts:
        print("No alerts generated.")
    else:
        for alert in alerts:
            print(
                f"[{alert['severity']}] "
                f"{alert['rule']} - "
                f"{alert['message']}"
            )

    print()
    print(f"Alerts saved to: {output_file}")

    send_to_loki(alerts)


if __name__ == "__main__":
    main()