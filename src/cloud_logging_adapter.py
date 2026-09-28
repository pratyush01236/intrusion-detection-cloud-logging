import json

def to_cloud_log_record(alert):
    """Prepare an IDS alert for a cloud logging API/agent."""
    return {
        "log_name": "ids-alerts",
        "severity": alert.get("severity", "INFO"),
        "json_payload": json.dumps(alert)
    }

if __name__ == "__main__":
    example = {
        "rule": "REPEATED_FAILED_LOGIN",
        "severity": "HIGH",
        "message": "Synthetic demonstration alert"
    }
    print(to_cloud_log_record(example))
