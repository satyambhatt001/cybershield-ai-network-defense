# core/logger.py
# Shared logging utility used by ALL modules
# Every alert from every detector gets saved here

import json
import os
from datetime import datetime
import config


def log_alert(alert: dict):
    """
    Saves any alert/action as a JSON line in alerts.log
    Each line is one complete JSON object — easy to read and parse
    """
    # Create data/ folder if it doesn't exist yet
    os.makedirs(os.path.dirname(config.ALERT_LOG), exist_ok=True)

    # Add human-readable timestamp if not present
    if "timestamp" not in alert:
        alert["timestamp"] = datetime.now().isoformat()

    # Write as one JSON line (jsonlines format)
    with open(config.ALERT_LOG, "a") as f:
        f.write(json.dumps(alert) + "\n")


def read_alerts(n: int = 100) -> list:
    """
    Read the last N alerts from log file
    Used by the Flask dashboard to display alerts
    Returns most recent first
    """
    if not os.path.exists(config.ALERT_LOG):
        return []

    with open(config.ALERT_LOG, "r") as f:
        lines = f.readlines()

    alerts = []
    for line in lines[-n:]:
        line = line.strip()
        if line:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return list(reversed(alerts))  # Most recent first
