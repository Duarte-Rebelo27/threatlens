from typing import Dict, List


def detect_abnormal_time(logs: List[Dict], config: Dict) -> List[Dict]:
    detector_cfg = config["detectors"]["abnormal_access_time"]

    if not detector_cfg.get("enabled", True):
        return []

    start_hour = detector_cfg["start_hour"]
    end_hour = detector_cfg["end_hour"]
    severity = detector_cfg["severity"]

    alerts = []

    for log in logs:
        hour = log["timestamp"].hour

        if start_hour <= hour <= end_hour:
            alerts.append({
                "ip_address": log["ip_address"],
                "type": "Abnormal Access Time",
                "severity": severity,
                "details": f"Access at unusual time: {hour}:00"
            })

    return alerts