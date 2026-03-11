from typing import Dict, List


def detect_suspicious_paths(logs: List[Dict], config: Dict) -> List[Dict]:
    detector_cfg = config["detectors"]["suspicious_paths"]

    if not detector_cfg.get("enabled", True):
        return []

    sensitive_paths = detector_cfg["paths"]
    alerts = []

    for log in logs:
        endpoint = log["endpoint"]

        if endpoint in sensitive_paths:
            alerts.append({
                "ip_address": log["ip_address"],
                "type": "Suspicious Path Access",
                "severity": sensitive_paths[endpoint],
                "details": f"Access to sensitive path: {endpoint}"
            })

    return alerts