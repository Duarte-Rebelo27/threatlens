from collections import defaultdict
from datetime import timedelta
from typing import Dict, List


def detect_brute_force_attempts(logs: List[Dict], config: Dict) -> List[Dict]:
    detector_cfg = config["detectors"]["brute_force"]

    if not detector_cfg.get("enabled", True):
        return []

    endpoint = detector_cfg["endpoint"]
    failed_status_code = detector_cfg["failed_status_code"]
    attempts_threshold = detector_cfg["attempts"]
    window_seconds = detector_cfg["window_seconds"]
    severity = detector_cfg["severity"]

    alerts = []
    failed_attempts = defaultdict(list)

    for log in logs:
        if log["endpoint"] == endpoint and log["status_code"] == failed_status_code:
            failed_attempts[log["ip_address"]].append(log["timestamp"])

    for ip_address, timestamps in failed_attempts.items():
        timestamps.sort()

        needed_index_gap = attempts_threshold - 1

        for i in range(len(timestamps) - needed_index_gap):
            if timestamps[i + needed_index_gap] - timestamps[i] <= timedelta(seconds=window_seconds):
                alerts.append({
                    "ip_address": ip_address,
                    "type": "Brute Force Attack",
                    "severity": severity,
                    "details": f"Multiple failed login attempts detected from IP {ip_address} within a short time frame."
                })
                break

    return alerts