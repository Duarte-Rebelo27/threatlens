from typing import List, Dict, Optional
from collections import defaultdict
from sqlalchemy.orm import Session

from backend.detectors.brute_force import detect_brute_force_attempts
from backend.detectors.suspicious_paths import detect_suspicious_paths
from backend.detectors.anomaly import detect_abnormal_time
from backend.models import AlertEvent


def analyze_logs(logs: List[Dict], db: Optional[Session] = None) -> List[Dict]:
    """
    Orchestrates: detectors -> (optional) persist raw events -> aggregate by IP
    """
    all_alerts = run_detectors(logs)

    if not all_alerts:
        return []

    if db is not None:
        save_alerts_to_db(db, all_alerts)

    return aggregate_alerts(all_alerts)


def run_detectors(logs: List[Dict]) -> List[Dict]:
    alerts = []
    alerts.extend(detect_brute_force_attempts(logs))
    alerts.extend(detect_suspicious_paths(logs))
    alerts.extend(detect_abnormal_time(logs))
    return alerts


def aggregate_alerts(alerts: List[Dict]) -> List[Dict]:
    aggregated = defaultdict(lambda: {
        "ip_address": "",
        "alert_types": [],
        "severity": 0,
        "details": []
    })

    for alert in alerts:
        ip_address = alert["ip_address"]
        aggregated[ip_address]["ip_address"] = ip_address
        aggregated[ip_address]["alert_types"].append(alert["type"])
        aggregated[ip_address]["severity"] += int(alert["severity"])
        aggregated[ip_address]["details"].append(alert["details"])

    for ip_address_data in aggregated.values():
        ip_address_data["severity"] = min(ip_address_data["severity"], 100)

    return list(aggregated.values())


def save_alerts_to_db(db: Session, alerts: List[Dict]) -> None:
    for alert in alerts:
        db.add(AlertEvent(
            ip_address=alert["ip_address"],
            alert_type=alert["type"],
            severity=int(alert["severity"]),
            details=str(alert["details"])
        ))