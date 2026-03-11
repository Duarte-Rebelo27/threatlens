from datetime import datetime, timedelta

from backend.detectors.brute_force import detect_brute_force_attempts


TEST_CONFIG = {
    "detectors": {
        "brute_force": {
            "enabled": True,
            "endpoint": "/login",
            "failed_status_code": 401,
            "attempts": 5,
            "window_seconds": 60,
            "severity": 85,
        }
    }
}


def test_detect_brute_force_attempts():
    base_time = datetime.now()

    logs = []
    for i in range(6):
        logs.append({
            "ip_address": "1.2.3.4",
            "timestamp": base_time + timedelta(seconds=i),
            "endpoint": "/login",
            "status_code": 401
        })

    alerts = detect_brute_force_attempts(logs, TEST_CONFIG)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Brute Force Attack"
    assert alerts[0]["severity"] == 85


def test_no_brute_force_if_spread_out():
    base_time = datetime.now()

    logs = []
    for i in range(6):
        logs.append({
            "ip_address": "1.2.3.4",
            "timestamp": base_time + timedelta(minutes=i),
            "endpoint": "/login",
            "status_code": 401
        })

    alerts = detect_brute_force_attempts(logs, TEST_CONFIG)

    assert len(alerts) == 0