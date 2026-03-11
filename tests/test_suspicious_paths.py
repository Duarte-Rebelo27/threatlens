from datetime import datetime

from backend.detectors.suspicious_paths import detect_suspicious_paths


TEST_CONFIG = {
    "detectors": {
        "suspicious_paths": {
            "enabled": True,
            "paths": {
                "/admin": 60,
                "/config": 60,
                "/wp-login": 60,
                "/etc/passwd": 90,
                "/backup": 60,
                "/.git": 60,
                "/.env": 90,
            }
        }
    }
}


def test_suspicious_path_detected():
    logs = [{
        "ip_address": "1.2.3.4",
        "timestamp": datetime.now(),
        "endpoint": "/admin",
        "status_code": 200
    }]

    alerts = detect_suspicious_paths(logs, TEST_CONFIG)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == 60
    assert alerts[0]["type"] == "Suspicious Path Access"