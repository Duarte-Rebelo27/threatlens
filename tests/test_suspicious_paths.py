from backend.detectors.suspicious_paths import detect_suspicious_paths
from datetime import datetime

def test_suspicious_path_detected():
    logs = [{
        'ip_address': '1.2.3.4',
        'timestamp': datetime.now(),
        'endpoint': '/admin',
        'status_code': 200
    }]

    alerts = detect_suspicious_paths(logs)

    assert len(alerts) == 1
    assert alerts[0]['severity'] == 60
    