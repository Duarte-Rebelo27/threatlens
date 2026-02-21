from backend.detectors.anomaly import detect_abnormal_time
from datetime import datetime

def test_abnormal_time_detected():
    logs = [{
        'ip_address': '8.8.8.8',
        'timestamp': datetime(2026, 2, 20, 3, 0, 0),
        'endpoint': '/home',
        'status_code': 200
    }]

    alerts = detect_abnormal_time(logs)
    assert len(alerts) == 1
    assert alerts[0]['type'] == 'Abnormal Access Time'
    