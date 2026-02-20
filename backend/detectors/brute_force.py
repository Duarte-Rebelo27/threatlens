from collection import defaultdict
from datetime import timedelta

def detect_brute_force_attempts(logs):
    alerts = []
    failed_attempts = defaultdict(list)

    for log in logs:
        if log ['endpoint'] == '/login' and log['status_code'] == 401:
            failed_attempts[log['ip_address']].append(log['timestamp'])
        
    for ip_address, timestamps in failed_attempts.items():
        timestamps.sort()

        for i in range(len(timestamps) - 4):
            if timestamps[i + 4] - timestamps[i] <= timedelta(minutes=1):
                alerts.append({
                    'ip_address': ip_address,
                    'type': 'Brute Force Attack',
                    'severity': '85',
                    'description': f'Multiple failed login attempts detected from IP {ip_address} within a short time frame.'
                })
                break
    
    return alerts