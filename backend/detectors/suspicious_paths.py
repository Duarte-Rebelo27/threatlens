def detect_suspicious_paths(logs):
    alerts = []
    sensitive_paths = ['/admin', '/config', '/wp-login','/etc/passwd',  '/backup', '/.git', '/.env']

    for log in logs:
        if log['endpoint'] in sensitive_paths:
            severity = 60
            if log['endpoint'] in ['/etc/passwd', '/.env']:
                severity = 90

            alerts.append({
                'ip_address': log['ip_address'],
                'type': 'Suspicious Path Access',
                'severity': severity,
                'details': f"Access to sensitive path: {log['endpoint']}"
            })
    
    return alerts