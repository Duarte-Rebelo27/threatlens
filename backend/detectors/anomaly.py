def detect_abnormal_time(logs):
    alerts = []

    for log in logs:
        hour = log["timestamp"].hour

        if hour >= 2 and hour <= 4:
            alerts.append({
                "ip_address": log["ip_address"],
                "type": "Abnormal Access Time",
                "severity": 25,
                "details": "Access at unusual time: {}:00".format(hour)
            })

    return alerts
