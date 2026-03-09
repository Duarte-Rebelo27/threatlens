import re
from datetime import datetime
from typing import List, Dict, Optional

log_pattern = re.compile(
    r'(?P<ip_address>\d+\.\d+\.\d+\.\d+) - - '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) '
    r'(?P<endpoint>\S+) '
    r'(?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3})'
    r'(?: (?P<response_size>\S+))?'
)

def parse_line(line: str) -> Optional[Dict]:
    match = log_pattern.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    timestamp_str = data["timestamp"]

    timestamp = None
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            timestamp = datetime.strptime(timestamp_str, fmt)
            break
        except ValueError:
            continue

    if timestamp is None:
        return None

    return {
        "ip_address": data["ip_address"],
        "timestamp": timestamp,
        "method": data["method"],
        "endpoint": data["endpoint"],
        "status_code": int(data["status_code"]),
    }

def parse_log_file(file_path: str) -> List[Dict]:
    parsed: List[Dict] = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            item = parse_line(line)
            if item is not None:
                parsed.append(item)

    return parsed