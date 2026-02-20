import re
from datetime import datetime

log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST) (.*?) HTTP/1\.1" (\d+)')

def parse_line(line):
    match = log_pattern.match(line)
    if not match:
        return None
    
    ip_address, timestamp_str, method, endpoint, status_code = match.groups()

    timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')

    return {
        'ip_address': ip_address,
        'timestamp': timestamp,
        'method': method,
        'endpoint': endpoint,
        'status_code': int(status_code)
    }
