import re
from datetime import datetime

log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(GET|POST) (.*?) HTTP/1\.1" (\d+)')

def parse_log_file(file_path):
    parsed_logs = []

    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match: 
                ip_address, timestamp_str, method, endpoint, status_code = match.groups()

                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')

                parsed_logs.append({
                    'ip_address': ip_address,
                    'timestamp': timestamp,
                    'method': method,
                    'endpoint': endpoint,
                    'status_code': int(status_code)
                })

        return parsed_logs