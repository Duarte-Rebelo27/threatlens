from backend.parser import parse_line
from datetime import datetime

def test_parse_valid_line():
    line = '192.168.1.10 - - [20/Feb/2026:21:10:15] "GET /login HTTP/1.1" 401'

    result = parse_line(line)

    assert result['ip_address'] == '192.168.1.10'
    assert result['method'] == 'GET'
    assert result['endpoint'] == '/login'
    assert result['status_code'] == 401
    assert isinstance(result['timestamp'], datetime)

def test_parse_invalid_line():
    line = 'Invalid log entry'

    result = parse_line(line)

    assert result is None