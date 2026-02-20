from parser import parse_log_file

logs = parse_log_file('../sample_logs/access.log')

for log in logs:
    print(log)