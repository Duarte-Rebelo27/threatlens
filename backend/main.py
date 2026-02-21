from backend.database import init_db
from backend.parser import parse_log_file
from backend.engine import analyze_logs

DEFAULT_LOG_PATH = 'sample_logs/access.log'

def main():
    # Initialize the database
    init_db()

    # Parse the logs
    logs = parse_log_file(DEFAULT_LOG_PATH)
    print(f"Parsed {len(logs)} log lines.")

    # Analyze the logs
    results = analyze_logs(logs)
    print(f"Flagged {len(results)} IP(s)\n")

    # Print results
    if not results:
        print("No suspicious activity detected.")
        return
    
    print("Aggregated Alerts:")
    for item in results:
        print (item)

if __name__ == "__main__":
    main()
