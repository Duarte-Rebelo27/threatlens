from backend.database import init_db, SessionLocal
from backend.parser import parse_log_file
from backend.engine import analyze_logs

DEFAULT_LOG_PATH = "sample_logs/access.log"

def main():
    init_db()

    logs = parse_log_file(DEFAULT_LOG_PATH)
    print(f"Parsed {len(logs)} log lines.")

    db = SessionLocal()
    try:
        results = analyze_logs(logs, db=db)  # <-- inject session
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    print(f"Flagged {len(results)} IP(s)\n")

    if not results:
        print("No suspicious activity detected.")
        return

    print("Aggregated Alerts:")
    for item in results:
        print(item)

if __name__ == "__main__":
    main()