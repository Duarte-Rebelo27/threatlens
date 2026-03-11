from pathlib import Path

from backend.database import Base, SessionLocal, engine
from backend.models import AlertEvent
from backend.stream.processor import LogStreamProcessor


def setup_function():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_process_line_saves_alerts_for_suspicious_path(tmp_path):
    log_file = tmp_path / "access.log"
    checkpoint_file = tmp_path / ".offset"
    log_file.write_text("", encoding="utf-8")

    processor = LogStreamProcessor(
        file_path=str(log_file),
        session_factory=SessionLocal,
        poll_interval=0.1,
        start_at_end=True,
        buffer_size=50,
        checkpoint_path=str(checkpoint_file),
    )

    line = '77.77.77.77 - - [20/Feb/2026:04:15:00] "GET /admin HTTP/1.1" 404'

    processor.process_line(line)

    db = SessionLocal()
    try:
        rows = db.query(AlertEvent).all()
        assert len(rows) == 2

        alert_types = sorted(row.alert_type for row in rows)
        assert alert_types == ["Abnormal Access Time", "Suspicious Path Access"]

        details = [row.details for row in rows]
        assert "Access to sensitive path: /admin" in details
    finally:
        db.close()


def test_process_lines_detects_bruteforce_from_multiple_events(tmp_path):
    log_file = tmp_path / "access.log"
    checkpoint_file = tmp_path / ".offset"
    log_file.write_text("", encoding="utf-8")

    processor = LogStreamProcessor(
        file_path=str(log_file),
        session_factory=SessionLocal,
        poll_interval=0.1,
        start_at_end=True,
        buffer_size=50,
        checkpoint_path=str(checkpoint_file),
    )

    lines = [
        '192.168.1.10 - - [20/Feb/2026:10:32:11] "POST /login HTTP/1.1" 401',
        '192.168.1.10 - - [20/Feb/2026:10:32:12] "POST /login HTTP/1.1" 401',
        '192.168.1.10 - - [20/Feb/2026:10:32:13] "POST /login HTTP/1.1" 401',
        '192.168.1.10 - - [20/Feb/2026:10:32:14] "POST /login HTTP/1.1" 401',
        '192.168.1.10 - - [20/Feb/2026:10:32:15] "POST /login HTTP/1.1" 401',
        '192.168.1.10 - - [20/Feb/2026:10:32:16] "POST /login HTTP/1.1" 401',
    ]

    processor.process_lines(lines)

    db = SessionLocal()
    try:
        rows = db.query(AlertEvent).all()

        assert len(rows) >= 1
        assert any(row.alert_type == "Brute Force Attack" for row in rows)
    finally:
        db.close()