import json
import time
from collections import deque
from pathlib import Path
from typing import Deque

from sqlalchemy.orm import sessionmaker

from backend.engine import run_detectors, save_alerts_to_db
from backend.parser import parse_line


class LogStreamProcessor:
    def __init__(
        self,
        file_path: str,
        session_factory: sessionmaker,
        poll_interval: float = 1.0,
        start_at_end: bool = True,
        buffer_size: int = 50,
        checkpoint_path: str = ".threatlens.offset",
    ) -> None:
        self.file_path = Path(file_path)
        self.session_factory = session_factory
        self.poll_interval = poll_interval
        self.start_at_end = start_at_end
        self.buffer_size = buffer_size
        self.checkpoint_path = Path(checkpoint_path)

        self.event_buffer: Deque[dict] = deque(maxlen=buffer_size)
        self._running = False
        self._seen_alert_keys: set[tuple] = set()

    def start(self) -> None:
        if not self.file_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.file_path}")

        self._running = True

        with self.file_path.open("r", encoding="utf-8") as f:
            start_position = self._get_start_position(f)
            f.seek(start_position)

            print(f"[ThreatLens] Watching {self.file_path} from byte {start_position}")

            while self._running:
                line = f.readline()

                if not line:
                    time.sleep(self.poll_interval)
                    continue

                self.process_line(line.rstrip("\n"))
                self._save_checkpoint(f.tell())

    def stop(self) -> None:
        self._running = False

    def process_line(self, line: str) -> None:
        if not line.strip():
            return

        parsed = parse_line(line)
        if parsed is None:
            return

        self.event_buffer.append(parsed)

        alerts = run_detectors(list(self.event_buffer))

        if not alerts:
            return

        new_alerts = []
        for alert in alerts:
            key = (
                alert["ip_address"],
                alert["type"],
                int(alert["severity"]),
                str(alert["details"]),
            )
            if key not in self._seen_alert_keys:
                self._seen_alert_keys.add(key)
                new_alerts.append(alert)

        if not new_alerts:
            return

        db = self.session_factory()
        try:
            save_alerts_to_db(db, new_alerts)
            db.commit()
            print(
                f"[ThreatLens] Saved {len(new_alerts)} new alert(s) "
                f"(buffer size: {len(self.event_buffer)}) from line: {line}"
            )
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _get_start_position(self, file_obj) -> int:
        checkpoint = self._load_checkpoint()

        if checkpoint:
            saved_path = checkpoint.get("file_path")
            saved_offset = checkpoint.get("offset", 0)

            if saved_path == str(self.file_path):
                file_size = self.file_path.stat().st_size
                if 0 <= saved_offset <= file_size:
                    return saved_offset

        if self.start_at_end:
            file_obj.seek(0, 2)
            return file_obj.tell()

        return 0

    def _load_checkpoint(self) -> dict | None:
        if not self.checkpoint_path.exists():
            return None

        try:
            with self.checkpoint_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _save_checkpoint(self, offset: int) -> None:
        payload = {
            "file_path": str(self.file_path),
            "offset": offset,
        }
        with self.checkpoint_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f)