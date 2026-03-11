from backend.database import SessionLocal, init_db
from backend.stream.processor import LogStreamProcessor

DEFAULT_LOG_PATH = "sample_logs/access.log"


def main() -> None:
    init_db()

    processor = LogStreamProcessor(
        file_path=DEFAULT_LOG_PATH,
        session_factory=SessionLocal,
        poll_interval=1.0,
        start_at_end=True,
        buffer_size=50,
        checkpoint_path=".threatlens.offset",
    )

    try:
        processor.start()
    except KeyboardInterrupt:
        processor.stop()
        print("\n[ThreatLens] Stream processor stopped.")


if __name__ == "__main__":
    main()