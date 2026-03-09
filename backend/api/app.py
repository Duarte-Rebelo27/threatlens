from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.api.deps import get_db
from backend.api.schemas import IngestLinesRequest, IngestResponse, AlertEventOut
from backend.database import init_db
from backend.engine import run_detectors, aggregate_alerts, save_alerts_to_db
from backend.models import AlertEvent
from backend.parser import parse_line


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="ThreatLens", version="1.0", lifespan=lifespan)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.post("/ingest/lines", response_model=IngestResponse)
def ingest_lines(payload: IngestLinesRequest, db: Session = Depends(get_db)):
    parsed = []

    for line in payload.lines:
        try:
            item = parse_line(line)
            if item is not None:
                parsed.append(item)
        except Exception:
            continue

    if not parsed:
        raise HTTPException(status_code=400, detail="No valid lines parsed")

    alerts = run_detectors(parsed)
    if not alerts:
        return IngestResponse(alerts=[])

    save_alerts_to_db(db, alerts)
    db.commit()

    aggregated = aggregate_alerts(alerts)
    return IngestResponse(alerts=aggregated)


@app.post("/ingest/logfile", response_model=IngestResponse)
async def ingest_logfile(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    text_content = content.decode("utf-8", errors="replace")
    lines = [line for line in text_content.splitlines() if line.strip()]
    return ingest_lines(IngestLinesRequest(lines=lines), db)


@app.get("/alerts", response_model=list[AlertEventOut])
def get_alerts(
    ip: str | None = None,
    alert_type: str | None = None,
    min_severity: int | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(AlertEvent)

    if ip:
        q = q.filter(AlertEvent.ip_address == ip)
    if alert_type:
        q = q.filter(AlertEvent.alert_type == alert_type)
    if min_severity is not None:
        q = q.filter(AlertEvent.severity >= min_severity)

    rows = (
        q.order_by(AlertEvent.created_at.desc())
        .offset(offset)
        .limit(min(limit, 200))
        .all()
    )

    return [
        AlertEventOut(
            id=r.id,
            ip_address=r.ip_address,
            alert_type=r.alert_type,
            severity=r.severity,
            details=r.details,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in rows
    ]