from typing import List
from pydantic import BaseModel


class IngestLinesRequest(BaseModel):
    lines: List[str]


class AggregatedAlert(BaseModel):
    ip_address: str
    alert_types: List[str]
    severity: int
    details: List[str]


class IngestResponse(BaseModel):
    alerts: List[AggregatedAlert]


class AlertEventOut(BaseModel):
    id: int
    ip_address: str
    alert_type: str
    severity: int
    details: str
    created_at: str