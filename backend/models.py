from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class AlertEvent(Base):
    __tablename__ = 'alert_events'

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    alert_type = Column(String)
    severity = Column(Integer)
    details = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    