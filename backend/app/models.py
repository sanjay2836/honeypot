"""
Database models for Honeypot Event Ingestion & Threat Classification.
"""
from datetime import datetime
import json
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Index
from .database import Base

class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(64), index=True, nullable=False)
    source_port = Column(Integer, nullable=True)
    service = Column(String(32), index=True, nullable=False)  # 'SSH' or 'HTTP'
    event_type = Column(String(64), index=True, nullable=False)  # 'LOGIN_ATTEMPT', 'COMMAND_EXEC', 'WEB_REQUEST', 'FILE_UPLOAD', 'RECON_PROBE'
    
    # Captured interaction details
    username = Column(String(128), nullable=True, index=True)
    password = Column(String(256), nullable=True)
    payload = Column(Text, nullable=True)
    user_agent = Column(String(512), nullable=True)
    path = Column(String(512), nullable=True)
    request_method = Column(String(16), nullable=True)
    session_id = Column(String(64), nullable=True, index=True)
    raw_details = Column(Text, nullable=True)  # JSON formatted extra context

    # Classified Threat Intelligence
    classification = Column(String(64), default="UNCLASSIFIED", index=True)  # SSH_BRUTE_FORCE, COMMAND_INJECTION, SQL_INJECTION, BOTNET_RECON, PATH_TRAVERSAL, CREDENTIAL_STUFFING, RECON_PROBE
    risk_score = Column(Integer, default=10)  # 0 to 100
    risk_level = Column(String(16), default="LOW", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    matched_rule = Column(String(256), nullable=True)

    # Geo Location Enrichment
    geo_country = Column(String(128), default="Unknown")
    geo_country_code = Column(String(8), default="XX")
    geo_city = Column(String(128), default="Unknown")
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    geo_org = Column(String(256), default="Unknown ISP/Org")

    __table_args__ = (
        Index("ix_events_ip_service", "source_ip", "service"),
        Index("ix_events_time_risk", "timestamp", "risk_level"),
    )

    def to_dict(self):
        details = {}
        if self.raw_details:
            try:
                details = json.loads(self.raw_details)
            except Exception:
                details = {"raw": self.raw_details}
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "service": self.service,
            "event_type": self.event_type,
            "username": self.username,
            "password": self.password,
            "payload": self.payload,
            "user_agent": self.user_agent,
            "path": self.path,
            "request_method": self.request_method,
            "session_id": self.session_id,
            "classification": self.classification,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "matched_rule": self.matched_rule,
            "geo": {
                "country": self.geo_country,
                "country_code": self.geo_country_code,
                "city": self.geo_city,
                "lat": self.geo_lat,
                "lon": self.geo_lon,
                "org": self.geo_org,
            },
            "details": details
        }
