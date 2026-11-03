"""
Pydantic schemas for Honeypot Event validation, responses, analytics, and metrics.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class EventCreate(BaseModel):
    source_ip: str
    source_port: Optional[int] = None
    service: str  # "SSH" or "HTTP"
    event_type: str  # "LOGIN_ATTEMPT", "COMMAND_EXEC", "WEB_REQUEST", "FILE_UPLOAD", "RECON_PROBE"
    username: Optional[str] = None
    password: Optional[str] = None
    payload: Optional[str] = None
    user_agent: Optional[str] = None
    path: Optional[str] = None
    request_method: Optional[str] = None
    session_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    # Set by decoys when replaying events buffered during a backend outage
    timestamp: Optional[datetime] = None

class GeoInfo(BaseModel):
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    lat: Optional[float] = None
    lon: Optional[float] = None
    org: str = "Unknown ISP/Org"

class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    source_port: Optional[int] = None
    service: str
    event_type: str
    username: Optional[str] = None
    password: Optional[str] = None
    payload: Optional[str] = None
    user_agent: Optional[str] = None
    path: Optional[str] = None
    request_method: Optional[str] = None
    session_id: Optional[str] = None
    classification: str
    risk_score: int
    risk_level: str
    matched_rule: Optional[str] = None
    geo: GeoInfo
    details: Optional[Dict[str, Any]] = None

class OverviewStats(BaseModel):
    total_events: int
    unique_ips: int
    ssh_events: int
    http_events: int
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    top_threat_vector: str

class FrequencyPoint(BaseModel):
    time_bucket: str
    ssh_count: int
    http_count: int
    total_count: int

class CredentialStat(BaseModel):
    credential: str
    type: str  # 'username' or 'password'
    count: int
    percentage: float

class RiskMatrixEntry(BaseModel):
    classification: str
    risk_level: str
    risk_score: int
    count: int
    description: str
    sample_payloads: List[str]

class GeoDistributionEntry(BaseModel):
    country: str
    country_code: str
    city: str
    count: int
    lat: Optional[float] = None
    lon: Optional[float] = None
    ip_samples: List[str]

class ServiceStatus(BaseModel):
    name: str
    type: str
    port: int
    status: str  # "ONLINE", "OFFLINE", "DEGRADED"
    last_event_time: Optional[datetime] = None
    event_count: int
