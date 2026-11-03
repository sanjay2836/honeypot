"""
Analytics & Threat Intelligence Aggregation Endpoints.
"""
from typing import List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from ..database import get_db
from ..models import HoneypotEvent
from ..schemas import (
    OverviewStats,
    FrequencyPoint,
    CredentialStat,
    RiskMatrixEntry,
    GeoDistributionEntry,
)

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/overview", response_model=OverviewStats)
def get_overview(db: Session = Depends(get_db)):
    """Retrieve high-level KPI metrics for the Security Operations Center."""
    total_events = db.query(HoneypotEvent).count()
    unique_ips = db.query(func.count(func.distinct(HoneypotEvent.source_ip))).scalar() or 0
    ssh_events = db.query(HoneypotEvent).filter(HoneypotEvent.service == "SSH").count()
    http_events = db.query(HoneypotEvent).filter(HoneypotEvent.service == "HTTP").count()
    
    critical_threats = db.query(HoneypotEvent).filter(HoneypotEvent.risk_level == "CRITICAL").count()
    high_threats = db.query(HoneypotEvent).filter(HoneypotEvent.risk_level == "HIGH").count()
    medium_threats = db.query(HoneypotEvent).filter(HoneypotEvent.risk_level == "MEDIUM").count()
    low_threats = db.query(HoneypotEvent).filter(HoneypotEvent.risk_level.in_(["LOW", "INFO"])).count()
    
    top_vector_row = db.query(
        HoneypotEvent.classification,
        func.count(HoneypotEvent.id).label("cnt")
    ).filter(
        HoneypotEvent.classification != "UNCLASSIFIED_INTERACTION"
    ).group_by(HoneypotEvent.classification).order_by(desc("cnt")).first()
    
    top_threat_vector = top_vector_row[0] if top_vector_row else "None Detected"
    
    return OverviewStats(
        total_events=total_events,
        unique_ips=unique_ips,
        ssh_events=ssh_events,
        http_events=http_events,
        critical_threats=critical_threats,
        high_threats=high_threats,
        medium_threats=medium_threats,
        low_threats=low_threats,
        top_threat_vector=top_threat_vector
    )

@router.get("/frequency", response_model=List[FrequencyPoint])
def get_frequency(minutes: int = 60, db: Session = Depends(get_db)):
    """
    Retrieve time-series buckets of attack events over the past N minutes.
    """
    now = datetime.utcnow()
    start_time = now - timedelta(minutes=minutes)
    
    events = db.query(
        HoneypotEvent.timestamp,
        HoneypotEvent.service
    ).filter(
        HoneypotEvent.timestamp >= start_time
    ).order_by(HoneypotEvent.timestamp.asc()).all()
    
    # Bucket events by minute or interval
    # Create 12 timeline slots across the requested period
    interval_sec = max(60, (minutes * 60) // 12)
    buckets = {}
    
    for i in range(13):
        t = start_time + timedelta(seconds=i * interval_sec)
        label = t.strftime("%H:%M")
        buckets[label] = {"ssh": 0, "http": 0}
        
    for ev_time, service in events:
        if ev_time:
            # Find closest slot
            slot_label = ev_time.strftime("%H:%M")
            if slot_label not in buckets:
                buckets[slot_label] = {"ssh": 0, "http": 0}
            if service == "SSH":
                buckets[slot_label]["ssh"] += 1
            else:
                buckets[slot_label]["http"] += 1
                
    points = []
    for label, counts in buckets.items():
        points.append(FrequencyPoint(
            time_bucket=label,
            ssh_count=counts["ssh"],
            http_count=counts["http"],
            total_count=counts["ssh"] + counts["http"]
        ))
        
    return points

@router.get("/credentials", response_model=List[CredentialStat])
def get_top_credentials(limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve top targeted usernames and passwords."""
    results = []
    
    total_usernames = db.query(HoneypotEvent).filter(HoneypotEvent.username.isnot(None), HoneypotEvent.username != "").count()
    if total_usernames > 0:
        top_users = db.query(
            HoneypotEvent.username,
            func.count(HoneypotEvent.id).label("cnt")
        ).filter(
            HoneypotEvent.username.isnot(None),
            HoneypotEvent.username != ""
        ).group_by(HoneypotEvent.username).order_by(desc("cnt")).limit(limit).all()
        
        for u, cnt in top_users:
            results.append(CredentialStat(
                credential=u,
                type="username",
                count=cnt,
                percentage=round((cnt / total_usernames) * 100, 1)
            ))
            
    total_passwords = db.query(HoneypotEvent).filter(HoneypotEvent.password.isnot(None), HoneypotEvent.password != "").count()
    if total_passwords > 0:
        top_passes = db.query(
            HoneypotEvent.password,
            func.count(HoneypotEvent.id).label("cnt")
        ).filter(
            HoneypotEvent.password.isnot(None),
            HoneypotEvent.password != ""
        ).group_by(HoneypotEvent.password).order_by(desc("cnt")).limit(limit).all()
        
        for p, cnt in top_passes:
            results.append(CredentialStat(
                credential=p,
                type="password",
                count=cnt,
                percentage=round((cnt / total_passwords) * 100, 1)
            ))
            
    return results

@router.get("/risk-matrix", response_model=List[RiskMatrixEntry])
def get_risk_matrix(db: Session = Depends(get_db)):
    """Retrieve classified attack patterns with risk severities and captured payload samples."""
    DESCRIPTIONS = {
        "SSH_BRUTE_FORCE": "High-frequency credential guessing targeting SSH daemon port",
        "COMMAND_INJECTION": "Execution attempt using bash, curl/wget droppers, or shell piping",
        "SQL_INJECTION": "Database manipulation attempt (UNION SELECT, OR '1'='1, sleep)",
        "BOTNET_RECON": "Automated security scanner or botnet probe (Nikto, sqlmap, Masscan)",
        "PATH_TRAVERSAL": "Directory traversal or sensitive file access (/.env, /etc/passwd)",
        "CREDENTIAL_STUFFING": "Automated credential spray against web authentication portals",
        "MALICIOUS_UPLOAD_ATTEMPT": "Payload delivery via multipart file upload endpoint",
        "SUSPICIOUS_PROBE": "Reconnaissance scan across exposed honeypot routes",
        "CREDENTIAL_PROBE": "Single unauthorized credential submission attempt",
        "UNAUTHORIZED_SHELL_ACTIVITY": "Commands executed within the fake shell sandbox",
        "UNCLASSIFIED_INTERACTION": "General unclassified network interaction"
    }
    
    rows = db.query(
        HoneypotEvent.classification,
        HoneypotEvent.risk_level,
        func.avg(HoneypotEvent.risk_score).label("avg_score"),
        func.count(HoneypotEvent.id).label("cnt")
    ).group_by(
        HoneypotEvent.classification,
        HoneypotEvent.risk_level
    ).order_by(desc("cnt")).all()
    
    matrix = []
    for classification, risk_level, avg_score, cnt in rows:
        # Fetch up to 3 sample payloads for this classification
        samples = db.query(HoneypotEvent.payload).filter(
            HoneypotEvent.classification == classification,
            HoneypotEvent.payload.isnot(None),
            HoneypotEvent.payload != ""
        ).limit(3).all()
        
        sample_list = [s[0] for s in samples if s[0]]
        if not sample_list:
            # Fallback to path or username if payload is empty
            alt_samples = db.query(HoneypotEvent.path, HoneypotEvent.username).filter(
                HoneypotEvent.classification == classification
            ).limit(2).all()
            sample_list = [f"path={p or '-'} user={u or '-'}" for p, u in alt_samples]

        matrix.append(RiskMatrixEntry(
            classification=classification,
            risk_level=risk_level,
            risk_score=int(avg_score or 10),
            count=cnt,
            description=DESCRIPTIONS.get(classification, "Classified threat interaction"),
            sample_payloads=sample_list
        ))
        
    return matrix

@router.get("/geo", response_model=List[GeoDistributionEntry])
def get_geo_distribution(db: Session = Depends(get_db)):
    """Retrieve geographic distribution of attacker source IPs."""
    rows = db.query(
        HoneypotEvent.geo_country,
        HoneypotEvent.geo_country_code,
        HoneypotEvent.geo_city,
        HoneypotEvent.geo_lat,
        HoneypotEvent.geo_lon,
        func.count(HoneypotEvent.id).label("cnt")
    ).group_by(
        HoneypotEvent.geo_country,
        HoneypotEvent.geo_country_code,
        HoneypotEvent.geo_city,
        HoneypotEvent.geo_lat,
        HoneypotEvent.geo_lon
    ).order_by(desc("cnt")).limit(20).all()
    
    geo_list = []
    for country, country_code, city, lat, lon, cnt in rows:
        ip_samples_rows = db.query(func.distinct(HoneypotEvent.source_ip)).filter(
            HoneypotEvent.geo_country == country,
            HoneypotEvent.geo_city == city
        ).limit(3).all()
        
        geo_list.append(GeoDistributionEntry(
            country=country or "Unknown",
            country_code=country_code or "XX",
            city=city or "Unknown",
            lat=lat,
            lon=lon,
            count=cnt,
            ip_samples=[ip[0] for ip in ip_samples_rows]
        ))
        
    return geo_list
