"""
Service Health & Status Monitoring Endpoints.
"""
from typing import List
from datetime import datetime, timedelta
import socket
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import HoneypotEvent
from ..schemas import ServiceStatus

router = APIRouter(prefix="/api/services", tags=["services"])

def check_tcp_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a local/container TCP port is reachable and accepting connections."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

@router.get("/status", response_model=List[ServiceStatus])
def get_service_statuses(db: Session = Depends(get_db)):
    """Check the status, event counts, and latest activity timestamps of all honeypot services."""
    services = []
    
    # 1. SSH Decoy
    ssh_count = db.query(HoneypotEvent).filter(HoneypotEvent.service == "SSH").count()
    last_ssh = db.query(HoneypotEvent.timestamp).filter(HoneypotEvent.service == "SSH").order_by(desc(HoneypotEvent.timestamp)).first()
    ssh_up = check_tcp_port("127.0.0.1", 2222) or check_tcp_port("honeypot-ssh", 22) or (last_ssh and last_ssh[0] > (datetime.utcnow() - timedelta(minutes=5)))
    
    services.append(ServiceStatus(
        name="SSH Decoy (Paramiko Honeynet)",
        type="SSH",
        port=2222,
        status="ONLINE" if ssh_up else "STANDBY",
        last_event_time=last_ssh[0] if last_ssh else None,
        event_count=ssh_count
    ))
    
    # 2. HTTP Decoy
    http_count = db.query(HoneypotEvent).filter(HoneypotEvent.service == "HTTP").count()
    last_http = db.query(HoneypotEvent.timestamp).filter(HoneypotEvent.service == "HTTP").order_by(desc(HoneypotEvent.timestamp)).first()
    http_up = check_tcp_port("127.0.0.1", 8080) or check_tcp_port("honeypot-http", 80) or (last_http and last_http[0] > (datetime.utcnow() - timedelta(minutes=5)))
    
    services.append(ServiceStatus(
        name="HTTP Web Decoy & Traps",
        type="HTTP",
        port=8080,
        status="ONLINE" if http_up else "STANDBY",
        last_event_time=last_http[0] if last_http else None,
        event_count=http_count
    ))
    
    # 3. Threat Engine
    services.append(ServiceStatus(
        name="Threat Intelligence & Rule Engine",
        type="ANALYTICS",
        port=8000,
        status="ONLINE",
        last_event_time=datetime.utcnow(),
        event_count=ssh_count + http_count
    ))
    
    return services
