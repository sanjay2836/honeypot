"""
Events ingestion and query endpoints.
"""
from typing import Any, Dict, List, Optional
import json
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import HoneypotEvent
from ..schemas import EventCreate, EventOut
from ..classifier import classify_event
from ..geoip import resolve_ip_geo
from ..ws_manager import ws_manager

logger = logging.getLogger("honeypot.events")
router = APIRouter(prefix="/api/events", tags=["events"])

def _persist_event(event_in: EventCreate, db: Session) -> dict:
    """Classify, enrich and store one event. Returns the serialised event."""
    event_dict = event_in.model_dump()

    # 1. Classify threat
    classification_res = classify_event(event_dict, db=db)

    # 2. Enrich with GeoIP
    geo_res = resolve_ip_geo(event_in.source_ip)

    # 3. Create DB Model (replayed events keep their original capture time)
    ts = event_in.timestamp
    if ts is not None and ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)

    db_event = HoneypotEvent(
        timestamp=ts or datetime.utcnow(),
        source_ip=event_in.source_ip,
        source_port=event_in.source_port,
        service=event_in.service.upper(),
        event_type=event_in.event_type.upper(),
        username=event_in.username,
        password=event_in.password,
        payload=event_in.payload,
        user_agent=event_in.user_agent,
        path=event_in.path,
        request_method=event_in.request_method,
        session_id=event_in.session_id,
        raw_details=json.dumps(event_in.details) if event_in.details else None,

        # Classification
        classification=classification_res["classification"],
        risk_score=classification_res["risk_score"],
        risk_level=classification_res["risk_level"],
        matched_rule=classification_res["matched_rule"],

        # Geo
        geo_country=geo_res.get("country", "Unknown"),
        geo_country_code=geo_res.get("country_code", "XX"),
        geo_city=geo_res.get("city", "Unknown"),
        geo_lat=geo_res.get("lat"),
        geo_lon=geo_res.get("lon"),
        geo_org=geo_res.get("org", "Unknown"),
    )

    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event.to_dict()


@router.post("", response_model=EventOut, status_code=201)
async def ingest_event(event_in: EventCreate, db: Session = Depends(get_db)):
    """
    Ingest a raw event from any decoy service (SSH or HTTP).
    Enriches with GeoIP, classifies attack vectors/risk scores, persists to DB,
    and broadcasts live to all connected dashboard WebSockets.
    """
    event_dict_out = _persist_event(event_in, db)

    # Real-time broadcast to all dashboard clients
    await ws_manager.broadcast_event(event_dict_out)

    return event_dict_out


@router.post("/batch")
async def ingest_event_batch(events: List[Dict[str, Any]] = Body(...), db: Session = Depends(get_db)):
    """
    Bulk-ingest events that decoys buffered on disk while the backend was unreachable.
    Each event is validated independently: malformed ones are counted as `rejected`
    (so a poison record can never block the replay queue) and the rest are stored.
    """
    accepted, rejected = 0, 0
    for raw in events:
        try:
            event_in = EventCreate.model_validate(raw)
            out = _persist_event(event_in, db)
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            rejected += 1
            logger.warning("Rejected replayed event: %s", exc)
            continue
        accepted += 1
        await ws_manager.broadcast_event(out)
    return {"accepted": accepted, "rejected": rejected}

@router.get("", response_model=List[EventOut])
def get_events(
    service: Optional[str] = None,
    risk_level: Optional[str] = None,
    classification: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    """List captured events with optional filtering."""
    query = db.query(HoneypotEvent)
    
    if service:
        query = query.filter(HoneypotEvent.service == service.upper())
    if risk_level:
        query = query.filter(HoneypotEvent.risk_level == risk_level.upper())
    if classification:
        query = query.filter(HoneypotEvent.classification == classification)
    if source_ip:
        query = query.filter(HoneypotEvent.source_ip == source_ip)
        
    events = query.order_by(desc(HoneypotEvent.timestamp)).offset(offset).limit(limit).all()
    return [e.to_dict() for e in events]

@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db)):
    """Retrieve details for a single honeypot event."""
    event = db.query(HoneypotEvent).filter(HoneypotEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event.to_dict()

@router.delete("", status_code=200)
def clear_events(db: Session = Depends(get_db)):
    """Reset / clear database events (useful for resetting lab sessions)."""
    count = db.query(HoneypotEvent).delete()
    db.commit()
    return {"status": "success", "cleared_events_count": count}
