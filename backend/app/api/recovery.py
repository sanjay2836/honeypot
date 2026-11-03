"""
Recovery & resilience endpoints.

If RECOVERY_API_TOKEN is set, mutating endpoints require header `X-Recovery-Token`.
"""
import os
import hmac
from typing import Optional
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import recovery

router = APIRouter(prefix="/api/recovery", tags=["recovery"])


def _authorize(token: Optional[str]) -> None:
    expected = os.getenv("RECOVERY_API_TOKEN")
    if expected and not hmac.compare_digest(expected, token or ""):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Recovery-Token")


class RestoreRequest(BaseModel):
    name: str


@router.get("/status")
def recovery_status():
    """Backup inventory, last integrity check, last recovery, retention settings."""
    return recovery.status()


@router.get("/backups")
def list_backups():
    return recovery.list_backups()


@router.post("/verify")
def verify_database():
    """Run an integrity check now (does not change anything)."""
    return recovery.verify_and_record()


@router.post("/backup", status_code=201)
def create_backup(x_recovery_token: Optional[str] = Header(default=None)):
    """Take a verified snapshot right now."""
    _authorize(x_recovery_token)
    result = recovery.create_backup(label="manual")
    if not result["ok"]:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@router.post("/restore")
def restore_backup(body: RestoreRequest, x_recovery_token: Optional[str] = Header(default=None)):
    """Replace the live database with a named snapshot (a pre-restore snapshot is taken first)."""
    _authorize(x_recovery_token)
    result = recovery.restore_backup(body.name)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/auto-recover")
def run_auto_recover(x_recovery_token: Optional[str] = Header(default=None)):
    """Check integrity and, only if the database is damaged, quarantine it and restore the newest good snapshot."""
    _authorize(x_recovery_token)
    return recovery.auto_recover()
