"""
Recovery subsystem for the Honeypot threat store.

Responsibilities
  1. Integrity verification of the SQLite threat store (PRAGMA integrity_check).
  2. Consistent online snapshots (sqlite3 backup API - safe while the DB is in use),
     verified after writing, with rotation.
  3. Restore from a snapshot (with a safety snapshot of the current DB first).
  4. Automatic recovery on startup / periodically: if the DB is corrupt it is
     quarantined and the newest healthy snapshot is restored (or a fresh DB is
     started if none exists).

Only SQLite is handled here. For PostgreSQL (DATABASE_URL) use pg_dump / PITR;
every function degrades to a harmless "unsupported" result in that case.

Configuration (environment variables, read at call time)
  BACKUP_DIR                 default: <db directory>/backups
  BACKUP_KEEP                snapshots to retain (default 10)
  BACKUP_INTERVAL_SECONDS    periodic snapshot interval (default 900, 0 = off)
  INTEGRITY_INTERVAL_SECONDS periodic integrity check interval (default 300, 0 = off)
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("honeypot.recovery")

_lock = threading.RLock()
_BACKUP_RE = re.compile(r"^honeypot-\d{8}T\d{6}\d{0,6}Z-[a-z\-]+\.db$")

# In-memory state exposed through /api/recovery/status
STATE: Dict[str, Any] = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "last_integrity_check": None,
    "last_integrity_ok": None,
    "last_backup": None,
    "last_backup_error": None,
    "last_recovery": None,      # dict describing the most recent automatic/manual recovery
    "recoveries_total": 0,
    "backups_total": 0,
}


# --------------------------------------------------------------------------- #
# Paths / config
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_path() -> Optional[str]:
    """Absolute path of the SQLite file, or None for non-SQLite / in-memory DBs."""
    from .database import engine

    if engine.dialect.name != "sqlite":
        return None
    database = engine.url.database
    if not database or database == ":memory:":
        return None
    return os.path.abspath(database)


def backup_dir(path: Optional[str] = None) -> str:
    configured = os.getenv("BACKUP_DIR")
    if configured:
        return os.path.abspath(configured)
    base = os.path.dirname(path or db_path() or os.getcwd())
    return os.path.join(base, "backups")


def _keep() -> int:
    try:
        return max(1, int(os.getenv("BACKUP_KEEP", "10")))
    except ValueError:
        return 10


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


# --------------------------------------------------------------------------- #
# Integrity
# --------------------------------------------------------------------------- #
def check_integrity(path: Optional[str] = None) -> Dict[str, Any]:
    """Run PRAGMA integrity_check on a SQLite file (read-only)."""
    path = path or db_path()
    if path is None:
        return {"ok": True, "supported": False, "detail": "non-SQLite database; integrity check skipped"}
    if not os.path.exists(path):
        return {"ok": True, "supported": True, "exists": False, "detail": "database file does not exist yet"}
    try:
        uri = f"file:{path.replace(os.sep, '/')}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
        finally:
            conn.close()
        detail = "; ".join(r[0] for r in rows)
        return {"ok": detail == "ok", "supported": True, "exists": True, "detail": detail}
    except sqlite3.Error as exc:
        return {"ok": False, "supported": True, "exists": True, "detail": f"{type(exc).__name__}: {exc}"}


def verify_and_record(path: Optional[str] = None) -> Dict[str, Any]:
    result = check_integrity(path)
    STATE["last_integrity_check"] = _now()
    STATE["last_integrity_ok"] = result["ok"]
    return result


# --------------------------------------------------------------------------- #
# Backups
# --------------------------------------------------------------------------- #
def list_backups(path: Optional[str] = None) -> List[Dict[str, Any]]:
    directory = backup_dir(path)
    if not os.path.isdir(directory):
        return []
    items = []
    for name in os.listdir(directory):
        if not _BACKUP_RE.match(name):
            continue
        full = os.path.join(directory, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        items.append({
            "name": name,
            "size_bytes": st.st_size,
            "created_at": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
        })
    items.sort(key=lambda i: i["name"], reverse=True)  # names embed a UTC timestamp
    return items


def _rotate(path: Optional[str] = None) -> None:
    for old in list_backups(path)[_keep():]:
        try:
            os.remove(os.path.join(backup_dir(path), old["name"]))
        except OSError as exc:
            logger.warning("Could not remove old backup %s: %s", old["name"], exc)


def create_backup(label: str = "auto", path: Optional[str] = None) -> Dict[str, Any]:
    """Create a verified, consistent snapshot of the live database."""
    path = path or db_path()
    if path is None:
        return {"ok": False, "error": "backups are only supported for SQLite databases"}
    if not os.path.exists(path):
        return {"ok": False, "error": "database file does not exist"}

    label = re.sub(r"[^a-z\-]", "", label.lower()) or "manual"
    directory = backup_dir(path)
    os.makedirs(directory, exist_ok=True)
    # microseconds in the name so rapid snapshots never collide
    name = f"honeypot-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}Z-{label}.db"
    target = os.path.join(directory, name)
    tmp = target + ".tmp"

    with _lock:
        try:
            src = sqlite3.connect(path, timeout=30)
            try:
                dst = sqlite3.connect(tmp)
                try:
                    src.backup(dst)          # consistent even while writers are active
                finally:
                    dst.close()
            finally:
                src.close()

            check = check_integrity(tmp)
            if not check["ok"]:
                os.remove(tmp)
                raise sqlite3.DatabaseError(f"snapshot failed verification: {check['detail']}")

            os.replace(tmp, target)
            _rotate(path)
            STATE["last_backup"] = {"name": name, "at": _now(), "label": label}
            STATE["last_backup_error"] = None
            STATE["backups_total"] += 1
            logger.info("Backup created: %s", name)
            return {"ok": True, "name": name, "size_bytes": os.path.getsize(target)}
        except Exception as exc:  # noqa: BLE001 - we never want a backup to crash the app
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            STATE["last_backup_error"] = f"{type(exc).__name__}: {exc}"
            logger.error("Backup failed: %s", exc)
            return {"ok": False, "error": STATE["last_backup_error"]}


# --------------------------------------------------------------------------- #
# Restore / recovery
# --------------------------------------------------------------------------- #
def _resolve_backup(name: str, path: Optional[str] = None) -> str:
    if not _BACKUP_RE.match(name or ""):
        raise ValueError("invalid backup name")
    full = os.path.join(backup_dir(path), name)
    if not os.path.isfile(full):
        raise FileNotFoundError(f"backup not found: {name}")
    return full


def _swap_in(source: str, path: str) -> None:
    """Atomically replace the DB file with `source` (copied) and clear stale WAL/SHM files."""
    from .database import engine

    engine.dispose()                          # drop pooled connections to the old file
    staging = path + ".restoring"
    shutil.copy2(source, staging)
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass
    os.replace(staging, path)


def restore_backup(name: str, path: Optional[str] = None) -> Dict[str, Any]:
    """Restore a named snapshot over the live database."""
    path = path or db_path()
    if path is None:
        return {"ok": False, "error": "restore is only supported for SQLite databases"}
    try:
        source = _resolve_backup(name, path)
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}

    check = check_integrity(source)
    if not check["ok"]:
        return {"ok": False, "error": f"backup failed integrity check: {check['detail']}"}

    with _lock:
        safety = None
        if os.path.exists(path) and check_integrity(path)["ok"]:
            safety = create_backup(label="pre-restore", path=path)
        _swap_in(source, path)

    after = check_integrity(path)
    STATE["recoveries_total"] += 1
    STATE["last_recovery"] = {
        "at": _now(), "mode": "manual-restore", "restored_from": name,
        "safety_backup": safety.get("name") if safety and safety.get("ok") else None,
        "ok": after["ok"],
    }
    logger.warning("Database restored from %s", name)
    return {"ok": after["ok"], "restored_from": name, "safety_backup": STATE["last_recovery"]["safety_backup"]}


def _quarantine(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    target = f"{path}.corrupt-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    os.replace(path, target)
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass
    return target


def auto_recover(path: Optional[str] = None) -> Dict[str, Any]:
    """
    If the DB is unhealthy: quarantine it, then restore the newest healthy snapshot.
    With no usable snapshot a fresh (empty) database is started by init_db().
    Healthy DB -> no-op.
    """
    path = path or db_path()
    result = verify_and_record(path)
    if result["ok"]:
        return {"action": "none", "ok": True, "detail": result["detail"]}

    logger.error("Database integrity check FAILED (%s) - starting recovery", result["detail"])
    with _lock:
        quarantined = _quarantine(path)
        restored_from = None
        for item in list_backups(path):                    # newest first
            candidate = os.path.join(backup_dir(path), item["name"])
            if check_integrity(candidate)["ok"]:
                _swap_in(candidate, path)
                restored_from = item["name"]
                break
            logger.warning("Skipping unhealthy backup %s", item["name"])
        if restored_from is None:
            from .database import engine
            engine.dispose()

    action = "restored-from-backup" if restored_from else "fresh-database"
    STATE["recoveries_total"] += 1
    STATE["last_integrity_ok"] = True if restored_from else None
    STATE["last_recovery"] = {
        "at": _now(), "mode": "automatic", "action": action,
        "restored_from": restored_from, "quarantined_file": quarantined,
        "reason": result["detail"], "ok": True,
    }
    logger.warning("Recovery complete: %s (quarantined=%s, restored_from=%s)", action, quarantined, restored_from)
    return {"action": action, "ok": True, "restored_from": restored_from, "quarantined_file": quarantined}


# --------------------------------------------------------------------------- #
# Background maintenance
# --------------------------------------------------------------------------- #
async def maintenance_loop() -> None:
    """Periodic integrity checks + snapshots. Cancelled on shutdown."""
    backup_every = _float_env("BACKUP_INTERVAL_SECONDS", 900)
    check_every = _float_env("INTEGRITY_INTERVAL_SECONDS", 300)
    if backup_every <= 0 and check_every <= 0:
        return

    tick = max(1.0, min(x for x in (backup_every, check_every) if x > 0) / 2)
    loop = asyncio.get_running_loop()
    last_backup = last_check = loop.time()

    while True:
        await asyncio.sleep(tick)
        now = loop.time()
        try:
            if check_every > 0 and now - last_check >= check_every:
                last_check = now
                outcome = await asyncio.to_thread(auto_recover)
                if outcome["action"] != "none":
                    logger.warning("Maintenance loop triggered recovery: %s", outcome)
            if backup_every > 0 and now - last_backup >= backup_every:
                last_backup = now
                await asyncio.to_thread(create_backup, "auto")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("Recovery maintenance error: %s", exc)


def status() -> Dict[str, Any]:
    path = db_path()
    return {
        "database": {
            "engine": "sqlite" if path else "other",
            "path": path,
            "size_bytes": os.path.getsize(path) if path and os.path.exists(path) else None,
        },
        "backup_dir": backup_dir(path) if path else None,
        "backups": list_backups(path) if path else [],
        "retention": _keep(),
        "intervals": {
            "backup_seconds": _float_env("BACKUP_INTERVAL_SECONDS", 900),
            "integrity_seconds": _float_env("INTEGRITY_INTERVAL_SECONDS", 300),
        },
        **STATE,
    }
