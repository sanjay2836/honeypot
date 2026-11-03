"""API-level tests for /api/recovery/* and the replay endpoint /api/events/batch."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    init_db()
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.delenv("RECOVERY_API_TOKEN", raising=False)


def test_status_shape():
    data = client.get("/api/recovery/status").json()
    for key in ("database", "backups", "retention", "intervals", "recoveries_total"):
        assert key in data


def test_verify_reports_ok():
    assert client.post("/api/recovery/verify").json()["ok"] is True


def test_backup_then_list_then_restore():
    created = client.post("/api/recovery/backup")
    assert created.status_code == 201
    name = created.json()["name"]
    assert any(b["name"] == name for b in client.get("/api/recovery/backups").json())
    restored = client.post("/api/recovery/restore", json={"name": name})
    assert restored.status_code == 200 and restored.json()["ok"]
    # app still serves requests after the swap
    assert client.get("/api/events?limit=1").status_code == 200


def test_restore_unknown_backup_is_400():
    r = client.post("/api/recovery/restore", json={"name": "../../etc/passwd"})
    assert r.status_code == 400


def test_token_protects_mutations(monkeypatch):
    monkeypatch.setenv("RECOVERY_API_TOKEN", "s3cret")
    assert client.post("/api/recovery/backup").status_code == 401
    assert client.post("/api/recovery/backup", headers={"X-Recovery-Token": "s3cret"}).status_code == 201
    assert client.get("/api/recovery/status").status_code == 200   # read-only stays open


def test_batch_replay_accepts_good_and_rejects_bad_and_keeps_timestamp():
    good = {"source_ip": "203.0.113.9", "service": "HTTP", "event_type": "WEB_REQUEST",
            "payload": "GET /.env", "path": "/.env", "request_method": "GET",
            "timestamp": "2026-01-02T03:04:05+00:00"}
    bad = {"service": "HTTP"}  # missing required fields
    r = client.post("/api/events/batch", json=[good, bad])
    assert r.status_code == 200
    assert r.json() == {"accepted": 1, "rejected": 1}
    events = client.get("/api/events?source_ip=203.0.113.9&limit=1").json()
    assert events[0]["timestamp"].startswith("2026-01-02T03:04:05")
