"""
Tests for the recovery subsystem: integrity checks, backups, rotation, restore and auto-recovery.
All tests use throw-away SQLite files; the real honeypot.db is never touched.
"""
import os
import sqlite3
import pytest

from app import recovery


def make_db(path, rows=5):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE honeypot_events (id INTEGER PRIMARY KEY, source_ip TEXT)")
    conn.executemany("INSERT INTO honeypot_events (source_ip) VALUES (?)", [(f"10.0.0.{i}",) for i in range(rows)])
    conn.commit()
    conn.close()


def count_rows(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM honeypot_events").fetchone()[0]
    finally:
        conn.close()


def corrupt(path):
    with open(path, "r+b") as fh:
        fh.seek(0)
        fh.write(b"THIS IS NOT A SQLITE DATABASE" * 200)


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = str(tmp_path / "honeypot.db")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("BACKUP_KEEP", "3")
    # make the module think our temp file is "the" database
    monkeypatch.setattr(recovery, "db_path", lambda: db)
    make_db(db)
    return db


def test_integrity_ok_and_corrupt(env):
    assert recovery.check_integrity(env)["ok"] is True
    corrupt(env)
    assert recovery.check_integrity(env)["ok"] is False


def test_missing_db_is_not_an_error(tmp_path):
    result = recovery.check_integrity(str(tmp_path / "nope.db"))
    assert result["ok"] is True and result["exists"] is False


def test_backup_is_verified_and_complete(env):
    res = recovery.create_backup("manual", env)
    assert res["ok"], res
    backups = recovery.list_backups(env)
    assert len(backups) == 1
    assert count_rows(os.path.join(recovery.backup_dir(env), backups[0]["name"])) == 5


def test_backup_rotation_keeps_newest(env):
    for _ in range(6):
        assert recovery.create_backup("auto", env)["ok"]
    names = [b["name"] for b in recovery.list_backups(env)]
    assert len(names) == 3
    assert names == sorted(names, reverse=True)


def test_auto_recover_noop_when_healthy(env):
    assert recovery.auto_recover(env)["action"] == "none"


def test_auto_recover_restores_latest_good_backup(env):
    recovery.create_backup("auto", env)
    corrupt(env)
    out = recovery.auto_recover(env)
    assert out["action"] == "restored-from-backup"
    assert recovery.check_integrity(env)["ok"]
    assert count_rows(env) == 5
    assert out["quarantined_file"] and os.path.exists(out["quarantined_file"])  # evidence preserved


def test_auto_recover_skips_bad_backup_and_uses_older_one(env):
    recovery.create_backup("auto", env)          # good (older)
    recovery.create_backup("auto", env)          # will be damaged (newer)
    newest = recovery.list_backups(env)[0]["name"]
    corrupt(os.path.join(recovery.backup_dir(env), newest))
    corrupt(env)
    out = recovery.auto_recover(env)
    assert out["action"] == "restored-from-backup"
    assert out["restored_from"] != newest
    assert count_rows(env) == 5


def test_auto_recover_without_backups_starts_fresh(env):
    corrupt(env)
    out = recovery.auto_recover(env)
    assert out["action"] == "fresh-database"
    assert not os.path.exists(env)               # init_db() will recreate it
    assert out["quarantined_file"]


def test_manual_restore_takes_safety_snapshot(env):
    recovery.create_backup("manual", env)
    name = recovery.list_backups(env)[0]["name"]
    conn = sqlite3.connect(env)
    conn.execute("DELETE FROM honeypot_events")
    conn.commit()
    conn.close()
    res = recovery.restore_backup(name, env)
    assert res["ok"] and res["safety_backup"]
    assert count_rows(env) == 5


@pytest.mark.parametrize("bad", ["../../etc/passwd", "honeypot.db", "", "x/../y.db"])
def test_restore_rejects_path_tricks(env, bad):
    assert recovery.restore_backup(bad, env)["ok"] is False


def test_restore_refuses_corrupt_backup(env):
    recovery.create_backup("manual", env)
    name = recovery.list_backups(env)[0]["name"]
    corrupt(os.path.join(recovery.backup_dir(env), name))
    res = recovery.restore_backup(name, env)
    assert res["ok"] is False
    assert count_rows(env) == 5                  # live DB untouched
