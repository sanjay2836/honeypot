"""Store-and-forward tests for the decoy event spool (backend outage -> buffer -> replay)."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "decoys", "ssh_decoy"))
from event_spool import EventForwarder  # noqa: E402


class FakeBackend:
    """Tiny HTTP server standing in for the analytics backend."""

    def __init__(self, single_status=201, batch_status=200):
        outer = self
        self.single, self.batches = [], []
        self.single_status, self.batch_status = single_status, batch_status

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path.endswith("/batch"):
                    outer.batches.append(body)
                    code = outer.batch_status
                else:
                    outer.single.append(body)
                    code = outer.single_status
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/events"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def event(n):
    return {"source_ip": f"198.51.100.{n}", "service": "SSH", "event_type": "LOGIN_ATTEMPT"}


def test_delivers_directly_when_backend_up(tmp_path):
    be = FakeBackend()
    try:
        fwd = EventForwarder(be.url, "t", spool_dir=str(tmp_path))
        assert fwd.send(event(1)) is True
        assert fwd.pending() == 0 and len(be.single) == 1
    finally:
        be.close()


def test_buffers_when_down_then_replays_in_order_with_timestamps(tmp_path):
    # Reserve a port nobody listens on -> connection refused
    dead = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = dead.server_port
    dead.server_close()
    fwd = EventForwarder(f"http://127.0.0.1:{port}/api/events", "t", spool_dir=str(tmp_path), timeout=0.5)
    for n in range(1, 4):
        assert fwd.send(event(n)) is False
    fwd.stop()
    assert fwd.pending() == 3

    # "Backend comes back": point a forwarder at it over the same spool dir (also proves restart-survival)
    be = FakeBackend()
    try:
        fwd2 = EventForwarder(be.url, "t", spool_dir=str(tmp_path))
        assert fwd2.pending() == 3
        assert fwd2.flush_once() is True
        assert fwd2.pending() == 0
        replayed = [e for batch in be.batches for e in batch]
        assert [e["source_ip"] for e in replayed] == ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
        assert all("timestamp" in e for e in replayed)
    finally:
        be.close()


def test_replay_keeps_events_on_5xx(tmp_path):
    be = FakeBackend(single_status=503, batch_status=503)
    try:
        fwd = EventForwarder(be.url, "t", spool_dir=str(tmp_path))
        fwd.send(event(1))
        fwd.stop()
        assert fwd.flush_once() is False
        assert fwd.pending() == 1                 # nothing lost
    finally:
        be.close()


def test_4xx_event_is_dropped_not_retried_forever(tmp_path):
    be = FakeBackend(single_status=422)
    try:
        fwd = EventForwarder(be.url, "t", spool_dir=str(tmp_path))
        assert fwd.send(event(1)) is False
        assert fwd.pending() == 0 and fwd.stats["dropped"] == 1
    finally:
        be.close()


def test_torn_line_from_crash_is_skipped(tmp_path):
    be = FakeBackend()
    try:
        fwd = EventForwarder(be.url, "t", spool_dir=str(tmp_path))
        with open(fwd.spool_file, "w") as fh:
            fh.write(json.dumps(event(1)) + "\n")
            fh.write('{"source_ip": "198.51.1')       # truncated mid-write
        assert fwd.flush_once() is True
        assert sum(len(b) for b in be.batches) == 1
    finally:
        be.close()


def test_spool_cap_drops_newest(tmp_path, monkeypatch):
    monkeypatch.setenv("SPOOL_MAX_EVENTS", "2")
    dead = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = dead.server_port
    dead.server_close()
    fwd = EventForwarder(f"http://127.0.0.1:{port}/api/events", "t", spool_dir=str(tmp_path), timeout=0.3)
    for n in range(4):
        fwd.send(event(n))
    fwd.stop()
    assert fwd.pending() == 2 and fwd.stats["dropped"] == 2
