"""
Durable event forwarding for decoys ("store-and-forward").

Problem solved: decoys used to POST each captured event once and silently drop it if the
backend was down/restarting, so attacker activity during an outage was lost forever.

Behaviour
  * send(event) tries the backend immediately (short timeout).
  * On network error / 5xx the event is appended to an on-disk JSONL spool (fsync'd).
  * A daemon thread retries with exponential backoff and replays the spool in batches
    to <BACKEND_API_URL>/batch, preserving the original capture time.
  * 4xx (other than 408/429) means the event itself is bad: it is dropped, never retried.
  * The spool survives decoy restarts; a half-finished replay is resumed on startup.

Environment
  SPOOL_DIR          directory for spool files (default: ./spool next to this file)
  SPOOL_MAX_EVENTS   cap on buffered events (default 100000); newest are dropped beyond it
  SPOOL_BATCH_SIZE   events per replay request (default 200)
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger("event_spool")


class EventForwarder:
    def __init__(self, backend_url: str, name: str, spool_dir: Optional[str] = None,
                 timeout: float = 2.0, base_backoff: float = 1.0, max_backoff: float = 30.0):
        self.backend_url = backend_url
        self.batch_url = backend_url.rstrip("/") + "/batch"
        self.timeout = timeout
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self.max_events = int(os.getenv("SPOOL_MAX_EVENTS", "100000"))
        self.batch_size = int(os.getenv("SPOOL_BATCH_SIZE", "200"))

        spool_dir = spool_dir or os.getenv("SPOOL_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "spool")
        os.makedirs(spool_dir, exist_ok=True)
        self.spool_file = os.path.join(spool_dir, f"{name}.spool.jsonl")
        self.replay_file = os.path.join(spool_dir, f"{name}.replaying.jsonl")

        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = {"sent": 0, "spooled": 0, "replayed": 0, "dropped": 0}

    # ------------------------------------------------------------------ public
    def send(self, event: dict) -> bool:
        """Forward an event; buffer it durably if the backend can't take it. Returns True if delivered now."""
        # While a backlog exists keep ordering by queueing behind it instead of jumping ahead.
        if self.pending() == 0:
            outcome = self._post_single(event)
            if outcome == "ok":
                self.stats["sent"] += 1
                return True
            if outcome == "reject":
                self.stats["dropped"] += 1
                logger.warning("Backend rejected event as invalid; dropping it")
                return False
        self._spool(event)
        self._ensure_thread()
        self._wake.set()
        return False

    def pending(self) -> int:
        with self._lock:
            return self._count(self.spool_file) + self._count(self.replay_file)

    def start(self) -> None:
        """Resume any backlog left by a previous run."""
        if self.pending() > 0:
            logger.info("Found %d buffered events from a previous run; will replay", self.pending())
            self._ensure_thread()
            self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def flush_once(self) -> bool:
        """Try to replay the whole backlog now. Returns True when the backlog is empty."""
        return self._replay()

    # ----------------------------------------------------------------- internals
    def _post_single(self, event: dict) -> str:
        try:
            resp = requests.post(self.backend_url, json=event, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("Backend unreachable (%s)", exc)
            return "retry"
        if resp.status_code in (200, 201):
            return "ok"
        if resp.status_code in (408, 429) or resp.status_code >= 500:
            return "retry"
        return "reject"

    @staticmethod
    def _count(path: str) -> int:
        try:
            with open(path, "rb") as fh:
                return sum(1 for line in fh if line.strip())
        except FileNotFoundError:
            return 0

    def _spool(self, event: dict) -> None:
        record = dict(event)
        record.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        line = json.dumps(record, default=str, separators=(",", ":")) + "\n"
        with self._lock:
            if self._count(self.spool_file) + self._count(self.replay_file) >= self.max_events:
                self.stats["dropped"] += 1
                logger.error("Spool full (%d events); dropping event", self.max_events)
                return
            with open(self.spool_file, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            self.stats["spooled"] += 1

    def _ensure_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="event-spool-replay", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        delay = self.base_backoff
        while not self._stop.is_set():
            self._wake.wait(timeout=delay)
            self._wake.clear()
            if self._stop.is_set():
                return
            if self.pending() == 0:
                delay = self.base_backoff
                continue
            if self._replay():
                logger.info("Replay complete; spool empty (replayed so far: %d)", self.stats["replayed"])
                delay = self.base_backoff
            else:
                delay = min(delay * 2, self.max_backoff)
                logger.info("Backend still unavailable; %d events buffered, retrying in %.0fs", self.pending(), delay)

    def _replay(self) -> bool:
        # Move new spool contents behind any interrupted replay, atomically w.r.t. writers.
        with self._lock:
            if os.path.exists(self.spool_file):
                with open(self.spool_file, "rb") as src, open(self.replay_file, "ab") as dst:
                    dst.write(src.read())
                    dst.flush()
                    os.fsync(dst.fileno())
                os.remove(self.spool_file)
            if not os.path.exists(self.replay_file):
                return True
            with open(self.replay_file, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]

        while lines:
            batch_lines = lines[: self.batch_size]
            events = []
            for ln in batch_lines:
                try:
                    events.append(json.loads(ln))
                except ValueError:
                    self.stats["dropped"] += 1     # torn write from a crash: unusable, skip
            try:
                resp = requests.post(self.batch_url, json=events, timeout=max(self.timeout, 15.0)) if events else None
            except requests.RequestException:
                break
            if resp is not None and not (200 <= resp.status_code < 300):
                if resp.status_code in (408, 429) or resp.status_code >= 500:
                    break
                # Non-retryable client error for the whole batch: drop it so it cannot wedge the queue.
                logger.error("Backend refused batch with HTTP %d; dropping %d events", resp.status_code, len(events))
                self.stats["dropped"] += len(events)
            elif resp is not None:
                self.stats["replayed"] += len(events)
            lines = lines[len(batch_lines):]
            self._rewrite_replay(lines)

        if not lines:
            self._rewrite_replay([])
            return True
        return False

    def _rewrite_replay(self, remaining: list) -> None:
        with self._lock:
            if not remaining:
                try:
                    os.remove(self.replay_file)
                except FileNotFoundError:
                    pass
                return
            tmp = self.replay_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(remaining) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.replay_file)
