"""
Unified Multi-Service Honeypot Runner  (self-healing supervisor)

Starts and *supervises* all honeypot components for local lab research:
  1. Backend Threat Analytics & Dashboard  (port 8000)
  2. SSH Decoy Honeypot                    (port 2222)
  3. HTTP Decoy Honeypot                   (port 8080)

Recovery behaviour
  * A crashed service is restarted on its own with exponential backoff
    (1s, 2s, 4s ... capped at 60s). Other services keep running - the old
    behaviour of tearing everything down when one process died is gone.
  * A service whose process is alive but whose port stops answering (hung) is
    killed and restarted after HEALTH_FAILURES consecutive failed probes.
  * A service that ran stably for 60s has its backoff reset.
  * A crash-looping service (> MAX_RESTARTS_PER_HOUR) is parked as FAILED
    instead of burning CPU; the rest of the system stays up.
  * Decoys buffer events to disk while the backend is down and replay them when
    it returns (see decoys/*/event_spool.py), so a backend restart loses nothing.

Environment overrides
  MAX_RESTARTS_PER_HOUR (default 20)   HEALTH_INTERVAL (default 10s)
  HEALTH_FAILURES (default 3)          STARTUP_GRACE (default 20s)
"""
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from collections import deque

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

MAX_RESTARTS_PER_HOUR = int(os.getenv("MAX_RESTARTS_PER_HOUR", "20"))
HEALTH_INTERVAL = float(os.getenv("HEALTH_INTERVAL", "10"))
HEALTH_FAILURES = int(os.getenv("HEALTH_FAILURES", "3"))
STARTUP_GRACE = float(os.getenv("STARTUP_GRACE", "20"))
STABLE_AFTER = 60.0
MAX_BACKOFF = 60.0


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Service:
    def __init__(self, name, cmd, cwd, env, port, probe="tcp"):
        self.name, self.cmd, self.cwd, self.env, self.port, self.probe = name, cmd, cwd, env, port, probe
        self.proc = None
        self.started_at = 0.0
        self.backoff = 1.0
        self.next_start = 0.0           # 0 => start immediately
        self.restarts = deque()         # timestamps of restarts within the last hour
        self.health_failures = 0
        self.failed = False             # parked after crash-looping

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        self.proc = subprocess.Popen(self.cmd, cwd=self.cwd, env=self.env)
        self.started_at = time.time()
        self.health_failures = 0
        log(f"[+] {self.name} started (pid {self.proc.pid}, port {self.port})")

    def stop(self, force: bool = False) -> None:
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            self.proc.kill() if force else self.proc.terminate()
        except Exception:
            pass

    def port_open(self) -> bool:
        """
        Liveness probe. A plain TCP connect succeeds even if the app is wedged (the kernel
        accepts into the backlog), so use the strongest check that creates no false events:
          http       - GET the backend status endpoint, expect 200 (proves the app answers)
          ssh-banner - connect and wait for the server's SSH banner (proves the accept loop runs)
          tcp        - connect only (HTTP decoy: a real GET would be logged as an attack event)
        """
        try:
            if self.probe == "http":
                url = f"http://127.0.0.1:{self.port}/api/recovery/status"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    return resp.status == 200
            with socket.create_connection(("127.0.0.1", self.port), timeout=3) as sock:
                if self.probe == "ssh-banner":
                    sock.settimeout(5)
                    return sock.recv(4).startswith(b"SSH-")
                return True
        except Exception:
            return False

    # -- supervision ---------------------------------------------------------
    def schedule_restart(self, reason: str) -> None:
        now = time.time()
        if now - self.started_at >= STABLE_AFTER:
            self.backoff = 1.0          # it was healthy for a while: treat as a fresh failure
        while self.restarts and now - self.restarts[0] > 3600:
            self.restarts.popleft()
        if len(self.restarts) >= MAX_RESTARTS_PER_HOUR:
            self.failed = True
            log(f"[X] {self.name} crash-looping ({len(self.restarts)} restarts in the last hour) - "
                f"parking it as FAILED. Other services keep running; fix the cause and restart run_all.py.")
            return
        self.restarts.append(now)
        self.next_start = now + self.backoff
        log(f"[!] {self.name} {reason}; restarting in {self.backoff:.0f}s "
            f"(restart #{len(self.restarts)} this hour)")
        self.backoff = min(self.backoff * 2, MAX_BACKOFF)
        self.proc = None

    def tick(self) -> None:
        if self.failed:
            return
        now = time.time()

        if self.proc is None:           # waiting for (re)start
            if now >= self.next_start:
                try:
                    self.start()
                except Exception as exc:
                    log(f"[!] {self.name} failed to launch: {exc}")
                    self.started_at = now
                    self.schedule_restart("could not be launched")
            return

        code = self.proc.poll()
        if code is not None:
            self.schedule_restart(f"exited with code {code}")
            return


class Supervisor:
    def __init__(self, services):
        self.services = services
        self.running = True
        self.last_health = 0.0

    def health_check(self) -> None:
        now = time.time()
        for svc in self.services:
            if svc.failed or svc.proc is None or svc.proc.poll() is not None:
                continue
            if now - svc.started_at < STARTUP_GRACE:
                continue
            if svc.port_open():
                svc.health_failures = 0
                continue
            svc.health_failures += 1
            log(f"[?] {svc.name} not answering on port {svc.port} "
                f"({svc.health_failures}/{HEALTH_FAILURES})")
            if svc.health_failures >= HEALTH_FAILURES:
                log(f"[!] {svc.name} appears hung - killing it")
                svc.stop(force=True)
                try:
                    svc.proc.wait(timeout=5)
                except Exception:
                    pass
                svc.schedule_restart("was unresponsive")

    def shutdown(self, *_):
        if not self.running:
            return
        self.running = False
        log("\n[!] Shutting down all Honeypot services gracefully...")
        for svc in reversed(self.services):         # decoys first, backend last
            svc.stop()
        deadline = time.time() + 5
        while time.time() < deadline and any(s.proc and s.proc.poll() is None for s in self.services):
            time.sleep(0.2)
        for svc in self.services:
            svc.stop(force=True)
        log("[*] All honeypot services terminated. Bye.")

    def run(self) -> None:
        while self.running:
            for svc in self.services:
                svc.tick()
            if time.time() - self.last_health >= HEALTH_INTERVAL:
                self.last_health = time.time()
                self.health_check()
            if all(s.failed for s in self.services):
                log("[X] Every service has failed. Exiting.")
                self.shutdown()
                sys.exit(1)
            time.sleep(1)


def wait_for_port(port: int, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def main():
    python_exe = sys.executable
    base_dir = os.path.dirname(os.path.abspath(__file__))

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{os.path.join(base_dir, 'backend')}{os.pathsep}{base_dir}"
    env["PYTHONIOENCODING"] = "utf-8"
    env["BACKEND_API_URL"] = "http://127.0.0.1:8000/api/events"
    env["SSH_PORT"] = "2222"
    env["HTTP_PORT"] = "8080"

    print("=" * 70)
    print("  [+] CYBER-SOC HONEYPOT SYSTEM -- LAB DEPLOYMENT (self-healing)")
    print("=" * 70)

    backend = Service(
        "Backend", [python_exe, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"],
        os.path.join(base_dir, "backend"), env, 8000, probe="http")
    ssh = Service("SSH decoy", [python_exe, "decoys/ssh_decoy/server.py"], base_dir, env, 2222, probe="ssh-banner")
    http = Service(
        "HTTP decoy", [python_exe, "-m", "uvicorn", "decoys.http_decoy.app:app", "--host", "0.0.0.0", "--port", "8080"],
        base_dir, env, 8080)
    sup = Supervisor([backend, ssh, http])

    signal.signal(signal.SIGINT, sup.shutdown)
    try:
        signal.signal(signal.SIGTERM, sup.shutdown)
    except (ValueError, OSError):
        pass

    # Backend first: wait until it is actually listening (it may restore a damaged DB on boot).
    backend.tick()   # tick() handles launch failures via the restart path
    if not wait_for_port(8000, 30):
        log("[!] Backend not listening after 30s - decoys will buffer events until it is up")
    ssh.tick()
    http.tick()

    print("\n[+] All honeypot services are LIVE.")
    print("    - Dashboard URL: http://127.0.0.1:8000")
    print("    - Recovery API:  http://127.0.0.1:8000/api/recovery/status")
    print("    - SSH Honeypot:  127.0.0.1:2222 (e.g. ssh -p 2222 root@127.0.0.1)")
    print("    - HTTP Honeypot: http://127.0.0.1:8080 (e.g. http://127.0.0.1:8080/admin/login)")
    print("    - Run Simulator: python simulator/simulate_attacks.py")
    print("\nPress Ctrl+C to terminate all services.\n")

    try:
        sup.run()
    except KeyboardInterrupt:
        sup.shutdown()


if __name__ == "__main__":
    main()
