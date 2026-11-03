# 🛡️ Full-Stack Cyber-SOC Honeypot & Attack Pattern Analysis System

A modern deception-based cybersecurity honeypot platform engineered for controlled lab and research environments. The system deploys isolated, realistic decoy services (SSH and HTTP), safely captures attacker interactions with **zero false positives** (any traffic hitting the decoy is malicious by definition), classifies attack vectors with a real-time threat intelligence engine, and streams telemetry to a live Security Operations Center (SOC) web dashboard via WebSockets and REST APIs.

---

## 🔒 Safety & Sandboxing Constraints

> [!IMPORTANT]
> **Defensive Observation Only**: This platform is designed exclusively for controlled security research and educational labs.
> 1. **Zero Execution of Untrusted Payloads**: Commands, shell droppers, SQL queries, and uploaded files are captured strictly as inert strings for telemetry and analysis. No attacker code is executed on the host system.
> 2. **Network Isolation**: When deployed via Docker Compose, services run in an isolated bridge network with no egress to internal networks or credentials.
> 3. **No Real Credentials**: The decoys use simulated, non-functional fake credentials and honey-tokens.

---

## 🏛️ Architecture Overview

```
                      [ Adversary / Attack Traffic ]
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
   [ Port 2222 / 22 ]                                [ Port 8080 / 80 ]
  SSH Decoy (Paramiko)                              HTTP Decoy (FastAPI)
  - Emulates OpenSSH 8.9p1 Ubuntu                   - Fake Internal Portal (/admin/login)
  - Traps Auth Credentials                          - Fake Diagnostic Ping (/api/tools/ping)
  - Sandboxed Shell Simulation                      - Honey-Tokens (/.env, /actuator/env)
  - Keystroke & Dropper Capture                     - File Upload Honeypot (/api/v1/upload)
           │                                                 │
           └────────────────────────┬────────────────────────┘
                                    │  Normalized Events
                                    ▼
                 ┌──────────────────────────────────────┐
                 │    FastAPI Analytics & Rule Engine   │
                 │              (Port 8000)             │
                 ├──────────────────────────────────────┤
                 │  - SSH & Web Brute-Force Detection   │
                 │  - Command Injection Classifier      │
                 │  - SQLi & Path Traversal Classifier  │
                 │  - Botnet Scanner UA Detector        │
                 │  - GeoIP Enrichment & Attribution    │
                 │  - SQLite / PostgreSQL Threat Store  │
                 └──────────────┬───────────────────────┘
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
     [ REST API Endpoints ]              [ WebSocket Stream (/ws/live) ]
             │                                     │
             └──────────────────┬──────────────────┘
                                │
                                ▼
               ┌─────────────────────────────────┐
               │    React SOC Cyber Dashboard    │
               │   - Real-time Terminal Stream   │
               │   - Attack Frequency Timeline   │
               │   - Classified Threat Matrix    │
               │   - Top Targeted Credentials    │
               │   - Global Threat Geo-Origin    │
               │   - 1-Click Attack Simulator    │
               └─────────────────────────────────┘
```

---

## 🚀 Quick Start (Local Lab Run)

### 1. Prerequisites
- Python 3.10+ (Python 3.11 / 3.12 / 3.14 supported)
- Standard Python libraries (FastAPI, Uvicorn, Paramiko, SQLAlchemy, Requests)

### 2. Launch All Honeypot Services
Run the unified multi-process launcher:
```bash
python run_all.py
```
This spawns:
- **Backend & Dashboard**: `http://127.0.0.1:8000`
- **SSH Honeypot Decoy**: `0.0.0.0:2222`
- **HTTP Honeypot Decoy**: `http://127.0.0.1:8080`

### 3. Open the Dashboard
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### 4. Execute Attack Simulation Campaign
In a new terminal, run the automated attack simulator to fire realistic multi-vector attacks against the honeypot:
```bash
python simulator/simulate_attacks.py
```
Watch the live terminal feed, frequency charts, and threat matrix update dynamically in real time!

---

## 🐳 Docker Compose Deployment (Isolated Bridge)

To deploy the entire stack in isolated Docker containers:

```bash
# Build and launch the containerized honeynet
docker compose up --build -d

# View running services
docker compose ps

# Follow container logs
docker compose logs -f
```

### Container Port Mappings:
- **Dashboard & Threat Engine**: `http://localhost:8000`
- **SSH Honeypot**: `localhost:2222` (maps to isolated port 22 in container)
- **HTTP Honeypot**: `http://localhost:8080` (maps to isolated port 80 in container)

---

## 📊 Threat Intelligence & Classification Matrix

| Attack Vector | Rule Logic & Signatures | Risk Level | Score |
| :--- | :--- | :---: | :---: |
| **COMMAND_INJECTION** | `wget`, `curl`, `chmod +x`, `bash -i`, `/bin/sh`, `;`, `\|`, `&&`, `nc -e`, `eval()` | `CRITICAL` / `HIGH` | 90 - 95 |
| **SSH_BRUTE_FORCE** | High-frequency password attempts within sliding time window (> threshold / min) | `HIGH` | 85 |
| **SQL_INJECTION** | `' OR '1'='1'`, `UNION SELECT`, `SLEEP()`, `DROP TABLE`, `INFORMATION_SCHEMA` | `HIGH` | 80 |
| **PATH_TRAVERSAL** | `../../`, `/etc/passwd`, `/windows/win.ini`, `/.env`, `/actuator/env` | `HIGH` | 75 |
| **CREDENTIAL_STUFFING** | Automated multi-credential spray against web login forms | `HIGH` | 70 |
| **BOTNET_RECON** | Known scanner User-Agents (`nikto`, `sqlmap`, `masscan`, `nmap`, `zgrab`, `python-requests`) | `MEDIUM` | 55 |
| **SUSPICIOUS_PROBE** | Endpoint reconnaissance against administrative or hidden paths | `LOW` | 35 |

---

## 🔌 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/events` | Ingest raw event from any decoy service (auto-classifies & enriches) |
| `GET` | `/api/events` | Query recent events with filters (`service`, `risk_level`, `classification`, `source_ip`) |
| `DELETE` | `/api/events` | Reset / clear event log store for fresh test runs |
| `GET` | `/api/analytics/overview` | High-level KPI metrics (total attacks, unique IPs, critical count, top vector) |
| `GET` | `/api/analytics/frequency` | Time-series attack volume buckets for chart visualization |
| `GET` | `/api/analytics/risk-matrix` | Classified threat patterns, severity breakdown, and sample payloads |
| `GET` | `/api/analytics/credentials` | Top targeted usernames and passwords with hit percentages |
| `GET` | `/api/analytics/geo` | Attacker geographic distribution and coordinates |
| `GET` | `/api/services/status` | Real-time health status of SSH and HTTP decoy listeners |
| `POST` | `/api/simulator/trigger` | Trigger simulated attack scenarios (`all`, `ssh_bruteforce`, `command_injection`, `web_sqli`, `botnet_recon`, `path_traversal`) |
| `POST` | `/api/events/batch` | Bulk-ingest events replayed by decoys after a backend outage (invalid records are rejected individually) |
| `GET` | `/api/recovery/status` | Backup inventory, last integrity check, last recovery, retention settings |
| `GET` | `/api/recovery/backups` | List available snapshots (newest first) |
| `POST` | `/api/recovery/verify` | Run a database integrity check now |
| `POST` | `/api/recovery/backup` | Take a verified snapshot now |
| `POST` | `/api/recovery/restore` | Restore a named snapshot (`{"name": "honeypot-...db"}`); a pre-restore snapshot is taken first |
| `POST` | `/api/recovery/auto-recover` | Check integrity; if damaged, quarantine the DB and restore the newest healthy snapshot |
| `WS` | `/ws/live` | Real-time WebSocket event broadcast stream |

---

## 🩹 Recovery System

Four layers keep the honeypot collecting evidence through crashes, hangs, outages and data corruption.

| Failure | What happens now |
| :--- | :--- |
| A service process crashes | `run_all.py` restarts **just that service** with exponential backoff (1s → 60s). It no longer tears everything down. |
| A service hangs (process alive, not answering) | Health probes (backend: HTTP, SSH: banner read, HTTP decoy: TCP) fail 3× → process is killed and restarted. |
| A service crash-loops | After 20 restarts/hour it is parked as `FAILED`; the rest keep running. |
| Backend is down / restarting | Decoys **buffer events to disk** (`decoys/*/spool/`, fsync'd JSONL) and replay them to `/api/events/batch` once the backend is back, **preserving original capture times**. Survives decoy restarts too. |
| SQLite file is corrupted | On startup and every 5 min the backend runs `PRAGMA integrity_check`. A damaged DB is **quarantined** (`honeypot.db.corrupt-<time>`, kept as evidence) and the newest healthy snapshot is restored. With no snapshot a fresh DB starts. |
| Bad data / accidental `DELETE /api/events` | Restore any snapshot via `POST /api/recovery/restore`. |

**Snapshots** use SQLite's online backup API (safe while the DB is in use), are integrity-verified after writing, and rotated. One is taken at startup, every 15 min, and on clean shutdown.

```bash
curl localhost:8000/api/recovery/status                       # what exists, last check, last recovery
curl -X POST localhost:8000/api/recovery/backup               # snapshot now
curl localhost:8000/api/recovery/backups                      # list
curl -X POST localhost:8000/api/recovery/restore \
     -H "Content-Type: application/json" -d '{"name": "honeypot-20261031T120000000000Z-manual.db"}'
```

### Configuration

| Variable | Default | Purpose |
| :--- | :---: | :--- |
| `BACKUP_DIR` | `<db dir>/backups` | Where snapshots are stored |
| `BACKUP_KEEP` | `10` | Snapshots retained |
| `BACKUP_INTERVAL_SECONDS` | `900` | Periodic snapshot interval (`0` = off) |
| `INTEGRITY_INTERVAL_SECONDS` | `300` | Periodic integrity check interval (`0` = off) |
| `RECOVERY_API_TOKEN` | *(unset)* | If set, backup/restore/auto-recover require header `X-Recovery-Token` |
| `SPOOL_DIR` / `SPOOL_MAX_EVENTS` / `SPOOL_BATCH_SIZE` | `./spool` / `100000` / `200` | Decoy event buffer |
| `MAX_RESTARTS_PER_HOUR` / `HEALTH_INTERVAL` / `HEALTH_FAILURES` / `STARTUP_GRACE` | `20` / `10` / `3` / `20` | `run_all.py` supervisor tuning |

> [!NOTE]
> **Docker:** the database now lives in the `honeypot-data` volume (`DATABASE_URL=sqlite:////app/data/honeypot.db`). Previously it was written to `/app/honeypot.db`, *outside* the volume, so it was lost whenever the container was recreated. Decoys have healthchecks and wait for a healthy backend; each has its own spool volume.
>
> **Limits:** PostgreSQL deployments are not covered by the snapshot/restore code (use `pg_dump`/PITR). An event whose HTTP response is lost *after* the backend stored it can be replayed once more (at-least-once delivery). Snapshots on the same disk do not protect against disk loss — copy `backups/` off-box for that.

---

## 🧪 Testing

Run the automated test suite covering classification rules, API routes, and schema validation:

```bash
# Run pytest with PYTHONPATH configured
python -m pytest backend/tests -v
```

---

## 📜 Attribution & Data Sources
- **IP Geolocation**: Data enriched using IP-API with local memory caching and RFC1918 simulation fallback.
- **Paramiko**: Used for safe SSH protocol emulation.
