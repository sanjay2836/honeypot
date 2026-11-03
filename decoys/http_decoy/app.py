"""
HTTP Honeypot Decoy Service.
Built with FastAPI. Emulates vulnerable corporate web applications, admin portals,
diagnostic ping utilities, secret files, and file upload endpoints.
SAFETY: Logs all incoming headers, payloads, and queries without executing any received data.
"""
import os
import uuid
import logging
from typing import Optional
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
import requests

try:
    from .event_spool import EventForwarder
except ImportError:  # executed outside a package
    from event_spool import EventForwarder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [HTTP-Honeypot] %(message)s"
)
logger = logging.getLogger("http_decoy")

BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000/api/events")
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))

forwarder = EventForwarder(BACKEND_API_URL, name="http")
forwarder.start()  # resume any backlog left over from a previous run

app = FastAPI(title="Internal Corporate Gateway Decoy", docs_url=None, redoc_url=None)

def report_event(
    request: Request,
    event_type: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    payload: Optional[str] = None,
    extra_details: Optional[dict] = None
):
    """Safely transmit captured HTTP interaction to the backend analytics engine."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    client_port = request.client.port if request.client else 0
    
    # Check headers for proxy/forwarded IPs if in reverse proxy setup
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()

    user_agent = request.headers.get("user-agent", "Unknown")
    path = request.url.path
    if request.url.query:
        path = f"{path}?{request.url.query}"
        
    session_id = request.cookies.get("SESSION_ID", str(uuid.uuid4())[:8])

    event_data = {
        "source_ip": client_ip,
        "source_port": client_port,
        "service": "HTTP",
        "event_type": event_type,
        "username": username,
        "password": password,
        "payload": payload or f"{request.method} {path}",
        "user_agent": user_agent,
        "path": path,
        "request_method": request.method,
        "session_id": session_id,
        "details": extra_details or {
            "headers": dict(request.headers),
            "cookies": dict(request.cookies)
        }
    }

    try:
        forwarder.send(event_data)   # buffered on disk + replayed if the backend is down
    except Exception as e:
        logger.error(f"Event forwarding failed unexpectedly: {e}")

# HTML Templates for realistic decoys
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Acme Corp | Internal Management Portal</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; width: 380px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    h2 { margin-top: 0; color: #38bdf8; font-size: 20px; text-align: center; }
    p.sub { font-size: 13px; color: #94a3b8; text-align: center; margin-bottom: 24px; }
    .form-group { margin-bottom: 16px; }
    label { display: block; font-size: 13px; margin-bottom: 6px; color: #cbd5e1; }
    input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 10px 12px; background: #0f172a; border: 1px solid #475569; border-radius: 6px; color: #fff; font-size: 14px; }
    input:focus { outline: none; border-color: #38bdf8; }
    button { width: 100%; padding: 10px; background: #0284c7; border: none; border-radius: 6px; color: white; font-weight: 600; cursor: pointer; margin-top: 8px; }
    button:hover { background: #0369a1; }
    .notice { margin-top: 20px; font-size: 11px; color: #64748b; text-align: center; border-top: 1px solid #334155; padding-top: 12px; }
    .error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; padding: 8px 12px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; display: none; }
  </style>
</head>
<body>
  <div class="card">
    <h2>ACME CORP GATEWAY</h2>
    <p class="sub">Production Infrastructure Access</p>
    <div id="err" class="error">Invalid username or password credentials.</div>
    <form method="POST" action="/admin/login">
      <div class="form-group">
        <label>Username / Employee ID</label>
        <input type="text" name="username" placeholder="e.g. jdoe or admin" required autocomplete="off">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="••••••••" required>
      </div>
      <button type="submit">Authenticate Session</button>
    </form>
    <div class="notice">Restricted authorized access only. All activities are monitored and logged.</div>
  </div>
  <script>
    if (window.location.search.includes('error=1')) {
      document.getElementById('err').style.display = 'block';
    }
  </script>
</body>
</html>
"""

PING_TOOL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Network Diagnostics Utility | Acme DevOps</title>
  <style>
    body { font-family: monospace; background: #090d16; color: #38bdf8; padding: 30px; }
    .container { max-width: 700px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 24px; }
    h1 { font-size: 18px; margin-top: 0; color: #10b981; }
    input[type="text"] { width: 70%; padding: 8px; background: #000; border: 1px solid #374151; color: #38bdf8; font-family: monospace; }
    button { padding: 8px 16px; background: #10b981; color: #000; border: none; font-weight: bold; cursor: pointer; }
    pre { background: #000; border: 1px solid #374151; padding: 12px; color: #a7f3d0; border-radius: 4px; overflow-x: auto; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>[Internal Utility] Ping / Host Reachability Test</h1>
    <form method="GET" action="/api/tools/ping">
      <label>Target Hostname or IP: </label>
      <input type="text" name="host" placeholder="127.0.0.1" value="127.0.0.1">
      <button type="submit">Execute Ping</button>
    </form>
    <pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.041 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.039 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2048ms
rtt min/avg/max/mdev = 0.038/0.039/0.041/0.001 ms</pre>
  </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home_endpoint(request: Request):
    report_event(request, event_type="WEB_REQUEST", payload="GET /")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/admin/login", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
@app.get("/wp-login.php", response_class=HTMLResponse)
async def login_get(request: Request):
    report_event(request, event_type="WEB_REQUEST", payload=f"GET {request.url.path}")
    return HTMLResponse(content=LOGIN_HTML)

@app.post("/admin/login", response_class=HTMLResponse)
@app.post("/login", response_class=HTMLResponse)
@app.post("/wp-login.php", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(""), password: str = Form("")):
    logger.info(f"[HTTP AUTH TRAP] User='{username}' Pass='{password}' from {request.client.host if request.client else 'unknown'}")
    report_event(
        request,
        event_type="LOGIN_ATTEMPT",
        username=username,
        password=password,
        payload=f"HTTP_LOGIN user={username} pass={password}",
        extra_details={"form_submission": {"username": username, "password": password}}
    )
    # Always return failure with error flag to keep attacker probing
    return HTMLResponse(
        content=LOGIN_HTML.replace('display: none;', 'display: block;'),
        status_code=401
    )

@app.get("/api/tools/ping")
@app.post("/api/tools/ping")
async def ping_tool_endpoint(request: Request, host: str = "127.0.0.1"):
    """
    Intentionally weak-looking diagnostic endpoint inviting command injection probes.
    SAFETY: Does not pass the input to any shell! Simply logs the attempt and returns simulated ping.
    """
    logger.info(f"[PING TOOL PROBE] Host param='{host}' from {request.client.host if request.client else 'unknown'}")
    report_event(
        request,
        event_type="COMMAND_EXEC",
        payload=f"PING_TOOL_PROBE host={host}",
        extra_details={"host_input": host}
    )
    
    # If request is from browser directly requesting HTML
    accept = request.headers.get("accept", "")
    if "text/html" in accept and request.method == "GET":
        rendered = PING_TOOL_HTML.replace("127.0.0.1", host[:64])
        return HTMLResponse(content=rendered)
        
    return JSONResponse({
        "status": "success",
        "target": host,
        "output": f"PING {host[:32]} (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.040 ms\n--- {host[:32]} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss"
    })

@app.post("/api/v1/upload")
async def upload_endpoint(request: Request, file: UploadFile = File(...)):
    """
    Honeypot upload endpoint. Traps suspicious webshell or script uploads without saving them to disk.
    """
    filename = file.filename
    content_type = file.content_type
    sample_bytes = await file.read(2048)
    sample_str = sample_bytes.decode("utf-8", errors="ignore")
    
    logger.info(f"[UPLOAD TRAP] Intercepted file upload: '{filename}' ({content_type}, {len(sample_bytes)} bytes)")
    report_event(
        request,
        event_type="FILE_UPLOAD",
        payload=f"UPLOAD filename={filename} mime={content_type} snippet={sample_str[:120]}",
        extra_details={"filename": filename, "mime": content_type, "sample": sample_str[:500]}
    )
    
    return JSONResponse({
        "status": "error",
        "message": f"File '{filename}' rejected: security validation failed.",
        "code": 403
    }, status_code=403)

@app.get("/.env")
@app.get("/actuator/env")
@app.get("/wp-config.php")
@app.get("/config.json")
async def secret_honeypot_endpoint(request: Request):
    """
    Honeytoken fake configuration endpoint.
    """
    logger.info(f"[SECRET PROBE] Attacker requested honeypot config file: {request.url.path}")
    report_event(
        request,
        event_type="RECON_PROBE",
        payload=f"SECRET_FILE_PROBE path={request.url.path}",
        extra_details={"target_file": request.url.path}
    )
    
    fake_env = """# ACME CORP PRODUCTION ENVIRONMENT
APP_ENV=production
APP_SECRET=decoy_honeypot_token_9920194819
DB_HOST=10.0.0.45
DB_USER=acme_root
DB_PASS=Sup3rS3cr3tH0n3yP0t!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
    return PlainTextResponse(content=fake_env, status_code=200)

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def catch_all_decoy(request: Request, full_path: str):
    """
    Catch-all route that traps and logs automated scanners, directory brute-forcers, and vulnerability probes.
    """
    path = f"/{full_path}"
    logger.info(f"[PROBE] Method={request.method} Path={path} from {request.client.host if request.client else 'unknown'}")
    report_event(
        request,
        event_type="RECON_PROBE",
        payload=f"{request.method} {path}"
    )
    return JSONResponse(
        {"status": "error", "message": f"Endpoint '{path}' not found on this server.", "code": 404},
        status_code=404
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("decoys.http_decoy.app:app", host="0.0.0.0", port=HTTP_PORT, reload=False)
