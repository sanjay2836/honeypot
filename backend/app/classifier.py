"""
Rule-based Threat Intelligence Classification & Risk Scoring Engine.
Classifies incoming honeypot events into attack vectors and assigns risk scores and levels.
"""
from typing import Dict, Any, Tuple
from datetime import datetime, timedelta
import re
from sqlalchemy.orm import Session
from .models import HoneypotEvent

# Signatures for Command Injection & Dropper attacks
COMMAND_INJECTION_PATTERNS = [
    r"(?i)\b(wget|curl|fetch|tftp|ftpget)\b",
    r"(?i)\b(chmod\s+(\+x|777|755))\b",
    r"(?i)\b(bash\s+-i|/bin/sh|/bin/bash|sh\s+-c)\b",
    r"(?i)\b(nc|netcat|ncat)\s+.*-e\b",
    r"(?i)\b(cat\s+/etc/passwd|cat\s+/etc/shadow)\b",
    r"(?i)\b(rm\s+-rf\s+/|dd\s+if=/dev/zero)\b",
    r"(?i)\b(eval\(|base64\s+-d|exec\(|system\()\b",
    r"(?i)(\||;|&&|\$\(|\`)\s*(wget|curl|bash|sh|id|whoami|cat|uname|nc)",
    r"(?i)\b(powershell|cmd\.exe|certutil|bitsadmin)\b",
    r"(?i)\b(nohup\s+.*&\s*$)",
]

# Signatures for SQL Injection
SQL_INJECTION_PATTERNS = [
    r"(?i)('\s*OR\s*'?1'?='?1)",
    r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
    r"(?i)\bSLEEP\s*\(\s*\d+\s*\)",
    r"(?i)\bBENCHMARK\s*\(\s*\d+",
    r"(?i)\bDROP\s+TABLE\b",
    r"(?i)\bINFORMATION_SCHEMA\b",
    r"(?i)(--\s*$|/\*.*\*/)",
    r"(?i)admin'--",
    r"(?i)'\s*or\s*''='",
]

# Signatures for Path Traversal & Secret Exposure Probes
PATH_TRAVERSAL_PATTERNS = [
    r"(?i)(\.\./|\.\.\\){2,}",
    r"(?i)(/etc/passwd|/etc/shadow|/windows/win\.ini|/boot\.ini)",
    r"(?i)(/\.env|/actuator/env|/actuator/health|/wp-config\.php|/config\.json|/web\.config)",
    r"(?i)(/\.git/|/\.svn/|/\.aws/credentials)",
]

# Known Vulnerability Scanners / Botnet User-Agents
SCANNER_USER_AGENTS = [
    r"(?i)nikto",
    r"(?i)sqlmap",
    r"(?i)masscan",
    r"(?i)nmap\s+scripting\s+engine",
    r"(?i)zgrab",
    r"(?i)censysinspect",
    r"(?i)shodan",
    r"(?i)gobuster",
    r"(?i)dirbuster",
    r"(?i)wpscan",
    r"(?i)python-requests",
    r"(?i)go-http-client",
    r"(?i)nuclei",
    r"(?i)httpx-toolkit",
]

def check_brute_force(db: Session, source_ip: str, service: str, window_minutes: int = 1, threshold: int = 5) -> Tuple[bool, int]:
    """
    Check if the source IP exceeded the threshold for login attempts in the sliding time window.
    Threshold default: 5 for fast demo lab testing, customizable.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    recent_attempts = db.query(HoneypotEvent).filter(
        HoneypotEvent.source_ip == source_ip,
        HoneypotEvent.service == service,
        HoneypotEvent.event_type == "LOGIN_ATTEMPT",
        HoneypotEvent.timestamp >= cutoff
    ).count()
    
    # Return whether it qualifies as brute force and the total count
    return (recent_attempts >= threshold), recent_attempts

def classify_event(event_dict: Dict[str, Any], db: Session = None) -> Dict[str, Any]:
    """
    Classifies a honeypot event and returns:
    {
        'classification': str,
        'risk_score': int,
        'risk_level': str,
        'matched_rule': str
    }
    """
    service = event_dict.get("service", "UNKNOWN").upper()
    event_type = event_dict.get("event_type", "UNKNOWN").upper()
    source_ip = event_dict.get("source_ip", "")
    payload = str(event_dict.get("payload") or "")
    user_agent = str(event_dict.get("user_agent") or "")
    path = str(event_dict.get("path") or "")
    username = str(event_dict.get("username") or "")
    password = str(event_dict.get("password") or "")

    combined_text = f"{payload} {path} {username} {password}"

    # 1. Check for Command Injection / Reverse Shell Dropper (CRITICAL / HIGH)
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, combined_text):
            return {
                "classification": "COMMAND_INJECTION",
                "risk_score": 95 if service == "SSH" else 90,
                "risk_level": "CRITICAL" if service == "SSH" else "HIGH",
                "matched_rule": f"Command Injection signature matched: '{pattern}'"
            }

    # 2. Check for SQL Injection (HIGH)
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, combined_text):
            return {
                "classification": "SQL_INJECTION",
                "risk_score": 80,
                "risk_level": "HIGH",
                "matched_rule": f"SQL Injection signature matched: '{pattern}'"
            }

    # 3. Check for Path Traversal / Sensitive File Extraction (HIGH)
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, combined_text) or re.search(pattern, path):
            return {
                "classification": "PATH_TRAVERSAL",
                "risk_score": 75,
                "risk_level": "HIGH",
                "matched_rule": f"Path Traversal / Credential leak attempt: '{pattern}'"
            }

    # 4. Check for Botnet Recon / Known Scanner User-Agents (MEDIUM)
    for pattern in SCANNER_USER_AGENTS:
        if re.search(pattern, user_agent):
            return {
                "classification": "BOTNET_RECON",
                "risk_score": 55,
                "risk_level": "MEDIUM",
                "matched_rule": f"Automated Scanner User-Agent: '{pattern}'"
            }

    # 5. Check for SSH or Web Brute-Force via DB frequency analysis
    if db is not None and event_type == "LOGIN_ATTEMPT":
        # Check SSH brute force (threshold 3 attempts in 1 min for fast testing, 50 in production)
        is_bf, count = check_brute_force(db, source_ip, service, window_minutes=2, threshold=3)
        if is_bf:
            if service == "SSH":
                return {
                    "classification": "SSH_BRUTE_FORCE",
                    "risk_score": 85,
                    "risk_level": "HIGH",
                    "matched_rule": f"SSH Brute-Force threshold exceeded ({count} attempts within 2 min from {source_ip})"
                }
            else:
                return {
                    "classification": "CREDENTIAL_STUFFING",
                    "risk_score": 70,
                    "risk_level": "HIGH",
                    "matched_rule": f"Web Credential Stuffing threshold exceeded ({count} attempts within 2 min from {source_ip})"
                }

    # 6. Check for Port Scan / Recon Probes
    if event_type in ["RECON_PROBE", "PORT_SCAN"] or (path and path.startswith("/.git") or path.startswith("/wp-")):
        return {
            "classification": "SUSPICIOUS_PROBE",
            "risk_score": 35,
            "risk_level": "LOW",
            "matched_rule": f"Endpoint Recon probe against path: {path or 'Decoy Port'}"
        }

    # 7. Default for basic interactions
    if event_type == "LOGIN_ATTEMPT":
        return {
            "classification": "CREDENTIAL_PROBE",
            "risk_score": 40,
            "risk_level": "MEDIUM",
            "matched_rule": f"Unauthorized login probe (user='{username}')"
        }
    elif event_type == "COMMAND_EXEC":
        return {
            "classification": "UNAUTHORIZED_SHELL_ACTIVITY",
            "risk_score": 65,
            "risk_level": "MEDIUM",
            "matched_rule": f"Sandbox shell command: '{payload}'"
        }
    elif event_type == "FILE_UPLOAD":
        return {
            "classification": "MALICIOUS_UPLOAD_ATTEMPT",
            "risk_score": 85,
            "risk_level": "HIGH",
            "matched_rule": "Suspicious file upload payload intercepted"
        }

    return {
        "classification": "UNCLASSIFIED_INTERACTION",
        "risk_score": 20,
        "risk_level": "INFO",
        "matched_rule": f"Raw {service} {event_type} interaction observed"
    }
