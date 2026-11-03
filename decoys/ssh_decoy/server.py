"""
SSH Honeypot Decoy Service.
Built using Paramiko. Emulates an authentic OpenSSH Linux server.
Traps credentials, records session keystrokes & commands, and streams telemetry to Backend API.
SAFETY: Never executes any attacker-submitted command or payload on the host system.
"""
import os
import sys
import socket
import threading
import time
import uuid
import json
import logging
import requests
import paramiko

from event_spool import EventForwarder  # same directory (script run as __main__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SSH-Honeypot] %(message)s"
)
logger = logging.getLogger("ssh_decoy")
# Port scanners and the supervisor health probe disconnect before sending an SSH banner; paramiko logs a
# full traceback for each. Real attacker activity is captured through our own event pipeline instead.
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

BACKEND_API_URL = os.getenv("BACKEND_API_URL", "http://127.0.0.1:8000/api/events")
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
SSH_BANNER = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
HOST_KEY_FILE = os.path.join(os.path.dirname(__file__), "host_key.pem")

# Simulated Fake Shell Filesystem and Commands
FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash
sshd:x:120:65534::/run/sshd:/usr/sbin/nologin
"""

def generate_or_load_host_key():
    """Ensure a persistent RSA host key exists for the SSH server."""
    if not os.path.exists(HOST_KEY_FILE):
        logger.info(f"Generating new RSA host key at {HOST_KEY_FILE}...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_FILE)
        return key
    return paramiko.RSAKey(filename=HOST_KEY_FILE)

forwarder = EventForwarder(BACKEND_API_URL, name="ssh")
forwarder.start()  # resume any backlog left over from a previous run


def send_event_to_backend(event_payload: dict):
    """Transmit a captured interaction; buffered on disk and replayed if the backend is down."""
    try:
        forwarder.send(event_payload)
    except Exception as e:  # never let telemetry problems break the decoy session
        logger.error(f"Event forwarding failed unexpectedly: {e}")

class HoneypotSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, session_id: str):
        self.client_ip = client_ip
        self.client_port = client_port
        self.session_id = session_id
        self.event = threading.Event()
        self.authenticated_user = None
        self.login_attempts = 0

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.login_attempts += 1
        logger.info(f"[AUTH] IP={self.client_ip} User='{username}' Password='{password}' (Attempt #{self.login_attempts})")

        # Send login attempt event to backend
        send_event_to_backend({
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "service": "SSH",
            "event_type": "LOGIN_ATTEMPT",
            "username": username,
            "password": password,
            "payload": f"SSH_AUTH user={username} pass={password}",
            "user_agent": "SSH-Client",
            "session_id": self.session_id,
            "details": {
                "attempt_number": self.login_attempts,
                "auth_method": "password"
            }
        })

        # Allow login for research/honeypot trap:
        # Accept if username is common (root, admin, ubuntu) or after 2 attempts, to trap shell commands
        if self.login_attempts >= 2 or username.lower() in ["root", "admin", "ubuntu", "test", "user", "deploy"]:
            self.authenticated_user = username
            logger.info(f"[AUTH SUCCESS] Admitted attacker '{username}' into honeypot sandbox.")
            return paramiko.AUTH_SUCCESSFUL

        # Otherwise reject first attempt to simulate real auth challenge
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        logger.info(f"[PUBKEY AUTH] IP={self.client_ip} User='{username}' Key={key.get_name()}")
        send_event_to_backend({
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "service": "SSH",
            "event_type": "LOGIN_ATTEMPT",
            "username": username,
            "password": "[PUBKEY_SUBMISSION]",
            "payload": f"PUBKEY {key.get_name()} {key.get_base64()[:20]}...",
            "user_agent": "SSH-Client",
            "session_id": self.session_id,
        })
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd_str = command.decode("utf-8", errors="ignore").strip()
        logger.info(f"[EXEC RAW] IP={self.client_ip} Command: '{cmd_str}'")
        
        send_event_to_backend({
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "service": "SSH",
            "event_type": "COMMAND_EXEC",
            "username": self.authenticated_user or "anonymous",
            "payload": cmd_str,
            "user_agent": "SSH-Exec",
            "session_id": self.session_id,
            "details": {"mode": "exec"}
        })

        # Process fake execution response
        output = handle_fake_command(cmd_str, self.authenticated_user or "root")
        channel.send(output.encode("utf-8") + b"\n")
        channel.send_exit_status(0)
        channel.close()
        return True

def handle_fake_command(cmd: str, user: str = "root") -> str:
    """
    Simulate realistic outputs for common reconnaissance, persistence, and dropper commands.
    SAFETY: Does not execute any commands on the real machine.
    """
    cmd_clean = cmd.strip()
    base_cmd = cmd_clean.split()[0].lower() if cmd_clean else ""

    if not cmd_clean:
        return ""
    if base_cmd == "whoami":
        return user
    elif base_cmd == "id":
        return f"uid=0({user}) gid=0({user}) groups=0({user})"
    elif base_cmd == "hostname":
        return "prod-api-srv01"
    elif base_cmd == "uname":
        return "Linux prod-api-srv01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux"
    elif base_cmd == "pwd":
        return f"/{user}" if user != "root" else "/root"
    elif base_cmd in ["ls", "dir"]:
        return "total 32\ndrwx------ 4 root root 4096 Aug 20 10:14 .\ndrwxr-xr-x 19 root root 4096 Aug 10 09:00 ..\n-rw-r--r-- 1 root root 3106 Aug 12 11:22 .bashrc\n-rw------- 1 root root 1240 Aug 19 14:05 backup_db.sql.gz\ndrwx------ 2 root root 4096 Aug 15 16:30 .ssh\n-rw-r--r-- 1 root root  807 Aug 10 09:05 .profile\n-rwxr-xr-x 1 root root 4520 Aug 18 12:00 deploy.sh"
    elif "cat /etc/passwd" in cmd_clean:
        return FAKE_PASSWD.strip()
    elif "cat /etc/shadow" in cmd_clean:
        return "root:$6$rounds=4096$qJ9/g0k...:19600:0:99999:7:::\nubuntu:*:19600:0:99999:7:::"
    elif base_cmd in ["wget", "curl", "fetch", "tftp"]:
        return "--2026-08-21 14:30:00-- Connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1048576 (1.0M) [application/x-sh]\nSaving to: 'output'\n\n100%[======================================>] 1,048,576   2.14MB/s   in 0.5s\n\n2026-08-21 14:30:01 (2.14 MB/s) - 'payload.sh' saved [1048576/1048576]"
    elif base_cmd in ["chmod", "chown"]:
        return ""
    elif base_cmd in ["ps", "top"]:
        return "  PID TTY          TIME CMD\n    1 ?        00:00:02 systemd\n  452 ?        00:00:00 cron\n  890 ?        00:00:01 sshd\n 1204 pts/0    00:00:00 bash\n 1350 pts/0    00:00:00 ps"
    elif base_cmd in ["ifconfig", "ip"]:
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.3.15  netmask 255.255.255.0  broadcast 10.0.3.255\n        rx packets 41295  bytes 31405928 (31.4 MB)\n        tx packets 30120  bytes 4102910 (4.1 MB)"
    elif base_cmd in ["history", "last"]:
        return "  1  cd /var/www\n  2  git pull origin main\n  3  systemctl restart nginx\n  4  cat /root/backup_db.sql.gz\n  5  uname -a"
    elif base_cmd in ["exit", "logout", "quit"]:
        return "logout"
    else:
        return f"{base_cmd}: command not found"

def handle_interactive_shell(channel, client_ip: str, client_port: int, username: str, session_id: str):
    """Interactive pseudo-shell session loop."""
    prompt = f"root@prod-api-srv01:~# " if username == "root" else f"{username}@prod-api-srv01:~$ "
    
    motd = (
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        "Last login: Fri Aug 21 09:12:04 2026 from 192.168.1.100\r\n\r\n"
    )
    channel.send(motd.replace("\n", "\r\n"))
    channel.send(prompt)

    current_cmd = []
    
    while True:
        try:
            byte = channel.recv(1)
            if not byte:
                break
                
            char = byte.decode("utf-8", errors="ignore")
            
            # Enter key pressed (CR / LF)
            if char in ["\r", "\n"]:
                channel.send("\r\n")
                full_cmd = "".join(current_cmd).strip()
                current_cmd = []
                
                if full_cmd:
                    logger.info(f"[SHELL CMD] IP={client_ip} User={username} Cmd: '{full_cmd}'")
                    
                    # Send shell command execution to backend
                    send_event_to_backend({
                        "source_ip": client_ip,
                        "source_port": client_port,
                        "service": "SSH",
                        "event_type": "COMMAND_EXEC",
                        "username": username,
                        "payload": full_cmd,
                        "user_agent": "SSH-Interactive-PTY",
                        "session_id": session_id,
                        "details": {"shell": "pty_interactive"}
                    })
                    
                    if full_cmd.lower() in ["exit", "logout", "quit"]:
                        channel.send("Connection closed by foreign host.\r\n")
                        break
                        
                    response = handle_fake_command(full_cmd, username)
                    if response:
                        channel.send(response.replace("\n", "\r\n") + "\r\n")
                        
                channel.send(prompt)
                
            # Backspace key pressed
            elif byte in [b"\x08", b"\x7f"]:
                if current_cmd:
                    current_cmd.pop()
                    channel.send("\b \b")
                    
            # Ctrl+C or Ctrl+D
            elif byte in [b"\x03", b"\x04"]:
                channel.send("\r\n")
                if byte == b"\x04":
                    break
                current_cmd = []
                channel.send(prompt)
                
            else:
                current_cmd.append(char)
                channel.send(byte)  # Echo back
                
        except Exception as e:
            logger.debug(f"Interactive shell exception: {e}")
            break

    try:
        channel.close()
    except Exception:
        pass

def handle_connection(client_sock, client_addr, host_key):
    """Handle an incoming TCP connection on the SSH Decoy port."""
    client_ip, client_port = client_addr
    session_id = str(uuid.uuid4())[:8]
    logger.info(f"Incoming connection from {client_ip}:{client_port} [Session={session_id}]")

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)
        
        server = HoneypotSSHServer(client_ip, client_port, session_id)
        transport.start_server(server=server)
        
        channel = transport.accept(20)
        if channel is None:
            return
            
        server.event.wait(10)
        handle_interactive_shell(channel, client_ip, client_port, server.authenticated_user or "root", session_id)
        
    except Exception as e:
        logger.debug(f"Connection from {client_ip} closed: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass

def start_ssh_honeypot():
    """Start the multi-threaded SSH Honeypot server."""
    host_key = generate_or_load_host_key()
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind(("0.0.0.0", SSH_PORT))
        server_sock.listen(100)
        logger.info(f"[*] SSH Honeypot listening on 0.0.0.0:{SSH_PORT} (Banner: '{SSH_BANNER}')")
    except Exception as e:
        logger.error(f"Failed to bind SSH honeypot to port {SSH_PORT}: {e}")
        sys.exit(1)

    while True:
        try:
            client_sock, client_addr = server_sock.accept()
            client_thread = threading.Thread(
                target=handle_connection,
                args=(client_sock, client_addr, host_key),
                daemon=True
            )
            client_thread.start()
        except KeyboardInterrupt:
            logger.info("SSH Honeypot stopping...")
            break
        except Exception as e:
            logger.error(f"Accept error: {e}")

if __name__ == "__main__":
    start_ssh_honeypot()
