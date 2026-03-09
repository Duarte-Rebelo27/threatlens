from fastapi.testclient import TestClient
from backend.api.app import app
from backend.database import Base, engine

client = TestClient(app)

def setup_function():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_ingest_lines_and_fetch_alerts():
    payload = {
        "lines": [
            '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /admin HTTP/1.0" 404 2326',
            '127.0.0.1 - - [10/Oct/2000:13:55:37 -0700] "GET /login HTTP/1.0" 401 1234',
            '127.0.0.1 - - [10/Oct/2000:13:55:38 -0700] "GET /wp-admin HTTP/1.0" 404 999',
        ]
    }

    ingest_response = client.post("/ingest/lines", json=payload)
    assert ingest_response.status_code == 200

    ingest_data = ingest_response.json()
    assert "alerts" in ingest_data
    assert isinstance(ingest_data["alerts"], list)
    assert len(ingest_data["alerts"]) > 0

    first_alert = ingest_data["alerts"][0]
    assert first_alert["ip_address"] == "127.0.0.1"
    assert "alert_types" in first_alert
    assert "severity" in first_alert
    assert "details" in first_alert

    alerts_response = client.get("/alerts")
    assert alerts_response.status_code == 200

    alerts_data = alerts_response.json()
    assert isinstance(alerts_data, list)
    assert len(alerts_data) >= 1

    first_db_alert = alerts_data[0]
    assert first_db_alert["ip_address"] == "127.0.0.1"
    assert first_db_alert["alert_type"] == "Suspicious Path Access"
    assert "details" in first_db_alert
    assert "created_at" in first_db_alert

def test_ingest_invalid_lines_returns_400():
    payload = {
        "lines": [
            "not a real log line",
            "still invalid",
        ]
    }

    response = client.post("/ingest/lines", json=payload)
    assert response.status_code == 400
    assert response.json() == {"detail": "No valid lines parsed"}
    