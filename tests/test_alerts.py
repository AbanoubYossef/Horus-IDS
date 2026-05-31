import pytest

@pytest.fixture
def auth_client(client):
    """Register a user and log in to provide an authenticated client."""
    client.post("/auth/register", json={
        "username": "alertuser",
        "email": "alert@example.com",
        "password": "securepassword123"
    })
    client.post("/auth/login", json={
        "username": "alertuser",
        "password": "securepassword123"
    })
    return client

def test_create_alert(auth_client):
    r = auth_client.post("/alerts", json={
        "title": "Test Alert",
        "description": "Suspicious activity detected",
        "severity": "high"
    })
    assert r.status_code == 200
    data = r.json()
    assert data["title"] == "Test Alert"
    assert data["severity"] == "high"
    assert data["status"] == "open"
    assert data["creator_name"] == "alertuser"
    assert "id" in data

def test_list_alerts(auth_client):
    auth_client.post("/alerts", json={"title": "Alert 1", "severity": "medium"})
    auth_client.post("/alerts", json={"title": "Alert 2", "severity": "critical"})
    
    r = auth_client.get("/alerts")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 2
    assert len(data["alerts"]) >= 2

def test_get_alert(auth_client):
    r = auth_client.post("/alerts", json={"title": "Specific Alert", "severity": "low"})
    alert_id = r.json()["id"]
    
    r2 = auth_client.get(f"/alerts/{alert_id}")
    assert r2.status_code == 200
    assert r2.json()["title"] == "Specific Alert"

def test_update_alert(auth_client):
    r = auth_client.post("/alerts", json={"title": "Update Me", "severity": "low"})
    alert_id = r.json()["id"]
    
    r2 = auth_client.put(f"/alerts/{alert_id}", json={
        "severity": "critical",
        "status": "investigating"
    })
    assert r2.status_code == 200
    assert r2.json()["severity"] == "critical"
    assert r2.json()["status"] == "investigating"

def test_delete_alert(auth_client):
    r = auth_client.post("/alerts", json={"title": "Delete Me", "severity": "low"})
    alert_id = r.json()["id"]
    
    r2 = auth_client.delete(f"/alerts/{alert_id}")
    assert r2.status_code == 200
    
    r3 = auth_client.get(f"/alerts/{alert_id}")
    assert r3.status_code == 404

def test_unauthorized_access(client):
    r = client.get("/alerts")
    assert r.status_code == 401
