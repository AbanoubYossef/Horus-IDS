import pytest

@pytest.fixture
def auth_client(client):
    client.post("/auth/register", json={
        "username": "analyticuser",
        "email": "analytic@example.com",
        "password": "securepassword123"
    })
    client.post("/auth/login", json={
        "username": "analyticuser",
        "password": "securepassword123"
    })
    return client

def test_timeline(auth_client):
    r = auth_client.get("/analytics/timeline?period=hour&days=1")
    assert r.status_code == 200
    data = r.json()
    assert "period" in data
    assert "data" in data
    assert isinstance(data["data"], list)

def test_attack_trends(auth_client):
    r = auth_client.get("/analytics/attack-trends?days=7")
    assert r.status_code == 200
    data = r.json()
    assert "trends" in data
    assert "top_attacks" in data

def test_severity_distribution(auth_client):
    r = auth_client.get("/analytics/severity-distribution?days=30")
    assert r.status_code == 200
    data = r.json()
    assert "daily" in data
    assert "totals" in data

def test_analytics_unauthorized(client):
    r = client.get("/analytics/timeline")
    assert r.status_code == 401
