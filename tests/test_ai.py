import pytest
from unittest.mock import AsyncMock

@pytest.fixture
def auth_client(client, monkeypatch):
    client.post("/auth/register", json={
        "username": "aiuser",
        "email": "ai@example.com",
        "password": "securepassword123"
    })
    client.post("/auth/login", json={
        "username": "aiuser",
        "password": "securepassword123"
    })
    
    from application.services.ai_service import AiService
    mock_chat = AsyncMock(return_value="This is a mocked AI response")
    monkeypatch.setattr(AiService, "chat", mock_chat)
    
    return client

def test_ai_chat(auth_client):
    r = auth_client.post("/ai/chat", json={
        "message": "Explain what a SYN Flood is",
        "history": []
    })
    assert r.status_code == 200
    data = r.json()
    assert "response" in data
    assert data["response"] == "This is a mocked AI response"

def test_ai_unauthorized(client):
    r = client.post("/ai/chat", json={"message": "Hello", "history": []})
    assert r.status_code == 401
