import pytest

def test_register_success(client):
    r = client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "securepassword123",
        "role": "analyst"
    })
    assert r.status_code == 200
    data = r.json()
    assert "user" in data
    assert data["user"]["username"] == "testuser"
    assert data["user"]["email"] == "test@example.com"
    assert "id" in data["user"]

def test_register_duplicate(client):
    client.post("/auth/register", json={
        "username": "dupuser",
        "email": "dup@example.com",
        "password": "securepassword123"
    })
    r = client.post("/auth/register", json={
        "username": "dupuser",
        "email": "dup@example.com",
        "password": "securepassword123"
    })
    assert r.status_code == 409
    assert "already exists" in r.json()["detail"]

def test_login_success(client):
    client.post("/auth/register", json={
        "username": "loginuser",
        "email": "login@example.com",
        "password": "securepassword123"
    })
    r = client.post("/auth/login", json={
        "username": "loginuser",
        "password": "securepassword123"
    })
    assert r.status_code == 200
    data = r.json()
    assert "token" in data
    assert data["user"]["username"] == "loginuser"
    assert "session_token" in r.cookies

def test_login_failure(client):
    r = client.post("/auth/login", json={
        "username": "wronguser",
        "password": "wrongpassword"
    })
    assert r.status_code == 401

def test_me_authenticated(client):
    client.post("/auth/register", json={
        "username": "meuser",
        "email": "me@example.com",
        "password": "securepassword123"
    })
    client.post("/auth/login", json={
        "username": "meuser",
        "password": "securepassword123"
    })
    r = client.get("/auth/me")
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "meuser"

def test_me_unauthenticated(client):
    r = client.get("/auth/me")
    assert r.status_code == 401

def test_logout(client):
    client.post("/auth/register", json={
        "username": "logoutuser",
        "email": "logout@example.com",
        "password": "securepassword123"
    })
    client.post("/auth/login", json={
        "username": "logoutuser",
        "password": "securepassword123"
    })
    r = client.post("/auth/logout")
    assert r.status_code == 200
    assert r.cookies.get("session_token") is None
    
    r2 = client.get("/auth/me")
    assert r2.status_code == 401
