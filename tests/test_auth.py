from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_me_returns_user_when_auth_disabled():
    r = client.get("/api/me")
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "admin"
