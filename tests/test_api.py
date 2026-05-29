import pytest


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


@pytest.fixture
def auth_headers(client):
    login = client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "changeme"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_analyze_brute_force(client, auth_headers):
    res = client.post(
        "/api/v1/analysis/analyze/ephemeral",
        json={
            "log_text": (
                "Failed login attempt from IP 192.168.1.20 repeated 45 times. User: admin"
            ),
            "use_slm": True,
        },
        headers=auth_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data["threats"]) >= 1
    assert data["threats"][0]["threat_type"] == "Brute Force Attack"
