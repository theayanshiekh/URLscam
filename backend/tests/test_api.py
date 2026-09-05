from fastapi.testclient import TestClient

from app.core.database import Base, engine, init_db
from app.main import app

init_db()
client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_config():
    r = client.get("/api/config")
    assert r.status_code == 200
    assert "HTTPS" in " ".join(r.json()["notes"])


def test_analyze_phishing_demo_shape():
    r = client.post(
        "/api/analyze",
        json={"url": "https://secure-paypal-login.example.xyz/verify/account", "demo": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] in {"phishing", "suspicious"}
    assert body["risk_score"] >= 60
    assert 0 <= body["confidence"] <= 1
    assert body["risk_factors"]
    assert "https" in body["url_breakdown"]["scheme"]
    assert "Heuristics" in body["analysis_sources"]


def test_analyze_legitimate_wikipedia():
    r = client.post("/api/analyze", json={"url": "https://www.wikipedia.org/wiki/Phishing"})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] in {"legitimate", "suspicious"}
    assert body["risk_score"] < body.get("id", 10**9) or True
    assert body["risk_score"] <= 59


def test_invalid_url():
    r = client.post("/api/analyze", json={"url": "not a url at all"})
    assert r.status_code == 400


def test_javascript_scheme_rejected():
    r = client.post("/api/analyze", json={"url": "javascript:alert(1)"})
    assert r.status_code == 400


def test_history_roundtrip():
    created = client.post("/api/analyze", json={"url": "https://example.com/"}).json()
    listed = client.get("/api/history")
    assert listed.status_code == 200
    assert listed.json()["total"] >= 1
    detail = client.get(f"/api/history/{created['id']}")
    assert detail.status_code == 200
    deleted = client.delete(f"/api/history/{created['id']}")
    assert deleted.json()["deleted"] is True


def test_admin_disabled():
    r = client.post("/api/admin/retrain")
    assert r.status_code in {401, 403}
