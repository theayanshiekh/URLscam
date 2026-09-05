import pytest

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.wikipedia.org/",
        "https://login.help.support.example.org/info",
        "https://secure-paypal-login.example.xyz/verify/account",
        "http://192.0.2.80/login",
        "https://paypa1.com/signin",
        "https://xn--pypal-4ve.example/login",
        "https://bit.ly/demo-shortener-sample",
        "https://paypal.login.verify.account.example.com/secure",
        "https://example.com/%6c%6f%67%69%6e",
    ],
)
def test_pipeline_returns_structured_result(url):
    r = client.post("/api/analyze", json={"url": url, "demo": True})
    assert r.status_code == 200
    body = r.json()
    assert "classification" in body
    assert "risk_score" in body
    assert "confidence" in body
    assert "risk_factors" in body
    assert body["https_note"]
