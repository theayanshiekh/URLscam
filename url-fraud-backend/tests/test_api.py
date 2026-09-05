"""
Unit and integration tests for the URL Fraud Detection REST API.
"""

import pytest
from app import create_app
from app.config import Config


class TestConfig(Config):
    TESTING = True
    DATABASE_PATH = ":memory:"


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "model_name" in data


def test_check_url_valid(client):
    res = client.post("/api/v1/check-url", json={
        "url": "https://www.google.com",
        "include_features": True,
        "include_explainability": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "is_flagged" in data
    assert "probability" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert "features" in data
    assert len(data["features"]) == 24


def test_check_url_empty_fails(client):
    res = client.post("/api/v1/check-url", json={"url": "   "})
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data


def test_check_url_missing_body(client):
    res = client.post("/api/v1/check-url", json={})
    assert res.status_code == 400


def test_batch_urls_valid(client):
    urls = [
        "https://www.google.com",
        "http://192.168.1.1/login-verify",
        "https://bit.ly/test-shortener"
    ]
    res = client.post("/api/v1/check-urls", json={"urls": urls})
    assert res.status_code == 200
    data = res.get_json()
    assert "summary" in data
    assert data["summary"]["total"] == 3
    assert "flagged_count" in data["summary"]
    assert "safe_count" in data["summary"]
    assert len(data["results"]) == 3


def test_batch_urls_empty_fails(client):
    res = client.post("/api/v1/check-urls", json={"urls": []})
    assert res.status_code == 400


def test_extract_features_endpoint(client):
    res = client.post("/api/v1/extract-features", json={"url": "https://example.com/test?a=1&b=2"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["feature_count"] == 24
    assert "features" in data
    assert "feature_vector" in data
    assert len(data["feature_vector"]) == 24


def test_model_info_endpoint(client):
    res = client.get("/api/v1/model/info")
    assert res.status_code == 200
    data = res.get_json()
    assert data["model_name"] == "random_forest"
    assert "threshold" in data
    assert "metrics" in data


def test_reports_flow(client):
    # Submit a false positive report
    res = client.post("/api/v1/reports", json={
        "url": "https://bloomberg.com/tosv2.html",
        "reported_as": "FALSE_POSITIVE",
        "notes": "Legitimate news site terms of service URL"
    })
    assert res.status_code == 201
    data = res.get_json()
    assert data["status"] == "success"
    assert "report_id" in data

    # Retrieve reports
    res2 = client.get("/api/v1/reports")
    assert res2.status_code == 200
    reports = res2.get_json()["reports"]
    assert len(reports) >= 1
    assert reports[0]["url"] == "https://bloomberg.com/tosv2.html"
