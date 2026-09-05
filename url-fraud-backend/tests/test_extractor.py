"""
Unit tests for the lexical feature extraction module.
"""

from app.core.extractor import extract_features, url_to_vector, FEATURE_NAMES, shannon_entropy


def test_feature_names_count():
    assert len(FEATURE_NAMES) == 24
    assert "url_length" in FEATURE_NAMES
    assert "has_ip_address" in FEATURE_NAMES
    assert "has_shortener" in FEATURE_NAMES
    assert "shannon_entropy" in FEATURE_NAMES


def test_clean_url_features():
    url = "https://www.example.com/about"
    feats = extract_features(url)
    assert len(feats) == 24
    assert feats["has_https"] == 1
    assert feats["has_ip_address"] == 0
    assert feats["has_shortener"] == 0
    assert feats["domain_length"] == len("www.example.com")
    assert feats["suspicious_word_count"] == 0


def test_ip_address_detection():
    url = "http://192.168.1.1/login"
    feats = extract_features(url)
    assert feats["has_ip_address"] == 1
    assert feats["has_https"] == 0
    assert feats["suspicious_word_count"] >= 1  # "login"


def test_shortener_detection():
    url = "https://bit.ly/3xYzAbc"
    feats = extract_features(url)
    assert feats["has_shortener"] == 1


def test_credential_spoofing_at_symbol():
    url = "https://google.com@evil-site.com/phish"
    feats = extract_features(url)
    assert feats["has_at_symbol"] == 1


def test_shannon_entropy():
    # Repetitive string has low entropy
    assert shannon_entropy("aaaaaaaa") < 1.0
    # Random diversified string has higher entropy
    assert shannon_entropy("a1b2c3d4e5!@#$") > 3.0


def test_url_to_vector():
    url = "https://example.com"
    vec = url_to_vector(url)
    assert isinstance(vec, list)
    assert len(vec) == 24
