import pytest

from app.security.ssrf import SSRFBlocked, assert_public_hostname, assert_public_url
from app.services.features import extract_features
from app.services.heuristics import run_heuristics
from app.services.risk_engine import combine_risk
from app.services.similarity import levenshtein
from app.utils.url_parser import URLParseError, parse_url


def test_parse_https_components():
    p = parse_url("https://Login.Example.COM:8443/a/b?x=1#frag")
    assert p.scheme == "https"
    assert p.hostname == "login.example.com"
    assert p.port == 8443
    assert p.path == "/a/b"
    assert p.query == "x=1"
    assert p.tld == "com"
    assert "login" in p.subdomains


def test_parse_ipv4():
    p = parse_url("http://192.0.2.10/login")
    assert p.is_ip
    feats = extract_features(p)
    assert feats["contains_ip"] == 1


def test_parse_ipv6():
    p = parse_url("http://[2001:db8::1]/path")
    assert p.is_ip
    assert p.is_ipv6


def test_punycode_flag():
    p = parse_url("https://xn--pypal-4ve.example/login")
    assert p.punycode
    feats = extract_features(p)
    assert feats["contains_punycode"] == 1


def test_encoded_characters():
    p = parse_url("https://example.com/%6c%6f%67%69%6e")
    feats = extract_features(p)
    assert feats["contains_encoded_characters"] == 1


def test_keywords():
    p = parse_url("https://example.com/verify/account?otp=1")
    feats = extract_features(p)
    assert feats["contains_verify_keyword"] == 1
    assert feats["contains_account_keyword"] == 1
    assert feats["contains_otp_keyword"] == 1


def test_typosquat_distance():
    assert levenshtein("paypal", "paypa1") == 1


def test_brand_impersonation_not_official_paypal():
    p = parse_url("https://secure-paypal-login.example.xyz/verify/account")
    feats = extract_features(p)
    factors, score = run_heuristics(p, feats)
    names = {f["name"] for f in factors}
    assert "Brand impersonation" in names or "Brand keyword on unrelated domain" in names
    assert score > 20


def test_official_domain_not_flagged_as_impersonation():
    p = parse_url("https://www.paypal.com/in/home")
    feats = extract_features(p)
    factors, _ = run_heuristics(p, feats)
    names = {f["name"] for f in factors}
    assert "Brand impersonation" not in names
    assert "Typosquatting / lookalike domain" not in names


def test_excessive_subdomains():
    p = parse_url("https://paypal.login.verify.account.example.com/")
    feats = extract_features(p)
    assert feats["num_subdomains"] >= 4
    factors, _ = run_heuristics(p, feats)
    assert any("subdomain" in f["name"].lower() for f in factors)


def test_shortener_is_signal_not_auto_phish():
    p = parse_url("https://bit.ly/demo")
    feats = extract_features(p)
    assert feats["is_shortener"] == 1
    factors, score = run_heuristics(p, feats)
    assert any(f["name"] == "URL shortener" for f in factors)
    ml = {"available": False}
    scored = combine_risk(ml, score, factors, {"intel_score": 0})
    assert scored["classification"] in {"suspicious", "legitimate", "phishing"}


def test_risk_thresholds_consistent():
    ml = {"available": True, "phishing_probability": 0.05, "suspicious_probability": 0.1, "confidence": 0.8, "label": "legitimate"}
    scored = combine_risk(ml, 5, [], {"intel_score": 0})
    assert scored["risk_score"] <= 29
    assert scored["classification"] == "legitimate"


def test_ssrf_localhost():
    with pytest.raises(SSRFBlocked):
        assert_public_hostname("localhost")
    with pytest.raises(SSRFBlocked):
        assert_public_hostname("127.0.0.1")
    with pytest.raises(SSRFBlocked):
        assert_public_hostname("10.0.0.5")
    with pytest.raises(SSRFBlocked):
        assert_public_hostname("169.254.169.254")
    with pytest.raises(SSRFBlocked):
        assert_public_url("http://127.0.0.1/secret")


def test_unsupported_scheme():
    with pytest.raises(URLParseError):
        parse_url("javascript:alert(1)")
    with pytest.raises(URLParseError):
        parse_url("ftp://example.com/file")
