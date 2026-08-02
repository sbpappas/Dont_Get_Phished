from phishguard.url_features import extract_url_features, split_url
from phishguard.heuristics import evaluate

BRANDS = {"paypal": "paypal.com", "amazon": "amazon.com"}
KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm"]


def _run(url):
    parts = split_url(url)
    feats = extract_url_features(url)
    result = evaluate(parts, feats, None, None, BRANDS, KEYWORDS)
    return result


def test_legitimate_domain_has_no_brand_flag():
    result = _run("https://www.paypal.com/signin")
    codes = {f.code for f in result.findings}
    assert "brand_in_domain_mismatch" not in codes
    assert "typosquat_similarity" not in codes


def test_brand_impersonation_flagged():
    result = _run("http://paypal-secure-login.xyz/verify/account")
    codes = {f.code for f in result.findings}
    assert "brand_in_domain_mismatch" in codes
    assert "suspicious_tld" in codes
    assert "no_https" in codes
    assert result.score >= 50


def test_typosquat_similarity_flagged():
    # close to paypal.com without containing the literal substring "paypal"
    result = _run("http://paypa1.com/login")
    codes = {f.code for f in result.findings}
    assert "typosquat_similarity" in codes


def test_ip_host_flagged():
    result = _run("http://192.168.1.5/account/login")
    codes = {f.code for f in result.findings}
    assert "ip_as_hostname" in codes
    assert "excessive_subdomains" not in codes  # IP dots aren't subdomains


def test_at_symbol_flagged():
    result = _run("http://real-bank.com@evil.com/login")
    codes = {f.code for f in result.findings}
    assert "at_symbol_in_url" in codes


def test_clean_url_scores_low():
    result = _run("https://www.wikipedia.org/wiki/Phishing")
    assert result.score == 0
    assert result.findings == []


def test_score_is_capped_at_100():
    result = _run(
        "http://paypal-secure-login-verify-account-update-confirm.xyz.tk/@evil/login"
    )
    assert 0 <= result.score <= 100
