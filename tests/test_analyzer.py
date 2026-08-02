from phishguard.analyzer import analyze


def test_analyze_offline_returns_result_without_network():
    result = analyze("http://paypal-secure-login.xyz/verify", offline=True)
    assert result.fetched_live is False
    assert result.ml_probability is None  # no network features -> no ML score
    assert result.verdict in {"Likely Safe", "Suspicious", "Likely Phishing"}
    assert result.verdict == "Likely Phishing"
    assert result.score == result.heuristic_score


def test_analyze_offline_clean_url_is_safe():
    result = analyze("https://www.wikipedia.org/wiki/Phishing", offline=True)
    assert result.verdict == "Likely Safe"
    assert result.score == 0


def test_result_to_dict_is_json_serializable():
    import json

    result = analyze("http://paypal-secure-login.xyz/verify", offline=True)
    json.dumps(result.to_dict())  # must not raise
