from phishguard.url_features import extract_url_features, split_url, _strip_www, _is_ip


def test_split_url_basic():
    p = split_url("https://sub.example.com:8443/a/b/c.php?x=1&y=2")
    assert p.scheme == "https"
    assert p.domain == "sub.example.com"
    assert p.port == 8443
    assert p.directory == "/a/b/"
    assert p.file == "c.php"
    assert p.query == "x=1&y=2"


def test_split_url_root_path():
    p = split_url("http://example.com")
    assert p.directory == ""
    assert p.file == ""


def test_split_url_trailing_slash():
    p = split_url("http://example.com/a/b/")
    assert p.directory == "/a/b/"
    assert p.file == ""


def test_domain_in_ip_detects_ipv4():
    assert _is_ip("192.168.1.1") is True
    assert _is_ip("example.com") is False


def test_strip_www_only_strips_prefix():
    assert _strip_www("www.bit.ly") == "bit.ly"
    assert _strip_www("ow.ly") == "ow.ly"  # must NOT be mangled to "ow.ly" -> "ow.ly" (no www prefix)
    assert _strip_www("wow.ly") == "wow.ly"  # must not falsely strip


def test_extract_url_features_ip_host():
    feats = extract_url_features("http://192.168.1.5/login")
    assert feats["domain_in_ip"] == 1
    assert feats["qty_slash_url"] >= 2


def test_extract_url_features_at_symbol():
    feats = extract_url_features("http://example.com@evil.com/path")
    assert feats["qty_at_url"] == 1


def test_extract_url_features_url_shortener():
    feats = extract_url_features("http://bit.ly/abc123")
    assert feats["url_shortened"] == 1

    feats2 = extract_url_features("http://wow.ly/abc123")
    assert feats2["url_shortened"] == 0


def test_extract_url_features_email_in_url():
    feats = extract_url_features("http://example.com/?to=someone@example.com")
    assert feats["email_in_url"] == 1


def test_extract_url_features_length_consistency():
    url = "https://example.com/path"
    feats = extract_url_features(url)
    assert feats["length_url"] == len(url)
