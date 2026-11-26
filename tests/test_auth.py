from mailtrace.auth import parse_auth


def test_full_auth_header():
    report = parse_auth({
        "authentication-results": [
            "mx.receiver.com; spf=pass smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
        ]
    })
    assert report.best("spf").passed
    assert report.best("dkim").passed
    assert report.best("dmarc").passed
    assert report.best("spf").details["smtp.mailfrom"] == "example.com"
    assert report.mechanisms_seen == {"spf", "dkim", "dmarc"}


def test_fail_and_softfail():
    report = parse_auth({
        "authentication-results": [
            "mx.receiver.com; spf=fail smtp.mailfrom=evil.example; "
            "dkim=softfail header.d=evil.example"
        ]
    })
    assert report.best("spf").result == "fail"
    assert not report.best("spf").passed
    assert report.best("dkim").result == "softfail"
    assert report.best("dmarc") is None


def test_multiple_headers_all_kept():
    report = parse_auth({
        "authentication-results": [
            "mx1.receiver.com; spf=pass smtp.mailfrom=example.com",
            "mx2.receiver.com; dkim=pass header.d=example.com",
        ]
    })
    assert len(report.results) == 2
    assert report.best("spf").passed
    assert report.best("dkim").passed


def test_pass_beats_fail_when_both_present():
    # A message can carry spf= for several identities; a pass for the
    # aligned identity is what matters.
    report = parse_auth({
        "authentication-results": [
            "mx.receiver.com; spf=fail smtp.mailfrom=other.example; "
            "spf=pass smtp.mailfrom=example.com"
        ]
    })
    assert report.best("spf").result == "pass"


def test_received_spf_fallback_used_only_without_auth_results():
    report = parse_auth({"received-spf": ["pass (mx.receiver.com: domain of x)"]})
    assert report.best("spf").result == "pass"
    assert report.best("spf").source == "Received-SPF"

    report = parse_auth({
        "authentication-results": ["mx.receiver.com; spf=fail smtp.mailfrom=x"],
        "received-spf": ["pass (mx.receiver.com: domain of x)"],
    })
    # Authentication-Results wins; the fallback must not override it.
    assert report.best("spf").result == "fail"


def test_empty_headers():
    assert parse_auth({}).results == []
