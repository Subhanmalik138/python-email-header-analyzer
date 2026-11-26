import pytest

from mailtrace.analysis import analyze_bytes
from conftest import CLEAN, NO_AUTH, SPOOFED, WITH_ATTACHMENT


def _codes(analysis):
    return {f.code for f in analysis.findings}


def test_clean_message_verdict_and_no_critical_findings():
    analysis = analyze_bytes(CLEAN)
    assert analysis.verdict == "clean"
    assert analysis.exit_code == 0
    assert analysis.from_addr == "alice@example.com"
    assert analysis.from_name == "Alice Example"
    assert analysis.subject == "Quarterly report"
    assert len(analysis.hops) == 2
    assert analysis.hops[0].from_ip == "192.168.1.5"
    assert analysis.hops[1].tls_version == "TLSV1.3"
    assert _codes(analysis) == set()


def test_spoofed_message_is_likely_spoofed():
    analysis = analyze_bytes(SPOOFED)
    assert analysis.verdict == "likely spoofed"
    assert analysis.exit_code == 2
    codes = _codes(analysis)
    assert "display-name-spoof" in codes
    assert "auth-spf-fail" in codes
    assert "auth-dkim-fail" in codes
    assert "auth-dmarc-fail" in codes
    assert "unencrypted-hop" in codes
    # Reply-To matches the From domain here, so no reply-to finding.
    assert "reply-to-mismatch" not in codes


def test_reply_to_mismatch_flagged():
    raw = SPOOFED.replace(
        b"Reply-To: attacker@evil.example",
        b"Reply-To: harvest@totally-different.example",
    )
    assert "reply-to-mismatch" in _codes(analyze_bytes(raw))


def test_return_path_mismatch_flagged():
    raw = CLEAN.replace(
        b"Return-Path: <alice@example.com>",
        b"Return-Path: <bounce@other.example>",
    )
    analysis = analyze_bytes(raw)
    assert analysis.verdict == "suspicious"
    assert "from-returnpath-mismatch" in _codes(analysis)


def test_missing_auth_headers_is_suspicious_not_clean():
    analysis = analyze_bytes(NO_AUTH)
    assert analysis.verdict == "suspicious"
    codes = _codes(analysis)
    assert "auth-spf-missing" in codes
    assert "auth-dkim-missing" in codes
    assert "auth-dmarc-missing" in codes
    assert "no-received-headers" in codes


def test_dangerous_double_extension_attachment():
    analysis = analyze_bytes(WITH_ATTACHMENT)
    assert analysis.verdict == "likely spoofed"
    assert len(analysis.attachments) == 1
    att = analysis.attachments[0]
    assert att.filename == "invoice.pdf.exe"
    assert att.size == 11  # "hello world"
    assert att.sha256  # 64 hex chars
    assert len(att.sha256) == 64
    assert att.dangerous
    assert "dangerous-attachment" in _codes(analysis)


def test_harmless_attachment_not_flagged():
    raw = WITH_ATTACHMENT.replace(b'invoice.pdf.exe', b'invoice.pdf')
    analysis = analyze_bytes(raw)
    assert not analysis.attachments[0].dangerous
    assert "dangerous-attachment" not in _codes(analysis)


def test_empty_message_raises():
    with pytest.raises(ValueError):
        analyze_bytes(b"   \n")


def test_missing_message_id_is_info_only():
    raw = CLEAN.replace(b"Message-ID: <abc123@example.com>\n", b"")
    analysis = analyze_bytes(raw)
    assert "missing-message-id" in _codes(analysis)
    assert analysis.verdict == "clean"  # info findings don't change the verdict


def test_date_far_in_future_flagged():
    raw = CLEAN.replace(
        b"Date: Tue, 25 Nov 2026 10:20:00 +0000",
        b"Date: Tue, 25 Nov 2030 10:20:00 +0000",
    )
    assert "date-in-future" in _codes(analyze_bytes(raw))


def test_as_dict_is_json_serializable():
    import json

    data = json.loads(json.dumps(analyze_bytes(SPOOFED).as_dict()))
    assert data["verdict"] == "likely spoofed"
    assert len(data["hops"]) == 1
    assert data["hops"][0]["from_ip"] == "198.51.100.77"
    assert data["authentication"][0]["mechanism"] == "spf"
    assert data["findings"]
