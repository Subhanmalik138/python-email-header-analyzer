import pytest

from mailtrace.received import format_delay, parse_received, parse_received_chain


def test_full_header_parses_every_field():
    hop = parse_received(
        "from mail.example.com (mail.example.com [203.0.113.10]) "
        "by mx.receiver.com with ESMTPS id x1 "
        "(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384); "
        "Tue, 25 Nov 2026 10:19:55 +0000"
    )
    assert hop.from_host == "mail.example.com"
    assert hop.from_ip == "203.0.113.10"
    assert hop.by_host == "mx.receiver.com"
    assert hop.with_proto == "ESMTPS"
    assert hop.tls_version == "TLSV1.3"
    assert hop.message_id == "x1"
    assert hop.date is not None and hop.date.hour == 10 and hop.date.minute == 19
    assert hop.encrypted


def test_bare_ip_without_comment():
    hop = parse_received(
        "from unknown [198.51.100.77] by mx.receiver.com with SMTP; "
        "Tue, 25 Nov 2026 10:59:30 +0000"
    )
    assert hop.from_ip == "198.51.100.77"
    assert hop.tls_version is None
    assert not hop.encrypted


def test_ipv6_address():
    hop = parse_received(
        "from mail6.example.com ([2001:db8::1]) by mx.receiver.com with ESMTPS; "
        "Tue, 25 Nov 2026 10:19:55 +0000"
    )
    assert hop.from_ip == "2001:db8::1"


def test_missing_date_is_none_not_error():
    hop = parse_received("from a.example by b.example with SMTP")
    assert hop.date is None
    assert hop.from_host == "a.example"


def test_malformed_date_is_none_not_error():
    hop = parse_received("from a.example by b.example; not a date at all")
    assert hop.date is None


def test_chain_reverses_to_chronological_order_and_computes_delays():
    hops = parse_received_chain([
        "from mail.example.com by mx.receiver.com with ESMTPS; "
        "Tue, 25 Nov 2026 10:19:55 +0000",
        "from [192.168.1.5] by mail.example.com with ESMTP; "
        "Tue, 25 Nov 2026 10:19:40 +0000",
    ])
    assert len(hops) == 2
    assert hops[0].by_host == "mail.example.com"  # oldest first
    assert hops[1].by_host == "mx.receiver.com"
    assert hops[0].delay_seconds is None
    assert hops[1].delay_seconds == pytest.approx(15.0)


def test_negative_delay_kept_for_clock_skew_detection():
    hops = parse_received_chain([
        "from b by c with SMTP; Tue, 25 Nov 2026 10:00:00 +0000",
        "from a by b with SMTP; Tue, 25 Nov 2026 10:05:00 +0000",
    ])
    assert hops[1].delay_seconds == pytest.approx(-300.0)


def test_for_address_parsed():
    hop = parse_received(
        "from mail.example.com by mx.receiver.com with ESMTPS "
        "for <bob@receiver.com>; Tue, 25 Nov 2026 10:19:55 +0000"
    )
    assert hop.for_address == "bob@receiver.com"


def test_format_delay_units():
    assert format_delay(None) == "-"
    assert format_delay(45) == "45s"
    assert format_delay(90) == "1.5m"
    assert format_delay(7200) == "2.0h"
    assert format_delay(172800) == "2.0d"
    assert "clock skew" in format_delay(-30)
