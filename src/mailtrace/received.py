"""Parsing of ``Received`` headers into structured delivery hops.

A message's Received headers are written newest-first, so the chronological
delivery path is the reverse of header order. Each header looks roughly like::

    from mail.example.com (mail.example.com [203.0.113.10])
        by mx.receiver.com with ESMTPS id abc123
        (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384);
        Tue, 25 Nov 2026 10:15:30 +0000

Real-world headers are messy — comments nest, hosts are missing, dates are
malformed — so the parser is deliberately tolerant: anything it cannot
understand is kept in ``raw`` and the field is left as ``None`` instead of
raising.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

_IP_RE = re.compile(r"\[([0-9A-Fa-f:.]+)\]")
_FROM_RE = re.compile(r"\bfrom\s+([^\s(]+)(?:\s*\(([^)]*)\))?", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s(]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+([^\s;(]+)", re.IGNORECASE)
_TLS_RE = re.compile(r"\b(TLSv?1(?:\.[0-3])?|SSLv?3|STARTTLS)\b", re.IGNORECASE)
_ID_RE = re.compile(r"\bid\s+([^\s;]+)", re.IGNORECASE)
_FOR_RE = re.compile(r"\bfor\s+<?([^>\s;]+)>?", re.IGNORECASE)


@dataclass
class Hop:
    """One server hop in the delivery path, newest-first in the raw headers."""

    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    with_proto: str | None = None
    tls_version: str | None = None
    message_id: str | None = None
    for_address: str | None = None
    date: datetime | None = None
    delay_seconds: float | None = None  # vs the previous hop, chronological order

    @property
    def encrypted(self) -> bool:
        return self.tls_version is not None

    @property
    def summary(self) -> str:
        src = self.from_ip or self.from_host or "?"
        dst = self.by_host or "?"
        proto = self.with_proto or "?"
        tls = f" {self.tls_version}" if self.tls_version else " no-TLS"
        return f"{src} -> {dst} ({proto}{tls})"


def _parse_date(raw: str) -> datetime | None:
    """The date is everything after the LAST semicolon (comments may contain
    semicolons of their own, so splitting on the first one is wrong)."""
    if ";" not in raw:
        return None
    date_part = raw.rsplit(";", 1)[1].strip()
    if not date_part:
        return None
    try:
        parsed = parsedate_to_datetime(date_part)
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    # Naive dates are assumed UTC rather than local time: a hop timestamp
    # with no zone is still a comparable point in time.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _strip_date(raw: str) -> str:
    return raw.rsplit(";", 1)[0] if ";" in raw else raw


def parse_received(value: str) -> Hop:
    """Parse one Received header value into a Hop. Never raises."""
    raw = " ".join(value.split())  # collapse folding whitespace
    body = _strip_date(raw)

    from_host = from_ip = None
    m = _FROM_RE.search(body)
    if m:
        from_host = m.group(1).strip()
        comment = m.group(2) or ""
        ip = _IP_RE.search(comment)
        if ip:
            from_ip = ip.group(1)
        # Some servers put the IP straight after the hostname, not in a
        # comment: "from unknown [203.0.113.10]".
        if from_ip is None:
            ip = _IP_RE.search(body[: m.end()])
            if ip:
                from_ip = ip.group(1)
    if from_ip is None:
        # Fallback: any bracketed IP anywhere in the header.
        ip = _IP_RE.search(body)
        if ip:
            from_ip = ip.group(1)

    by_host = None
    m = _BY_RE.search(body)
    if m:
        by_host = m.group(1).strip()

    with_proto = None
    m = _WITH_RE.search(body)
    if m:
        with_proto = m.group(1).strip()

    tls_version = None
    m = _TLS_RE.search(body)
    if m:
        tls_version = m.group(1).upper()

    message_id = None
    m = _ID_RE.search(body)
    if m:
        message_id = m.group(1).strip()

    for_address = None
    m = _FOR_RE.search(body)
    if m:
        for_address = m.group(1).strip()

    return Hop(
        raw=raw,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        with_proto=with_proto,
        tls_version=tls_version,
        message_id=message_id,
        for_address=for_address,
        date=_parse_date(raw),
    )


def parse_received_chain(values: list[str]) -> list[Hop]:
    """Parse all Received headers into the chronological delivery path.

    Header order is newest-first; the returned list is oldest-first (the
    order the message actually travelled). ``delay_seconds`` on each hop is
    the time since the previous hop, so the first hop is always ``None``.
    """
    hops = [parse_received(v) for v in values]
    hops.reverse()
    previous: datetime | None = None
    for hop in hops:
        if hop.date is not None and previous is not None:
            hop.delay_seconds = (hop.date - previous).total_seconds()
        if hop.date is not None:
            previous = hop.date
    return hops


def format_delay(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    if seconds < 0:
        return f"{seconds:.0f}s (clock skew?)"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"
