"""Message analysis: identities, spoof checks, attachments, verdict.

The analysis answers three questions:

1. **Who claims to have sent this?** — From, Reply-To, Return-Path,
   Sender, and the display name attached to each.
2. **Does the delivery path back that up?** — the Received chain, and the
   SPF / DKIM / DMARC verdicts the receiving server recorded.
3. **Is anything else off?** — suspicious attachments, missing
   Message-ID, impossible dates, unencrypted hops.

Each check produces a Finding with a severity; the overall verdict is the
worst severity present. A message with no authentication headers at all is
"suspicious", not "clean" — absence of evidence is itself a signal.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr

from .auth import AuthReport, parse_auth
from .received import Hop, format_delay, parse_received_chain

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".msi", ".ps1", ".hta", ".lnk", ".apk", ".dmg",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}

# A display name that is really a domain ("PayPal", "support@bank.com",
# "accounts.google.com") while the From address belongs to another domain
# is the classic display-name spoof.
_DOMAIN_LIKE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$|^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


@dataclass
class Finding:
    level: str  # "info" | "warning" | "critical"
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level.upper():8}] {self.code}: {self.message}"


@dataclass
class Attachment:
    filename: str | None
    content_type: str
    size: int
    sha256: str

    @property
    def dangerous(self) -> bool:
        name = (self.filename or "").lower()
        if any(name.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            return True
        # Double extension, e.g. invoice.pdf.exe
        parts = name.rsplit(".", 2)
        return len(parts) == 3 and f".{parts[1]}" in ARCHIVE_EXTENSIONS | {".pdf", ".doc", ".docx", ".xls", ".xlsx"} and name.endswith(tuple(DANGEROUS_EXTENSIONS))


@dataclass
class Analysis:
    subject: str | None
    date: datetime | None
    message_id: str | None
    from_name: str
    from_addr: str
    reply_to: str | None
    return_path: str | None
    sender: str | None
    hops: list[Hop] = field(default_factory=list)
    auth: AuthReport = field(default_factory=AuthReport)
    attachments: list[Attachment] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    headers: dict[str, list[str]] = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        levels = {f.level for f in self.findings}
        if "critical" in levels:
            return "likely spoofed"
        if "warning" in levels:
            return "suspicious"
        return "clean"

    @property
    def exit_code(self) -> int:
        return {"clean": 0, "suspicious": 1, "likely spoofed": 2}[self.verdict]

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "date": self.date.isoformat() if self.date else None,
            "message_id": self.message_id,
            "from": {"name": self.from_name, "address": self.from_addr},
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "verdict": self.verdict,
            "hops": [
                {
                    "from_host": h.from_host,
                    "from_ip": h.from_ip,
                    "by_host": h.by_host,
                    "with": h.with_proto,
                    "tls": h.tls_version,
                    "date": h.date.isoformat() if h.date else None,
                    "delay": format_delay(h.delay_seconds),
                }
                for h in self.hops
            ],
            "authentication": [
                {"mechanism": r.mechanism, "result": r.result, "details": r.details}
                for r in self.auth.results
            ],
            "attachments": [
                {
                    "filename": a.filename,
                    "content_type": a.content_type,
                    "size": a.size,
                    "sha256": a.sha256,
                    "dangerous": a.dangerous,
                }
                for a in self.attachments
            ],
            "findings": [
                {"level": f.level, "code": f.code, "message": f.message}
                for f in self.findings
            ],
        }


def _is_private_ip(value: str) -> bool:
    """True for RFC1918 / loopback / link-local addresses — the sender's own
    network. Deliberately NOT ``ipaddress.is_private``: that also covers
    documentation ranges such as TEST-NET (198.51.100.0/24), which are
    public-looking addresses in real headers."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(
        addr in net
        for net in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fe80::/10"),
        )
    )


def _domain(addr: str | None) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower()


def _first(headers: dict[str, list[str]], name: str) -> str | None:
    values = headers.get(name)
    return values[0] if values else None


def _collect_headers(msg: EmailMessage) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for name, value in msg.raw_items():
        headers.setdefault(name.lower(), []).append(str(value))
    return headers


def _collect_attachments(msg: EmailMessage) -> list[Attachment]:
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            Attachment(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return attachments


def _check_auth(analysis: Analysis) -> None:
    for mechanism in ("spf", "dkim", "dmarc"):
        best = analysis.auth.best(mechanism)
        if best is None:
            analysis.findings.append(
                Finding("warning", f"auth-{mechanism}-missing",
                        f"No {mechanism.upper()} result recorded — the receiving "
                        "server did not check this message, or stripped the header.")
            )
        elif best.result == "fail":
            analysis.findings.append(
                Finding("critical" if mechanism != "spf" else "warning",
                        f"auth-{mechanism}-fail",
                        f"{mechanism.upper()} check failed ({best.details}).")
            )
        elif best.result == "softfail":
            analysis.findings.append(
                Finding("warning", f"auth-{mechanism}-softfail",
                        f"{mechanism.upper()} softfail ({best.details}).")
            )


def _check_identities(analysis: Analysis) -> None:
    from_domain = analysis.from_domain
    return_path_domain = _domain(analysis.return_path)
    if analysis.return_path and return_path_domain and from_domain:
        if return_path_domain != from_domain:
            analysis.findings.append(
                Finding("warning", "from-returnpath-mismatch",
                        f"From domain ({from_domain}) differs from Return-Path "
                        f"domain ({return_path_domain}) — bounces go elsewhere.")
            )
    if analysis.reply_to:
        reply_domain = _domain(analysis.reply_to)
        if reply_domain and from_domain and reply_domain != from_domain:
            analysis.findings.append(
                Finding("warning", "reply-to-mismatch",
                        f"Reply-To ({analysis.reply_to}) is on a different domain "
                        f"than From ({from_domain}) — replies leave the sender's domain.")
            )
    if analysis.sender:
        sender_domain = _domain(analysis.sender)
        if sender_domain and from_domain and sender_domain != from_domain:
            analysis.findings.append(
                Finding("info", "sender-differs",
                        f"Sender header ({analysis.sender}) differs from From — "
                        "common for mailing lists and delegated sending.")
            )
    # Display-name spoof: the name looks like a domain/brand address while
    # the real From domain is something else entirely.
    name = analysis.from_name.strip()
    if name and _DOMAIN_LIKE.match(name) and from_domain:
        claimed = name.rsplit("@", 1)[-1].lower() if "@" in name else name.lower()
        if claimed != from_domain:
            analysis.findings.append(
                Finding("critical", "display-name-spoof",
                        f"Display name looks like '{name}' but the message is "
                        f"actually from {from_domain}.")
            )


def _check_path(analysis: Analysis) -> None:
    hops = analysis.hops
    if not hops:
        analysis.findings.append(
            Finding("warning", "no-received-headers",
                    "No Received headers — the message has no delivery path to audit.")
        )
        return
    if len(hops) > 10:
        analysis.findings.append(
            Finding("info", "many-hops",
                    f"{len(hops)} Received hops is unusually long — possible "
                    "forwarding chain or loop.")
        )
    for hop in hops:
        if not hop.encrypted and hop.with_proto and hop.with_proto.upper() in ("SMTP", "ESMTP"):
            # The first hop (a user's own mail client submitting to its
            # server, usually from a private address) routinely carries no
            # TLS marker; flagging it would drown real findings. Only
            # server-to-server relays are expected to be encrypted.
            if hop.from_ip and _is_private_ip(hop.from_ip):
                continue
            analysis.findings.append(
                Finding("warning", "unencrypted-hop",
                        f"Hop {hop.summary} carried the message without TLS.")
            )
            break  # one warning covers it; the report lists every hop
    slow = [h for h in hops if h.delay_seconds is not None and h.delay_seconds > 3600]
    if slow:
        worst = max(slow, key=lambda h: h.delay_seconds or 0)
        analysis.findings.append(
            Finding("info", "slow-hop",
                    f"Message sat {format_delay(worst.delay_seconds)} at "
                    f"{worst.by_host or 'a hop'} before being forwarded.")
        )
    negative = [h for h in hops if h.delay_seconds is not None and h.delay_seconds < -60]
    if negative:
        analysis.findings.append(
            Finding("warning", "clock-skew",
                    "A hop is timestamped before the previous one — a server "
                    "clock is wrong, or the header was forged.")
        )


def _check_message(analysis: Analysis) -> None:
    if not analysis.message_id:
        analysis.findings.append(
            Finding("info", "missing-message-id",
                    "No Message-ID header — legitimate mail servers always add one.")
        )
    if analysis.date is None:
        analysis.findings.append(
            Finding("warning", "missing-date",
                    "No parseable Date header.")
        )
    elif analysis.hops:
        last = analysis.hops[-1].date
        if last is not None:
            delta = (analysis.date - last).total_seconds()
            if delta > 86400:
                analysis.findings.append(
                    Finding("warning", "date-in-future",
                            "Date header is more than a day after the last "
                            "Received timestamp.")
                )
            elif delta < -86400:
                analysis.findings.append(
                    Finding("info", "date-in-past",
                            "Date header is more than a day before the last "
                            "Received timestamp.")
                )
    for att in analysis.attachments:
        if att.dangerous:
            analysis.findings.append(
                Finding("critical", "dangerous-attachment",
                        f"Attachment '{att.filename}' is an executable or uses a "
                        "double extension to hide its real type.")
            )


def analyze_bytes(data: bytes) -> Analysis:
    """Parse and analyze one raw .eml message. Raises ValueError on empty input."""
    if not data.strip():
        raise ValueError("empty message")
    msg = BytesParser(policy=policy.default).parsebytes(data)
    headers = _collect_headers(msg)

    from_name, from_addr = parseaddr(_first(headers, "from") or "")
    _, reply_to = parseaddr(_first(headers, "reply-to") or "")
    _, return_path = parseaddr(_first(headers, "return-path") or "")
    _, sender = parseaddr(_first(headers, "sender") or "")

    date = None
    date_header = _first(headers, "date")
    if date_header:
        try:
            from email.utils import parsedate_to_datetime
            date = parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            date = None
    if date is not None and date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)

    analysis = Analysis(
        subject=_first(headers, "subject"),
        date=date,
        message_id=_first(headers, "message-id"),
        from_name=from_name,
        from_addr=from_addr,
        reply_to=reply_to or None,
        return_path=return_path or None,
        sender=sender or None,
        hops=parse_received_chain(headers.get("received", [])),
        auth=parse_auth(headers),
        attachments=_collect_attachments(msg),
        headers=headers,
    )

    _check_auth(analysis)
    _check_identities(analysis)
    _check_path(analysis)
    _check_message(analysis)
    return analysis


def analyze_file(path: str) -> Analysis:
    with open(path, "rb") as fh:
        return analyze_bytes(fh.read())
