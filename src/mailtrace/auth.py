"""Parsing of email authentication results.

Sources, in order of preference:

1. ``Authentication-Results`` headers (RFC 8601) — the authoritative
   verdict of the receiving server, e.g.::

       Authentication-Results: mx.receiver.com;
           spf=pass smtp.mailfrom=sender.com;
           dkim=pass header.d=sender.com;
           dmarc=pass header.from=sender.com

2. ``Received-SPF`` headers — a fallback for SPF when no
   Authentication-Results header is present.

Results are kept per mechanism; a message can legitimately carry several
``spf=`` entries (one per checked identity), so we keep them all and let the
caller decide which one matters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_MECH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
# key=value pairs inside one mechanism's result, e.g. "smtp.mailfrom=x".
_DETAIL_RE = re.compile(r"([a-z][a-z0-9._-]*)\s*=\s*([^;\s]+)", re.IGNORECASE)
_RECEIVED_SPF_RE = re.compile(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)

KNOWN_RESULTS = {
    "pass", "fail", "softfail", "neutral", "none",
    "temperror", "permerror", "policy",
}


@dataclass
class AuthResult:
    mechanism: str  # "spf" | "dkim" | "dmarc"
    result: str     # "pass" | "fail" | "softfail" | ...
    details: dict[str, str] = field(default_factory=dict)
    source: str = "Authentication-Results"  # or "Received-SPF"

    @property
    def passed(self) -> bool:
        return self.result == "pass"


@dataclass
class AuthReport:
    results: list[AuthResult] = field(default_factory=list)

    def for_mechanism(self, mechanism: str) -> list[AuthResult]:
        return [r for r in self.results if r.mechanism == mechanism]

    def best(self, mechanism: str) -> AuthResult | None:
        """The most meaningful result for a mechanism: a pass wins, then a
        hard fail, then anything else. ``None`` when the mechanism was never
        checked at all."""
        found = self.for_mechanism(mechanism)
        if not found:
            return None
        for wanted in ("pass", "fail", "softfail"):
            for result in found:
                if result.result == wanted:
                    return result
        return found[0]

    @property
    def mechanisms_seen(self) -> set[str]:
        return {r.mechanism for r in self.results}


def _parse_auth_results_header(value: str) -> list[AuthResult]:
    # The first segment (before the first ";") is the authserv-id, not a
    # mechanism — drop it before scanning for key=value pairs.
    body = value.split(";", 1)[1] if ";" in value else value
    results: list[AuthResult] = []
    for match in _MECH_RE.finditer(body):
        mechanism = match.group(1).lower()
        result = match.group(2).lower()
        if result not in KNOWN_RESULTS:
            continue
        # Details live in the text after this mechanism up to the next ";".
        segment = body[match.start():]
        segment = segment.split(";", 1)[0]
        details = {
            key.lower(): val
            for key, val in _DETAIL_RE.findall(segment)
            if key.lower() not in ("spf", "dkim", "dmarc")
        }
        results.append(AuthResult(mechanism, result, details))
    return results


def parse_auth(headers: dict[str, list[str]]) -> AuthReport:
    """Build an AuthReport from a message's headers.

    ``headers`` maps lower-cased header names to their values (a message can
    carry several Authentication-Results headers).
    """
    results: list[AuthResult] = []
    for value in headers.get("authentication-results", []):
        results.extend(_parse_auth_results_header(value))
    if not any(r.mechanism == "spf" for r in results):
        for value in headers.get("received-spf", []):
            m = _RECEIVED_SPF_RE.match(value)
            if m:
                results.append(
                    AuthResult("spf", m.group(1).lower(), {}, "Received-SPF")
                )
    return AuthReport(results)
