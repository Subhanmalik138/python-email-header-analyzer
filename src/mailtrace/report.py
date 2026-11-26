"""Rendering of an Analysis as a human-readable text report or JSON."""

from __future__ import annotations

import json

from .analysis import Analysis
from .received import format_delay


def _section(title: str) -> str:
    return f"\n{title}\n{'-' * len(title)}\n"


def render_text(analysis: Analysis, *, trace_only: bool = False,
                show_attachments: bool = True) -> str:
    lines: list[str] = []

    lines.append(f"From:    {analysis.from_name + ' ' if analysis.from_name else ''}<{analysis.from_addr}>")
    if analysis.subject:
        lines.append(f"Subject: {analysis.subject}")
    if analysis.date:
        lines.append(f"Date:    {analysis.date.isoformat()}")
    if analysis.message_id:
        lines.append(f"Msg-ID:  {analysis.message_id}")
    lines.append(f"Verdict: {analysis.verdict.upper()}")

    lines.append(_section("Delivery path"))
    if not analysis.hops:
        lines.append("  (no Received headers)")
    else:
        lines.append(f"  {'#':>2}  {'From':<28} {'By':<28} {'Proto':<8} {'TLS':<8} {'Delay':>6}")
        for i, hop in enumerate(analysis.hops, 1):
            lines.append(
                f"  {i:>2}  {(hop.from_ip or hop.from_host or '?'):<28} "
                f"{(hop.by_host or '?'):<28} {(hop.with_proto or '?'):<8} "
                f"{(hop.tls_version or 'none'):<8} {format_delay(hop.delay_seconds):>6}"
            )

    if not trace_only:
        lines.append(_section("Authentication"))
        if not analysis.auth.results:
            lines.append("  (no Authentication-Results recorded)")
        for result in analysis.auth.results:
            detail = " ".join(f"{k}={v}" for k, v in result.details.items())
            lines.append(f"  {result.mechanism.upper():<6} {result.result:<10} {detail}")

        lines.append(_section("Findings"))
        if not analysis.findings:
            lines.append("  (none)")
        for finding in analysis.findings:
            lines.append(f"  {finding}")

        if show_attachments:
            lines.append(_section("Attachments"))
            if not analysis.attachments:
                lines.append("  (none)")
            for att in analysis.attachments:
                flag = "  <-- DANGEROUS" if att.dangerous else ""
                lines.append(
                    f"  {att.filename or '(unnamed)'} ({att.content_type}, "
                    f"{att.size} bytes, sha256 {att.sha256[:12]}...){flag}"
                )

    return "\n".join(lines) + "\n"


def render_json(analysis: Analysis) -> str:
    return json.dumps(analysis.as_dict(), indent=2) + "\n"
