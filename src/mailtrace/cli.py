"""Command-line interface for MailTrace.

Exit codes
----------
0  clean — no findings above informational level
1  suspicious — at least one warning
2  likely spoofed — at least one critical finding
3  usage / parse error (unreadable file, empty message)
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .analysis import analyze_bytes, analyze_file
from .report import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailtrace",
        description="Forensic email header analyzer: trace the delivery path, "
                    "check SPF/DKIM/DMARC, and flag spoofing.",
    )
    parser.add_argument("files", nargs="*", metavar="FILE",
                        help=".eml file to analyze (reads stdin when omitted)")
    parser.add_argument("--json", action="store_true",
                        help="emit a machine-readable JSON report")
    parser.add_argument("--trace", action="store_true",
                        help="show only the delivery path, skip findings")
    parser.add_argument("--attachments", action="store_true",
                        help="list attachments (on by default in text reports)")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def _report(path: str | None, *, as_json: bool, trace_only: bool,
            show_attachments: bool) -> int:
    try:
        if path is None:
            analysis = analyze_bytes(sys.stdin.buffer.read())
        else:
            analysis = analyze_file(path)
    except (OSError, ValueError) as exc:
        label = path or "<stdin>"
        print(f"mailtrace: {label}: {exc}", file=sys.stderr)
        return 3
    if as_json:
        print(render_json(analysis), end="")
    else:
        print(render_text(analysis, trace_only=trace_only,
                          show_attachments=show_attachments or not trace_only),
              end="")
    return analysis.exit_code


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    files = args.files or [None]
    worst = 0
    for i, path in enumerate(files):
        if len(files) > 1:
            print(f"== {path or '<stdin>'} ==")
        code = _report(path, as_json=args.json, trace_only=args.trace,
                       show_attachments=args.attachments)
        worst = max(worst, code)
        if i < len(files) - 1:
            print()
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
