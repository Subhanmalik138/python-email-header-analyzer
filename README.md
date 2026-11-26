# MailTrace — Email Header Analyzer CLI

Every phishing investigation starts with the same question: *where did this
message really come from, and can I trust it?* MailTrace answers it from a
`.eml` file — no mailbox access, no network, no dependencies.

It traces the `Received` chain hop by hop, reads the SPF / DKIM / DMARC
verdicts the receiving server recorded, and flags the mismatches phishers
rely on: a display name that pretends to be `support@paypal.com`, a
`Reply-To` on a different domain than `From`, an unencrypted hop, a
double-extension attachment.

## What it checks

| Check | What it catches |
| --- | --- |
| Received-chain trace | Every hop (host, IP, protocol, TLS version, per-hop delay) in delivery order |
| SPF / DKIM / DMARC | Pass / fail / softfail from `Authentication-Results`, with `Received-SPF` fallback |
| Display-name spoof | A name that looks like a domain or address while `From` belongs to another domain |
| From / Return-Path mismatch | Bounces going to a different domain than the claimed sender |
| Reply-To mismatch | Replies leaving the sender's domain |
| Unencrypted hops | SMTP/ESMTP hops that carried the message without TLS |
| Clock skew & slow hops | A hop timestamped before its predecessor, or a message stalled for hours |
| Attachments | Filename, type, size, SHA-256 — executables and `invoice.pdf.exe`-style double extensions flagged |
| Date / Message-ID | Missing or impossible dates, missing Message-ID |

## Verdicts and exit codes

- `clean` (exit 0) — authentication passes, identities line up.
- `suspicious` (exit 1) — at least one warning: missing auth results, a domain mismatch, an unencrypted hop.
- `likely spoofed` (exit 2) — at least one critical finding: failed DKIM/DMARC, display-name spoof, dangerous attachment.
- `3` — the file could not be read or the message is empty.

A message with no authentication headers at all is `suspicious`, not
`clean` — absence of evidence is itself a signal. The exit codes are meant
for CI: drop a `.eml` into a pipeline and gate on the result.

## Install

```bash
pip install .
```

Requires Python 3.10+ and nothing else — the standard library does all the
work (`email`, `argparse`, `hashlib`, `ipaddress`).

## Usage

```bash
# Analyze a saved message
mailtrace suspicious.eml

# Read from stdin (e.g. straight out of a mail client export)
cat message.eml | mailtrace

# Machine-readable report for scripting
mailtrace message.eml --json

# Just the delivery path
mailtrace message.eml --trace

# Several files at once — exit code is the worst verdict
mailtrace inbox/*.eml
```

## Example output

```
$ mailtrace examples/spoofed.eml
From:    support@paypal.com <attacker@evil.example>
Subject: Urgent: verify your account now
Date:    2026-11-25T11:00:00+00:00
Msg-ID:  <zzz999@evil.example>
Verdict: LIKELY SPOOFED

Delivery path
-------------
   #  From                         By                           Proto    TLS      Delay
   1  198.51.100.77                mx.receiver.com              SMTP     none        -

Authentication
--------------
  SPF    fail       smtp.mailfrom=evil.example
  DKIM   fail       header.d=evil.example
  DMARC  fail       header.from=evil.example

Findings
--------
  [CRITICAL] auth-dkim-fail: DKIM check failed ({'header.d': 'evil.example'}).
  [CRITICAL] auth-dmarc-fail: DMARC check failed ({'header.from': 'evil.example'}).
  [CRITICAL] display-name-spoof: Display name looks like 'support@paypal.com'
             but the message is actually from evil.example.
  [WARNING ] auth-spf-fail: SPF check failed ({'smtp.mailfrom': 'evil.example'}).
  [WARNING ] unencrypted-hop: Hop 198.51.100.77 -> mx.receiver.com (SMTP no-TLS)
             carried the message without TLS.

Attachments
-----------
  (none)
```

## Design decisions

1. **Tolerant parsing, never crashing.** Real-world `Received` headers are
   messy — nested comments, missing hosts, malformed dates. Anything the
   parser cannot understand is kept in the raw header and the field is left
   empty, so one weird hop never kills the whole report.
2. **The date lives after the last semicolon.** Comments inside a `Received`
   header can contain semicolons of their own, so splitting on the first one
   mis-parses the timestamp.
3. **Authentication is read, not re-implemented.** MailTrace trusts the
   receiving server's `Authentication-Results` (RFC 8601) instead of
   re-doing DNS lookups — that keeps it offline, fast, and honest about what
   it can prove. Re-validating SPF/DKIM from DNS is a different tool.
4. **Findings carry severity, verdicts are derived.** Every check emits a
   finding with a level; the verdict is just the worst level present. That
   makes the `--json` output stable for automation and the text report easy
   to read.
5. **An unencrypted first hop is not a finding.** A user's own mail client
   submitting from a private address routinely leaves no TLS marker in the
   header. Only server-to-server relays are expected to be encrypted, so
   only those are flagged.

## Running tests

```bash
pip install pytest
python -m pytest
```

## Project structure

```
src/mailtrace/
  __init__.py      package metadata
  received.py      Received-header parsing into delivery hops
  auth.py          Authentication-Results / Received-SPF parsing
  analysis.py      identities, spoof checks, attachments, verdict
  report.py        text and JSON rendering
  cli.py           argparse CLI and exit codes
tests/             36 pytest tests, incl. clean / spoofed / attachment fixtures
examples/          clean.eml and spoofed.eml to try it on
```

## License

MIT — see [LICENSE](LICENSE).
