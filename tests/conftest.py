"""Shared .eml fixtures for the MailTrace test suite."""

CLEAN = b"""\
From: Alice Example <alice@example.com>
To: bob@receiver.com
Subject: Quarterly report
Date: Tue, 25 Nov 2026 10:20:00 +0000
Message-ID: <abc123@example.com>
Return-Path: <alice@example.com>
Authentication-Results: mx.receiver.com;
    spf=pass smtp.mailfrom=example.com;
    dkim=pass header.d=example.com;
    dmarc=pass header.from=example.com
Received: from mail.example.com (mail.example.com [203.0.113.10])
    by mx.receiver.com with ESMTPS id x1
    (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384);
    Tue, 25 Nov 2026 10:19:55 +0000
Received: from [192.168.1.5] by mail.example.com with ESMTP id x0;
    Tue, 25 Nov 2026 10:19:40 +0000

Hi Bob, the report is attached.
"""

SPOOFED = b"""\
From: "support@paypal.com" <attacker@evil.example>
Reply-To: attacker@evil.example
To: victim@receiver.com
Subject: Urgent: verify your account now
Date: Tue, 25 Nov 2026 11:00:00 +0000
Message-ID: <zzz999@evil.example>
Return-Path: <attacker@evil.example>
Authentication-Results: mx.receiver.com;
    spf=fail smtp.mailfrom=evil.example;
    dkim=fail header.d=evil.example;
    dmarc=fail header.from=evil.example
Received: from evil.example (evil.example [198.51.100.77])
    by mx.receiver.com with SMTP id y1;
    Tue, 25 Nov 2026 10:59:30 +0000

Please open the attached invoice.
"""

WITH_ATTACHMENT = b"""\
From: Carol <carol@example.com>
To: dave@receiver.com
Subject: See this
Date: Tue, 25 Nov 2026 09:00:00 +0000
Message-ID: <att1@example.com>
Return-Path: <carol@example.com>
Authentication-Results: mx.receiver.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
Received: from mail.example.com (mail.example.com [203.0.113.10]) by mx.receiver.com with ESMTPS id a1 (using TLSv1.2); Tue, 25 Nov 2026 08:59:50 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

See the attached invoice.
--BOUNDARY
Content-Type: application/pdf; name="invoice.pdf.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice.pdf.exe"

aGVsbG8gd29ybGQ=
--BOUNDARY--
"""

NO_AUTH = b"""\
From: mallory@unknown.example
To: bob@receiver.com
Subject: No auth headers here
Date: Tue, 25 Nov 2026 12:00:00 +0000
Message-ID: <noauth@unknown.example>
Return-Path: <mallory@unknown.example>

Nothing to see.
"""
