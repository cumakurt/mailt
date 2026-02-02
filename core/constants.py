"""
Shared constants for MailT: SMTP/Mail protocol defaults and identities.
Use these instead of hardcoding port, timeout, or EHLO identity across modules.

ATTACK MODE: Only RFC test domains and test mailbox are used; no real recipients.
"""
# SMTP
SMTP_PORT = 25
SMTP_PORT_SUBMISSION = 587
SMTP_PORT_SMTPS = 465
SMTP_TIMEOUT = 10.0
SMTP_BANNER_TIMEOUT = 10.0
EHLO_IDENTITY = "mailt.local"

# Exploit/PoC phase (ATTACK MODE) — slightly longer timeout for DATA phase
SMTP_EXPLOIT_TIMEOUT = 15.0

# POP3 / IMAP (discovery)
POP3_PORT = 110
POP3S_PORT = 995
IMAP_PORT = 143
IMAPS_PORT = 993

# ATTACK MODE — RFC test domains and test mailbox only (never real recipients)
RFC_TEST_DOMAIN_SENDER = "example.net"
RFC_TEST_DOMAIN_RECIPIENT = "example.org"
RFC_TEST_MAILBOX = "mailt-poc@example.org"
