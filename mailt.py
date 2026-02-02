#!/usr/bin/env python3
"""
MailT — Email Security Analysis Framework
Anonymous DNS and SMTP checks; CVSS 3.1 and MITRE ATT&CK reporting.

Copyright (C) Cuma KURT <cumakurt@gmail.com>
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version. See LICENSE for full text.

Developed by Cuma KURT — cumakurt@gmail.com
https://github.com/cumakurt/mailt
https://www.linkedin.com/in/cuma-kurt-34414917/
"""
import argparse
import ipaddress
import os
import re
import sys

# Ensure project root is on path when run as script
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Force line-buffered stdout/stderr so --help and progress output appear immediately (fixes blank screen)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except (OSError, AttributeError):
        pass

from core.context import ScanContext
from core.scanner import main_scan
from core.requirements_check import check_requirements
from core.config import load_env_config, load_file_config, merge_config

# Exit codes: 0 = success, 1 = validation/deps error, 2 = scan failure (step errors)
EXIT_SUCCESS = 0
EXIT_VALIDATION = 1
EXIT_SCAN_FAILURE = 2

_help_printed = False  # Ensure --help is only printed once (e.g. if main() is invoked twice)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="MailT",
        description="Email Security Analysis — anonymous DNS and SMTP checks. SAFE MODE by default; ATTACK MODE only with explicit flags.",
    )
    parser.add_argument("--target", required=True, metavar="DOMAIN", help="Target mail domain (e.g. example.com)")
    parser.add_argument("--verbose", action="store_true", help="Verbose (debug) logging")
    parser.add_argument("--attack-mode", action="store_true", help="Enable exploit/PoC phase (requires --i-understand-the-risks)")
    parser.add_argument("--i-understand-the-risks", action="store_true", help="Acknowledge risks of active exploitation (use with --attack-mode)")
    parser.add_argument("--smtp", metavar="HOST", help="Manual SMTP server hostname or IP (overrides MX lookup)")
    parser.add_argument("--pop3", metavar="HOST", help="Manual POP3 server hostname or IP")
    parser.add_argument("--imap", metavar="HOST", help="Manual IMAP server hostname or IP")
    parser.add_argument("--all", metavar="HOST", dest="all_servers", help="Set SMTP, POP3 and IMAP to the same host (overridden by --smtp/--pop3/--imap)")
    parser.add_argument("--output-dir", "-o", metavar="DIR", help="Output directory for reports (default: reports/)")
    parser.add_argument("--format", choices=("html", "json", "markdown", "all"), default="html", help="Report format (default: html only)")
    parser.add_argument("--quiet", action="store_true", help="Minimal progress output (only final summary)")
    parser.add_argument("--log-file", metavar="FILE", help="Append logs to file")
    parser.add_argument("--timeout", type=float, metavar="SEC", help="Global scan timeout in seconds")
    parser.add_argument("--dns-timeout", type=float, metavar="SEC", help="DNS query timeout in seconds")
    parser.add_argument("--smtp-timeout", type=float, metavar="SEC", help="SMTP/socket timeout in seconds")
    parser.add_argument("--config", metavar="FILE", help="Path to JSON config file (overridden by CLI)")
    parser.add_argument("--email", metavar="ADDRESS", help="Test mailbox email (enables user-based credential-aware tests; requires --password)")
    parser.add_argument("--password", metavar="SECRET", help="Test mailbox password (use with --email for credential-aware tests)")
    return parser


def parse_args() -> argparse.Namespace:
    return _build_parser().parse_args()


# RFC 1035: max label 63, total domain 253; label: [a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?
DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
MAX_DOMAIN_LENGTH = 253


def _is_ip_address(s: str) -> bool:
    """Return True if s is a valid IPv4 or IPv6 address."""
    s = s.strip()
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def validate_target_domain(domain: str) -> None:
    """Validate target domain (format and length); reject IP addresses; exit with non-zero if invalid."""
    if not domain:
        print("MailT: --target must be a non-empty domain. Example: example.com", file=sys.stderr)
        sys.exit(EXIT_VALIDATION)
    if len(domain) > MAX_DOMAIN_LENGTH:
        print(f"MailT: --target domain length exceeds {MAX_DOMAIN_LENGTH} characters.", file=sys.stderr)
        sys.exit(EXIT_VALIDATION)
    if _is_ip_address(domain):
        print("MailT: --target must be a domain name, not an IP address. Example: example.com", file=sys.stderr)
        sys.exit(EXIT_VALIDATION)
    labels = domain.split(".")
    for label in labels:
        if not label:
            print("MailT: --target must not have empty or trailing dots. Example: example.com", file=sys.stderr)
            sys.exit(EXIT_VALIDATION)
        if len(label) > 63:
            print("MailT: --target label length exceeds 63 characters.", file=sys.stderr)
            sys.exit(EXIT_VALIDATION)
        if not DOMAIN_LABEL_RE.match(label):
            print("MailT: --target has invalid label (use letters, digits, hyphens; no leading/trailing hyphen). Example: example.com", file=sys.stderr)
            sys.exit(EXIT_VALIDATION)


def main() -> None:
    global _help_printed
    # Handle --help / -h explicitly once (flush so help is visible). Print only once even if main() is invoked twice.
    if "--help" in sys.argv or "-h" in sys.argv:
        if not _help_printed:
            _build_parser().print_help()
            _help_printed = True
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit(0)

    args = parse_args()
    check_requirements()
    target_domain = args.target.strip().lower()
    validate_target_domain(target_domain)
    test_email = (args.email or "").strip() or None
    test_password = (args.password or "").strip() or None
    if (test_email and not test_password) or (test_password and not test_email):
        print("MailT: --email and --password must be provided together for user-based tests.", file=sys.stderr)
        sys.exit(EXIT_VALIDATION)
    credential_aware = bool(test_email and test_password)
    # Attack mode ONLY when BOTH flags are set; otherwise no exploit code runs
    attack_mode = bool(args.attack_mode and args.i_understand_the_risks)
    if args.attack_mode and not args.i_understand_the_risks:
        print("MailT: ATTACK MODE not enabled. You must pass BOTH --attack-mode AND --i-understand-the-risks to run exploit modules.")
    all_host = (args.all_servers or "").strip() or None
    manual_smtp = (args.smtp or all_host or "").strip() or None
    manual_pop3 = (args.pop3 or all_host or "").strip() or None
    manual_imap = (args.imap or all_host or "").strip() or None

    env_cfg = load_env_config()
    file_cfg = load_file_config(args.config or "")
    cli_cfg = {
        "verbose": args.verbose if args.verbose else None,
        "output_dir": (args.output_dir or "").strip() or None,
        "output_format": (args.format or "html").lower(),
        "quiet": args.quiet if args.quiet else None,
        "log_file": (args.log_file or "").strip() or None,
        "scan_timeout_seconds": getattr(args, "timeout", None),
        "dns_timeout": getattr(args, "dns_timeout", None),
        "smtp_timeout": getattr(args, "smtp_timeout", None),
    }
    cli_cfg = {k: v for k, v in cli_cfg.items() if v is not None}
    merged = merge_config(env_cfg, file_cfg, cli_cfg)

    ctx = ScanContext(
        target_domain=target_domain,
        verbose=merged.get("verbose", False),
        attack_mode=attack_mode,
        manual_smtp_host=manual_smtp,
        manual_pop3_host=manual_pop3,
        manual_imap_host=manual_imap,
        output_dir=merged.get("output_dir"),
        output_format=merged.get("output_format", "html"),
        quiet=merged.get("quiet", False),
        log_file=merged.get("log_file"),
        scan_timeout_seconds=merged.get("scan_timeout_seconds"),
        dns_timeout=merged.get("dns_timeout"),
        smtp_timeout=merged.get("smtp_timeout"),
        test_email=test_email,
        test_password=test_password,
        credential_aware=credential_aware,
    )
    main_scan(ctx)
    if ctx.step_errors:
        sys.exit(EXIT_SCAN_FAILURE)
    sys.exit(EXIT_SUCCESS)


if __name__ == "__main__":
    main()
