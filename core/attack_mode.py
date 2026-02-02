"""
Attack mode enforcement: test domains, test mailbox, rate limit, max attempts.
Exploit code MUST check attack_mode and use these constants only.
"""
import logging
import time
from typing import Optional

logger = logging.getLogger("mailt.attack_mode")

# RFC 2606 / 6761 test domains — never use real org/person addresses
RFC_TEST_DOMAINS = ("example.net", "example.org", "example.com")
# Test mailbox / sinkhole — no real recipient
TEST_MAILBOX_LOCAL = "blackhole@localhost"
TEST_MAILBOX_RFC = "mailt-poc@example.org"

# Rate limit: min seconds between exploit attempts per module
RATE_LIMIT_SECONDS = 2.0
# Max attempts per exploit type (e.g. AUTH attempts)
MAX_AUTH_ATTEMPTS = 5
MAX_RELAY_ATTEMPTS = 2
MAX_SPOOF_ATTEMPTS = 1

# Last attempt time per module (for rate limit)
_last_attempt: dict[str, float] = {}


def require_attack_mode(ctx) -> bool:
    """Return True only if context has attack_mode enabled. Exploit modules must skip if False."""
    return getattr(ctx, "attack_mode", False)


def enforce_rate_limit(module_name: str) -> None:
    """Sleep if needed to enforce rate limit between exploit attempts."""
    now = time.monotonic()
    last = _last_attempt.get(module_name, 0)
    elapsed = now - last
    if elapsed < RATE_LIMIT_SECONDS:
        time.sleep(RATE_LIMIT_SECONDS - elapsed)
    _last_attempt[module_name] = time.monotonic()


def get_test_rcpt_address() -> str:
    """Return allowed RCPT TO address for PoC (RFC test domain)."""
    return f"mailt-poc@{RFC_TEST_DOMAINS[1]}"


def get_test_from_domain() -> str:
    """Return allowed MAIL FROM domain for external relay PoC."""
    return RFC_TEST_DOMAINS[0]


def get_test_to_domain() -> str:
    """Return allowed RCPT TO domain for external relay PoC (different from from)."""
    return RFC_TEST_DOMAINS[1]


def log_attack_warning() -> None:
    """Emit warning that active exploitation tests are about to run."""
    logger.warning("[WARNING] You are about to perform active exploitation tests (ATTACK MODE).")
