"""
DKIM selector discovery via TXT lookup on selector._domainkey.domain.
Parses public key (p=) and estimates key length for weak-key finding.
"""
import base64
import logging
import re
from core.context import ScanContext
from core.utils import resolve_txt

logger = logging.getLogger("mailt.dns")

# Minimum RSA key length (bits) to consider strong
DKIM_MIN_KEY_BITS = 2048

# Common selectors used by major providers
COMMON_SELECTORS = [
    "default", "dkim", "key1", "key2", "selector1", "selector2",
    "k1", "mx", "s1", "s2", "mail", "google", "sendgrid", "ses"
]


def _parse_public_key_bits(record: str) -> tuple[int | None, bool]:
    """
    Extract p= value from DKIM record, decode base64, estimate key size in bits.
    Returns (estimated_bits, weak) where weak=True if < DKIM_MIN_KEY_BITS.
    """
    match = re.search(r"\bp=([A-Za-z0-9+/=]+)\b", record)
    if not match:
        return (None, False)
    try:
        raw = base64.b64decode(match.group(1), validate=True)
    except Exception:
        return (None, False)
    # Rough estimate: DER-encoded RSA public key size -> modulus bits
    # 140 bytes ~ 1024-bit, 270 ~ 2048-bit
    estimated_bits = len(raw) * 8
    weak = estimated_bits > 0 and estimated_bits < DKIM_MIN_KEY_BITS
    return (estimated_bits, weak)


def _check_selector(domain: str, selector: str) -> dict | None:
    name = f"{selector}._domainkey.{domain}"
    txts = resolve_txt(name)
    for t in txts:
        if "v=DKIM1" in t or "p=" in t:
            out = {"selector": selector, "record": t[:500]}
            bits, weak = _parse_public_key_bits(t)
            if bits is not None:
                out["public_key_bits"] = bits
                out["weak_key"] = weak
            return out
    return None


def run(ctx: ScanContext) -> None:
    domain = ctx.target_domain
    discovered = []

    for sel in COMMON_SELECTORS:
        result = _check_selector(domain, sel)
        if result:
            discovered.append(result)
            if ctx.verbose:
                logger.debug("DKIM selector found: %s", sel)

    ctx.add_dns_data("dkim_selectors", discovered)
