"""
BIMI (Brand Indicators for Message Identification) check.
"""
import logging
from core.context import ScanContext
from core.utils import resolve_txt_ex

logger = logging.getLogger("mailt.dns")


def _get_bimi_record(domain: str) -> tuple[str | None, str, str]:
    """Returns (record_or_none, status, message). status: ok | empty | nxdomain | timeout | error."""
    bimi_domain = f"default._bimi.{domain}"
    txts, status, message = resolve_txt_ex(bimi_domain)
    for t in txts:
        if "v=BIMI1" in t:
            return (t.strip(), "ok", "")
    return (None, status, message)


def run(ctx: ScanContext) -> None:
    domain = ctx.target_domain
    bimi_raw, bimi_status, bimi_message = _get_bimi_record(domain)
    ctx.add_dns_data("bimi_record", bimi_raw)
    ctx.add_dns_data("bimi_status", bimi_status)
    ctx.add_dns_data("bimi_message", bimi_message)
    if ctx.verbose and bimi_raw:
        logger.debug("BIMI: %s | status=%s", bimi_raw[:80], bimi_status)
