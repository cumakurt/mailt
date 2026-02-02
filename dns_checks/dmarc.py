"""
DMARC policy: record at _dmarc.domain, policy (none/quarantine/reject).
"""
import re
import logging
from core.context import ScanContext
from core.utils import resolve_txt_ex

logger = logging.getLogger("mailt.dns")


def _get_dmarc_record(domain: str) -> tuple[str | None, str, str]:
    """Returns (record_or_none, status, message). status: ok | empty | nxdomain | timeout | error."""
    dmarc_domain = f"_dmarc.{domain}"
    txts, status, message = resolve_txt_ex(dmarc_domain)
    for t in txts:
        if "v=DMARC1" in t:
            return (t.strip(), "ok", "")
    return (None, status, message)


def _parse_dmarc(record: str) -> dict:
    policy = "none"
    subdomain_policy = None
    rua = []
    ruf = []
    pct = None
    adkim = "r"
    aspf = "r"
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k, v = k.strip().lower(), v.strip().lower()
        if k == "p":
            policy = v
        elif k == "sp":
            subdomain_policy = v
        elif k == "rua":
            rua.append(v)
        elif k == "ruf":
            ruf.append(v)
        elif k == "pct":
            try:
                pct = int(v)
            except ValueError:
                pass
        elif k == "adkim":
            adkim = v
        elif k == "aspf":
            aspf = v
    return {
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "rua": rua,
        "ruf": ruf,
        "pct": pct,
        "adkim": adkim,
        "aspf": aspf,
    }


def run(ctx: ScanContext) -> None:
    domain = ctx.target_domain
    dmarc_raw, dmarc_status, dmarc_message = _get_dmarc_record(domain)
    parsed = {}

    if dmarc_raw:
        parsed = _parse_dmarc(dmarc_raw)
        if ctx.verbose:
            logger.debug("DMARC policy: %s | status=%s", parsed.get("policy"), dmarc_status)

    ctx.add_dns_data("dmarc_record", dmarc_raw)
    ctx.add_dns_data("dmarc_status", dmarc_status)
    ctx.add_dns_data("dmarc_message", dmarc_message)
    ctx.add_dns_data("dmarc_parsed", parsed)
