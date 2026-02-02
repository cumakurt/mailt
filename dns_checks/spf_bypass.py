"""
SPF bypass and misconfiguration analysis: +all/~all/?all, subdomain SPF, envelope vs header risk.
Uses existing DNS data and optional subdomain lookups. No mail sent.
"""
import logging
from core.context import ScanContext
from core.utils import resolve_txt_ex

logger = logging.getLogger("mailt.dns")

SPF_PREFIX = "v=spf1"
COMMON_SUBDOMAINS = ("mail", "hr", "smtp", "email", "corp")


def _has_spf(domain: str) -> bool:
    """Return True if domain has any TXT record starting with v=spf1."""
    txts, status, _ = resolve_txt_ex(domain)
    for t in txts:
        if t.strip().lower().startswith(SPF_PREFIX):
            return True
    return False


def run(ctx: ScanContext) -> None:
    domain = ctx.target_domain
    d = ctx.dns_data

    result = {
        "subdomain_no_spf": [],
        "spf_plus_all": False,
        "spf_softfail": False,
        "spf_neutral": False,
        "spf_lookup_over_10": False,
        "dmarc_p_none": False,
        "spf_only_no_dkim_dmarc": False,
    }

    all_qualifier = d.get("spf_all_qualifier")
    if all_qualifier == "+":
        result["spf_plus_all"] = True
    elif all_qualifier == "~":
        result["spf_softfail"] = True
    elif all_qualifier == "?":
        result["spf_neutral"] = True

    if (d.get("spf_lookup_count") or 0) > 10:
        result["spf_lookup_over_10"] = True

    dmarc_parsed = d.get("dmarc_parsed") or {}
    if dmarc_parsed.get("policy") == "none":
        result["dmarc_p_none"] = True

    has_spf = bool(d.get("spf_record"))
    has_dkim = bool(d.get("dkim_selectors"))
    has_dmarc = bool(d.get("dmarc_record"))
    if has_spf and not has_dkim and not has_dmarc:
        result["spf_only_no_dkim_dmarc"] = True

    for sub in COMMON_SUBDOMAINS:
        subdomain = f"{sub}.{domain}"
        if not _has_spf(subdomain):
            result["subdomain_no_spf"].append(subdomain)

    ctx.add_dns_data("spf_bypass", result)
    if ctx.verbose:
        logger.debug(
            "SPF bypass: +all=%s ~all=%s ?all=%s subdomain_no_spf=%s spf_only=%s",
            result["spf_plus_all"],
            result["spf_softfail"],
            result["spf_neutral"],
            result["subdomain_no_spf"],
            result["spf_only_no_dkim_dmarc"],
        )
