"""
SPF record analysis: presence, mechanisms, lookup limit.
"""
import re
import logging
from core.context import ScanContext
from core.utils import resolve_txt, resolve_txt_ex

logger = logging.getLogger("mailt.dns")

SPF_PREFIX = "v=spf1 "


def _get_spf_record(domain: str) -> tuple[str | None, str, str]:
    """Returns (spf_record_or_none, status, message). status: ok | empty | nxdomain | timeout | error."""
    txts, status, message = resolve_txt_ex(domain)
    for t in txts:
        if t.strip().lower().startswith("v=spf1"):
            return (t.strip(), "ok", "")
    return (None, status, message)


def _parse_mechanisms(spf: str) -> list[dict]:
    """Extract mechanisms (include, a, mx, etc.) and modifiers."""
    parts = spf[len(SPF_PREFIX):].split()
    mechanisms = []
    for p in parts:
        if p.lower().startswith("include:"):
            mechanisms.append({"type": "include", "value": p[8:].strip()})
        elif p.lower() in ("all", "-all", "~all", "?all", "+all"):
            mechanisms.append({"type": "all", "qualifier": p[0] if p[0] in "-~?" else "+"})
        elif p.lower().startswith("a:"):
            mechanisms.append({"type": "a", "domain": p[2:].strip() or None})
        elif p.lower().startswith("mx:"):
            mechanisms.append({"type": "mx", "domain": p[3:].strip() or None})
        elif p.lower() in ("a", "mx", "ptr"):
            mechanisms.append({"type": p.lower(), "value": None})
        elif "=" in p:
            mechanisms.append({"type": "mechanism", "raw": p})
        else:
            mechanisms.append({"type": "other", "raw": p})
    return mechanisms


def _count_dns_lookups(domain: str, spf: str, seen: set) -> int:
    """Estimate DNS lookups (include, a, mx, etc.). Simplified."""
    count = 0
    for part in spf[len(SPF_PREFIX):].split():
        part_lower = part.lower()
        if part_lower.startswith("include:"):
            count += 1
            inc_domain = part[8:].strip().split("/")[0].strip()
            if inc_domain and inc_domain not in seen:
                seen.add(inc_domain)
                inc_txt = resolve_txt(inc_domain)
                for t in inc_txt:
                    if t.strip().lower().startswith("v=spf1"):
                        count += _count_dns_lookups(inc_domain, t.strip(), seen)
                        break
        elif part_lower.startswith("a:") or part_lower.startswith("mx:"):
            count += 1
        elif part_lower in ("a", "mx"):
            count += 1
    return count


def run(ctx: ScanContext) -> None:
    domain = ctx.target_domain
    spf_raw, spf_status, spf_message = _get_spf_record(domain)
    mechanisms = []
    lookup_count = 0
    all_qualifier = None

    if spf_raw:
        mechanisms = _parse_mechanisms(spf_raw)
        lookup_count = _count_dns_lookups(domain, spf_raw, set())
        for m in mechanisms:
            if m.get("type") == "all":
                all_qualifier = m.get("qualifier") or "pass"
                break

    ctx.add_dns_data("spf_record", spf_raw)
    ctx.add_dns_data("spf_status", spf_status)
    ctx.add_dns_data("spf_message", spf_message)
    ctx.add_dns_data("spf_mechanisms", mechanisms)
    ctx.add_dns_data("spf_lookup_count", lookup_count)
    ctx.add_dns_data("spf_all_qualifier", all_qualifier)

    if ctx.verbose and spf_raw:
        logger.debug("SPF: %s | lookups ~%d | all=%s | status=%s", spf_raw[:80], lookup_count, all_qualifier, spf_status)
