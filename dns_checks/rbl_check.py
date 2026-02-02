"""
RBL/DNSBL check: passive DNS lookup of SMTP IPs against global blacklists.
Tests MX and manual SMTP host IPs against Spamhaus, Spamcop, SORBS, Barracuda, etc.
No third-party API or web scraping; fault-tolerant with timeout and rate-limit handling.
"""
import ipaddress
import logging
from typing import Any

from core.context import ScanContext
from core.utils import resolve_a_ex

logger = logging.getLogger("mailt.rbl")

# Widely used RBL zones (passive DNS only). Format: reversed IP + "." + zone
RBL_ZONES = [
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "description": "Combined SBL/XBL/PBL"},
    {"name": "Spamcop", "zone": "bl.spamcop.net", "description": "Spamcop blocklist"},
    {"name": "SORBS", "zone": "dnsbl.sorbs.net", "description": "SORBS DNSBL"},
    {"name": "Barracuda", "zone": "b.barracudacentral.org", "description": "Barracuda Reputation"},
    {"name": "CBL", "zone": "cbl.abuseat.org", "description": "Composite Blocking List"},
    {"name": "PSBL", "zone": "psbl.surriel.com", "description": "Passive Spam Block List"},
    {"name": "UCEPROTECT L1", "zone": "dnsbl-1.uceprotect.net", "description": "UCEPROTECT Level 1"},
    {"name": "Spamhaus SBL-XBL", "zone": "sbl.spamhaus.org", "description": "Spamhaus SBL"},
    {"name": "Spamhaus XBL", "zone": "xbl.spamhaus.org", "description": "Spamhaus Exploits"},
]

# Shorter timeout per RBL to avoid long stalls; rate-limit friendly
RBL_QUERY_TIMEOUT = 3.0
RBL_LIFETIME = 5.0


def _reverse_ip_v4(ip: str) -> str | None:
    """Return reversed octets for IPv4 (e.g. 1.2.3.4 -> 4.3.2.1)."""
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        return ".".join(reversed(ip.strip().split(".")))
    except (ValueError, AttributeError):
        return None


def _reverse_ip_v6(ip: str) -> str | None:
    """Return reversed nibbles with dots for IPv6 (e.g. 2001:db8::1 -> 1.0.0.0...)."""
    try:
        addr = ipaddress.IPv6Address(ip.strip())
        expanded = addr.exploded.replace(":", "")
        return ".".join(reversed(expanded))
    except (ValueError, AttributeError):
        return None


def _reverse_ip(ip: str) -> str | None:
    """Return RBL query suffix (reversed IP) for IPv4 or IPv6."""
    ip = (ip or "").strip()
    if not ip:
        return None
    if ":" in ip:
        return _reverse_ip_v6(ip)
    return _reverse_ip_v4(ip)


def _query_rbl(ip: str, zone: str) -> dict[str, Any]:
    """
    Query one RBL zone for one IP. Returns {listed, response, status, message}.
    Uses passive DNS only; handles timeout, NXDOMAIN, and errors safely.
    """
    reversed_ip = _reverse_ip(ip)
    if not reversed_ip:
        return {"listed": False, "response": None, "status": "error", "message": "invalid_ip"}
    query = f"{reversed_ip}.{zone}".lower()
    try:
        import dns.resolver
        import dns.exception
        resolver = dns.resolver.Resolver()
        resolver.timeout = RBL_QUERY_TIMEOUT
        resolver.lifetime = RBL_LIFETIME
        answers = resolver.resolve(query, "A")
        responses = [str(r.address) for r in answers]
        # Any A record (typically 127.0.0.x) means listed
        return {
            "listed": True,
            "response": responses[0] if responses else None,
            "status": "ok",
            "message": "; ".join(responses[:3]) if responses else "listed",
        }
    except dns.resolver.NXDOMAIN:
        return {"listed": False, "response": None, "status": "ok", "message": "not_listed"}
    except dns.resolver.NoAnswer:
        return {"listed": False, "response": None, "status": "ok", "message": "not_listed"}
    except dns.exception.Timeout:
        return {"listed": False, "response": None, "status": "timeout", "message": "timeout"}
    except dns.resolver.NoNameservers:
        return {"listed": False, "response": None, "status": "error", "message": "no_nameservers"}
    except Exception as e:
        logger.debug("RBL query %s failed: %s", query, e)
        return {"listed": False, "response": None, "status": "error", "message": str(e)[:200]}


def _get_smtp_hosts(ctx: ScanContext) -> list[tuple[str, str]]:
    """Return list of (hostname, source) to resolve: MX hosts + manual SMTP if set."""
    hosts: list[tuple[str, str]] = []
    seen: set[str] = set()
    domain = ctx.target_domain

    # MX hostnames (sorted by preference)
    mx_list = ctx.dns_data.get("mx") or []
    from core.utils import get_mx_hosts_sorted
    for _pref, mx_host in get_mx_hosts_sorted(mx_list):
        h = (mx_host or "").strip().lower()
        if h and h not in seen:
            seen.add(h)
            hosts.append((h, "mx"))

    # Manual SMTP host (--smtp or --all)
    manual = (ctx.manual_smtp_host or "").strip().lower()
    if manual and manual not in seen:
        seen.add(manual)
        hosts.append((manual, "manual_smtp"))

    return hosts


def _resolve_host_ips(host: str) -> list[str]:
    """Resolve host to IPv4 and IPv6 addresses. Returns list of IP strings."""
    ips: list[str] = []
    a_list, a_status, _ = resolve_a_ex(host)
    if a_status == "ok" and a_list:
        ips.extend(a_list)
    from core.utils import resolve_aaaa_ex
    aaaa_list, aaaa_status, _ = resolve_aaaa_ex(host)
    if aaaa_status == "ok" and aaaa_list:
        ips.extend(aaaa_list)
    return ips


def _compute_reputation_score(listed_count: int, total_checked: int) -> float:
    """
    SMTP IP reputation score 0.0 (good) to 1.0 (bad).
    Based on fraction of RBLs that list the IP; only definitive results (ok) count.
    """
    if total_checked <= 0:
        return 0.0
    return min(1.0, listed_count / total_checked)


def run(ctx: ScanContext) -> None:
    """
    Resolve SMTP-related hosts (MX + manual) to IPs, query each IP against all RBL zones,
    store results in ctx.smtp_data["rbl_check"]. Default active; fault-tolerant.
    """
    result: dict[str, Any] = {
        "ips_tested": [],
        "by_ip": {},
        "summary": {"any_listed": False, "ips_listed_count": 0, "total_ips": 0, "rbl_zones_count": len(RBL_ZONES)},
        "rbl_zones": [{"name": z["name"], "zone": z["zone"], "description": z["description"]} for z in RBL_ZONES],
    }
    hosts = _get_smtp_hosts(ctx)
    if not hosts:
        ctx.add_smtp_data("rbl_check", result)
        return

    all_ips: list[tuple[str, str, str]] = []  # (ip, host, source)
    for host, source in hosts:
        for ip in _resolve_host_ips(host):
            all_ips.append((ip, host, source))

    # Deduplicate by IP (keep first host/source)
    seen_ip: set[str] = set()
    unique_ips: list[tuple[str, str, str]] = []
    for ip, host, source in all_ips:
        if ip not in seen_ip:
            seen_ip.add(ip)
            unique_ips.append((ip, host, source))

    result["summary"]["total_ips"] = len(unique_ips)

    for ip, host, source in unique_ips:
        result["ips_tested"].append({"ip": ip, "host": host, "source": source})
        by_ip: dict[str, Any] = {
            "host": host,
            "source": source,
            "results": {},
            "listed_count": 0,
            "total_checked": 0,
            "reputation_score": 0.0,
        }
        for z in RBL_ZONES:
            zone_name = z["zone"]
            q = _query_rbl(ip, zone_name)
            by_ip["results"][zone_name] = {
                "listed": q["listed"],
                "response": q["response"],
                "status": q["status"],
                "message": q.get("message", ""),
            }
            if q["status"] == "ok":
                by_ip["total_checked"] += 1
                if q["listed"]:
                    by_ip["listed_count"] += 1
        by_ip["reputation_score"] = _compute_reputation_score(
            by_ip["listed_count"], by_ip["total_checked"]
        )
        result["by_ip"][ip] = by_ip
        if by_ip["listed_count"] > 0:
            result["summary"]["any_listed"] = True
            result["summary"]["ips_listed_count"] = result["summary"].get("ips_listed_count", 0) + 1

    ctx.add_smtp_data("rbl_check", result)
    if ctx.verbose:
        listed_ips = [ip for ip, data in result["by_ip"].items() if data["listed_count"] > 0]
        logger.debug(
            "RBL check: %d IP(s) tested, %d listed; listed IPs: %s",
            result["summary"]["total_ips"],
            result["summary"]["ips_listed_count"],
            listed_ips[:5],
        )
