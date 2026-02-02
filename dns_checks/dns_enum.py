"""
DNS enumeration: MX, A, AAAA, TXT, NS for target domain.
Uses robust resolution with status (ok/empty/nxdomain/timeout/error) to avoid false positives.
"""
import logging
from core.context import ScanContext
from core.utils import (
    resolve_a_ex,
    resolve_aaaa_ex,
    resolve_mx_ex,
    resolve_txt_ex,
    resolve_ns_ex,
    resolve_ptr,
)

logger = logging.getLogger("mailt.dns")


def run(ctx: ScanContext) -> None:
    domain = ctx.target_domain
    mx_list, mx_status, mx_message = resolve_mx_ex(domain)
    txt_list, txt_status, txt_message = resolve_txt_ex(domain)
    ns_list, ns_status, ns_message = resolve_ns_ex(domain)
    a_list, a_status, a_message = resolve_a_ex(domain)
    aaaa_list, aaaa_status, aaaa_message = resolve_aaaa_ex(domain)

    ctx.add_dns_data("mx", mx_list)
    ctx.add_dns_data("mx_status", mx_status)
    ctx.add_dns_data("mx_message", mx_message)
    ctx.add_dns_data("a", a_list)
    ctx.add_dns_data("a_status", a_status)
    ctx.add_dns_data("a_message", a_message)
    ctx.add_dns_data("aaaa", aaaa_list)
    ctx.add_dns_data("aaaa_status", aaaa_status)
    ctx.add_dns_data("aaaa_message", aaaa_message)
    ctx.add_dns_data("txt_raw", txt_list)
    ctx.add_dns_data("txt_status", txt_status)
    ctx.add_dns_data("txt_message", txt_message)
    ctx.add_dns_data("ns", ns_list)
    ctx.add_dns_data("ns_status", ns_status)
    ctx.add_dns_data("ns_message", ns_message)

    # PTR / reverse DNS for MX host IPs (first 3 MX hosts, one A per host to limit queries)
    ptr_results = []
    for pref, mx_host in (mx_list or [])[:3]:
        host = (mx_host or "").strip()
        if not host:
            continue
        ips, _, _ = resolve_a_ex(host)
        for ip in ips[:1]:
            ptr_list, ptr_status, ptr_msg = resolve_ptr(ip)
            ptr_results.append({
                "mx_host": host,
                "ip": ip,
                "ptr": ptr_list,
                "ptr_status": ptr_status,
                "ptr_message": ptr_msg,
            })
    ctx.add_dns_data("ptr_results", ptr_results)

    if ctx.verbose:
        logger.debug(
            "MX: %s (status=%s) | A: %s (status=%s) | AAAA: %s (status=%s) | TXT count: %d (status=%s)",
            mx_list, mx_status, a_list, a_status, aaaa_list, aaaa_status, len(txt_list), txt_status,
        )
