"""
Common utilities: DNS resolution (robust, with status), safe network calls, logging.
MXToolbox-style: clear pass/fail/empty/timeout/nxdomain to avoid false positives.
"""
import socket
import logging
import time
from typing import Any, Optional

logger = logging.getLogger("mailt.utils")

# DNS: timeouts and retries for reliable results
DNS_TIMEOUT = 5.0
DNS_RETRIES = 2
DNS_LIFETIME = 10.0  # max total time per query


def _dns_resolve(
    domain: str,
    rtype: str,
    extract: Any,
) -> tuple[list[Any], str, str]:
    """
    Resolve DNS with retries. Returns (data_list, status, message).
    status: ok | empty | nxdomain | timeout | error
    """
    import dns.resolver
    import dns.exception

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    last_exc = None
    for attempt in range(DNS_RETRIES + 1):
        try:
            answers = resolver.resolve(domain, rtype)
            data = extract(answers)
            if data:
                return (data, "ok", "")
            return ([], "empty", "No records")
        except dns.resolver.NXDOMAIN:
            return ([], "nxdomain", "Domain does not exist")
        except dns.resolver.NoAnswer:
            return ([], "empty", "No records")
        except dns.resolver.NoNameservers:
            last_exc = "No nameservers"
        except dns.exception.Timeout:
            last_exc = "Timeout"
        except Exception as e:
            last_exc = str(e)
            logger.debug("%s %s failed: %s", rtype, domain, e)
    return ([], "timeout" if "Timeout" in str(last_exc) else "error", last_exc or "Unknown error")


def _extract_mx(answers) -> list[tuple[int, str]]:
    return [(r.preference, str(r.exchange).rstrip(".")) for r in answers]


def _extract_txt(answers) -> list[str]:
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]


def _extract_ns(answers) -> list[str]:
    return [str(r.target).rstrip(".") for r in answers]


def _extract_a(answers) -> list[str]:
    return [str(r.address) for r in answers]


def _extract_aaaa(answers) -> list[str]:
    return [str(r.address) for r in answers]


def resolve_a_ex(domain: str) -> tuple[list[str], str, str]:
    """A records with status. Returns (addresses, status, message). status: ok | empty | nxdomain | timeout | error."""
    return _dns_resolve(domain, "A", _extract_a)


def resolve_aaaa_ex(domain: str) -> tuple[list[str], str, str]:
    """AAAA records with status. Returns (addresses, status, message). status: ok | empty | nxdomain | timeout | error."""
    return _dns_resolve(domain, "AAAA", _extract_aaaa)


def resolve_mx_ex(domain: str) -> tuple[list[tuple[int, str]], str, str]:
    """MX with status. Returns (records, status, message). status: ok | empty | nxdomain | timeout | error."""
    return _dns_resolve(domain, "MX", _extract_mx)


def resolve_txt_ex(domain: str) -> tuple[list[str], str, str]:
    """TXT with status."""
    return _dns_resolve(domain, "TXT", _extract_txt)


def resolve_ns_ex(domain: str) -> tuple[list[str], str, str]:
    """NS with status."""
    return _dns_resolve(domain, "NS", _extract_ns)


def resolve_mx(domain: str) -> list[tuple[int, str]]:
    """Resolve MX records. Returns list of (preference, hostname). Backward compat."""
    data, _, _ = resolve_mx_ex(domain)
    return data


def resolve_txt(domain: str) -> list[str]:
    """Resolve TXT records. Backward compat."""
    data, _, _ = resolve_txt_ex(domain)
    return data


def resolve_ns(domain: str) -> list[str]:
    """Resolve NS records. Backward compat."""
    data, _, _ = resolve_ns_ex(domain)
    return data


def resolve_a(domain: str) -> list[str]:
    """Resolve A records for domain. Returns list of IPv4 addresses. Backward compat; use resolve_a_ex for status."""
    data, _, _ = resolve_a_ex(domain)
    return data


def resolve_aaaa(domain: str) -> list[str]:
    """Resolve AAAA records for domain. Returns list of IPv6 addresses. Backward compat; use resolve_aaaa_ex for status."""
    data, _, _ = resolve_aaaa_ex(domain)
    return data


def resolve_ptr(ip: str) -> tuple[list[str], str, str]:
    """
    Reverse DNS (PTR) lookup for an IPv4 address.
    Returns (list of PTR hostnames, status, message). status: ok | empty | timeout | error
    """
    import dns.reversename
    import dns.resolver
    import dns.exception

    try:
        rev = dns.reversename.from_address(ip)
    except Exception as e:
        return ([], "error", str(e))
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME
    try:
        answers = resolver.resolve(rev, "PTR")
        ptr_list = [str(r.target).rstrip(".") for r in answers]
        return (ptr_list, "ok", "") if ptr_list else ([], "empty", "No PTR records")
    except dns.resolver.NXDOMAIN:
        return ([], "empty", "No PTR records")
    except dns.resolver.NoAnswer:
        return ([], "empty", "No PTR records")
    except dns.exception.Timeout:
        return ([], "timeout", "Timeout")
    except Exception as e:
        logger.debug("PTR for %s failed: %s", ip, e)
        return ([], "error", str(e))


def safe_socket_connect(host: str, port: int, timeout: float = 10.0) -> Optional[socket.socket]:
    """Create TCP connection to host:port. Returns socket or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    except (socket.error, OSError) as e:
        logger.debug("Connect %s:%s failed: %s", host, port, e)
        return None


def read_line(sock: socket.socket, timeout: float = 10.0) -> Optional[str]:
    """Read a single line (CRLF) from socket."""
    sock.settimeout(timeout)
    try:
        data = b""
        while not data.endswith(b"\r\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError, UnicodeDecodeError):
        return None


def get_smtp_host_from_mx(mx_list: list, fallback_domain: str) -> str:
    """
    Return the best MX host for SMTP connection.
    Sorts by preference (lower first), skips empty hostnames, falls back to domain.
    """
    sorted_mx = get_mx_hosts_sorted(mx_list)
    if not sorted_mx:
        return fallback_domain.strip().lower()
    host = (sorted_mx[0][1] or "").strip()
    return host if host else fallback_domain.strip().lower()


def get_smtp_host(ctx: Any) -> str:
    """Return SMTP host: manual_smtp_host if set, else MX-derived host."""
    manual = getattr(ctx, "manual_smtp_host", None)
    if manual and str(manual).strip():
        return str(manual).strip().lower()
    return get_smtp_host_from_mx(ctx.dns_data.get("mx", []), ctx.target_domain)


def get_pop3_host(ctx: Any) -> str:
    """Return POP3 host: manual_pop3_host if set, else MX-derived host."""
    manual = getattr(ctx, "manual_pop3_host", None)
    if manual and str(manual).strip():
        return str(manual).strip().lower()
    return get_smtp_host_from_mx(ctx.dns_data.get("mx", []), ctx.target_domain)


def get_imap_host(ctx: Any) -> str:
    """Return IMAP host: manual_imap_host if set, else MX-derived host."""
    manual = getattr(ctx, "manual_imap_host", None)
    if manual and str(manual).strip():
        return str(manual).strip().lower()
    return get_smtp_host_from_mx(ctx.dns_data.get("mx", []), ctx.target_domain)


def get_mx_hosts_sorted(mx_list: list) -> list[tuple[int, str]]:
    """
    Return MX list sorted by preference (lower first), with empty hostnames skipped.
    Each item is (preference, hostname). Primary is first, then backup MX hosts.
    """
    if not mx_list:
        return []
    return sorted(
        [(int(m[0]), (m[1] or "").strip()) for m in mx_list if len(m) >= 2 and (m[1] or "").strip()],
        key=lambda x: (x[0], x[1]),
    )


def platform_hint_from_banner(banner: str) -> Optional[str]:
    """Guess mail platform from SMTP banner string."""
    if not banner:
        return None
    if "Microsoft" in banner or "Exchange" in banner:
        return "Microsoft Exchange / M365"
    if "ESMTP" in banner and "Postfix" in banner:
        return "Postfix"
    if "Zimbra" in banner:
        return "Zimbra"
    if "Sendmail" in banner:
        return "Sendmail"
    if "Exim" in banner:
        return "Exim"
    return None
