"""
Mail ecosystem surface discovery: SMTP, POP3, IMAP, Webmail.
Port-based discovery, banner grabbing, TLS capability. SAFE MODE only (no exploit).
"""
import logging
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host, get_pop3_host, get_imap_host

logger = logging.getLogger("mailt.mail")

TIMEOUT = 8.0
PORTS = {
    "smtp": 25,
    "smtps": 465,
    "submission": 587,
    "pop3": 110,
    "pop3s": 995,
    "imap": 143,
    "imaps": 993,
    "http": 80,
    "https": 443,
}


def _probe_port(host: str, port: int, use_tls: bool = False, timeout: float = TIMEOUT) -> dict:
    """Probe single port; return open, banner, error."""
    out = {"open": False, "banner": None, "tls": use_tls, "error": None}
    sock = safe_socket_connect(host, port, timeout)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            banner = read_line(tls_sock, timeout)
            out["open"] = True
            out["banner"] = banner
            out["tls_version"] = getattr(tls_sock, "version", None)
            tls_sock.close()
        else:
            banner = read_line(sock, timeout)
            out["open"] = True
            out["banner"] = banner
        sock.close()
    except ssl.SSLError as e:
        out["error"] = f"ssl_error:{e}"
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _probe_webmail_paths(domain: str, timeout: float = 6.0) -> dict:
    """Probe common webmail paths via HTTPS; return detected product/version from headers/HTML."""
    import urllib.request
    import urllib.error

    paths = ["/", "/owa/", "/roundcube/", "/webmail/", "/mail/", "/zimbra/", "/horde/"]
    seen_products = set()
    detected = []
    base = f"https://{domain}"
    for path in paths:
        url = base + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MailT/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = dict(resp.headers)
                html = resp.read().decode("utf-8", errors="replace")[:4096]
                hdr_str = str(headers).lower()
                html_lower = html.lower()
                if ("roundcube" in html_lower or "roundcube" in hdr_str) and "Roundcube" not in seen_products:
                    seen_products.add("Roundcube")
                    detected.append({"path": path, "product": "Roundcube", "version": _extract_version(html, "roundcube")})
                if ("owa" in path or "outlook" in html_lower or "exchange" in hdr_str) and "OWA" not in seen_products:
                    seen_products.add("OWA")
                    detected.append({"path": path, "product": "OWA/Exchange", "version": None})
                if ("zimbra" in html_lower or "zimbra" in hdr_str) and "Zimbra" not in seen_products:
                    seen_products.add("Zimbra")
                    detected.append({"path": path, "product": "Zimbra", "version": _extract_version(html, "zimbra")})
                if "horde" in html_lower and "Horde" not in seen_products:
                    seen_products.add("Horde")
                    detected.append({"path": path, "product": "Horde", "version": None})
                if "cpanel" in html_lower and "cPanel" not in seen_products:
                    seen_products.add("cPanel")
                    detected.append({"path": path, "product": "cPanel Webmail", "version": None})
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, Exception):
            continue
    return {"detected": detected[:10], "base": base}


def _extract_version(html: str, product: str) -> str | None:
    """Simple version extraction from HTML meta or comment."""
    import re
    if "roundcube" in product.lower():
        m = re.search(r"roundcube[^\d]*([\d.]+)", html.lower())
        return m.group(1) if m else None
    if "zimbra" in product.lower():
        m = re.search(r"zimbra[^\d]*([\d.]+)", html.lower())
        return m.group(1) if m else None
    return None


def run(ctx: ScanContext) -> None:
    smtp_host = get_smtp_host(ctx)
    pop3_host = get_pop3_host(ctx)
    imap_host = get_imap_host(ctx)
    domain = ctx.target_domain
    result = {"ports": {}, "webmail": None}

    # SMTP
    result["ports"]["smtp_25"] = _probe_port(smtp_host, PORTS["smtp"], use_tls=False)
    result["ports"]["smtps_465"] = _probe_port(smtp_host, PORTS["smtps"], use_tls=True)
    result["ports"]["submission_587"] = _probe_port(smtp_host, PORTS["submission"], use_tls=False)
    # POP3
    result["ports"]["pop3_110"] = _probe_port(pop3_host, PORTS["pop3"], use_tls=False)
    result["ports"]["pop3s_995"] = _probe_port(pop3_host, PORTS["pop3s"], use_tls=True)
    # IMAP
    result["ports"]["imap_143"] = _probe_port(imap_host, PORTS["imap"], use_tls=False)
    result["ports"]["imaps_993"] = _probe_port(imap_host, PORTS["imaps"], use_tls=True)

    # Webmail: try SMTP host and domain
    for host in (smtp_host, domain):
        if host != smtp_host or not result["ports"].get("smtp_25", {}).get("error"):
            w = _probe_webmail_paths(host)
            if w.get("detected"):
                result["webmail"] = w
                break

    ctx.add_smtp_data("mail_service_discovery", result)
    if ctx.verbose:
        open_ports = [k for k, v in result["ports"].items() if v.get("open")]
        webmail = (result.get("webmail") or {}).get("detected")
        logger.debug("Mail discovery: open=%s webmail=%s", open_ports, webmail)
