"""
SMTP enumeration: connect to MX, read banner, EHLO, AUTH list, VRFY/EXPN, HELP.
Port discovery: 25, 465 (SMTPS), 587 (Submission). Anonymous only; no credentials.
"""
import logging
import socket
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, platform_hint_from_banner, get_smtp_host
from core.constants import (
    SMTP_PORT,
    SMTP_PORT_SUBMISSION,
    SMTP_PORT_SMTPS,
    SMTP_BANNER_TIMEOUT,
    EHLO_IDENTITY,
)

logger = logging.getLogger("mailt.smtp")


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _collect_help(sock) -> list[str]:
    """Send HELP and collect response lines (214/211 continuation)."""
    lines = []
    try:
        _send(sock, "HELP")
        while True:
            line = read_line(sock, SMTP_BANNER_TIMEOUT)
            if not line:
                break
            lines.append(line)
            code = line[:3] if len(line) >= 3 else ""
            if code not in ("214", "211", "250") or (len(line) > 4 and line[3:4] != "-"):
                break
        return lines
    except Exception:
        return lines


def _collect_banner_and_ehlo(host: str, port: int = SMTP_PORT) -> dict:
    out = {
        "banner": None,
        "ehlo_lines": [],
        "help_response": [],
        "auth_mechanisms": [],
        "starttls_supported": False,
        "vrfy_supported": False,
        "expn_supported": False,
        "error": None,
    }
    sock = safe_socket_connect(host, port, SMTP_BANNER_TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        banner = read_line(sock, SMTP_BANNER_TIMEOUT)
        out["banner"] = banner
        _send(sock, f"EHLO {EHLO_IDENTITY}")
        while True:
            line = read_line(sock, SMTP_BANNER_TIMEOUT)
            if not line:
                break
            out["ehlo_lines"].append(line)
            code = line[:3] if len(line) >= 3 else ""
            if code != "250":
                if line[3:4] == "-":
                    continue
                break
            rest = line[4:].strip().upper()
            if rest.startswith("AUTH "):
                out["auth_mechanisms"] = [x.strip() for x in rest[5:].split()]
            if "STARTTLS" in rest:
                out["starttls_supported"] = True
            if "VRFY" in rest:
                out["vrfy_supported"] = True
            if "EXPN" in rest:
                out["expn_supported"] = True
            if line[3:4] != "-":
                break
        out["help_response"] = _collect_help(sock)
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except (OSError, ssl.SSLError) as e:
        out["error"] = f"network_or_ssl:{e}"
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _probe_port_smtps(host: str, port: int = SMTP_PORT_SMTPS) -> dict:
    """Probe SMTPS (implicit TLS) on port 465; return open, banner, error."""
    out = {"open": False, "banner": None, "error": None}
    sock = safe_socket_connect(host, port, SMTP_BANNER_TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        ssl_ctx = ssl.create_default_context()
        tls_sock = ssl_ctx.wrap_socket(sock, server_hostname=host)
        banner = read_line(tls_sock, SMTP_BANNER_TIMEOUT)
        out["open"] = True
        out["banner"] = banner
        tls_sock.close()
    except ssl.SSLError as e:
        out["error"] = f"ssl_error:{e}"
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except OSError as e:
        out["error"] = f"network_error:{e}"
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _probe_port_submission(host: str, port: int = SMTP_PORT_SUBMISSION) -> dict:
    """Probe submission port 587; banner + EHLO (no STARTTLS)."""
    out = {"open": False, "banner": None, "ehlo_lines": [], "error": None}
    sock = safe_socket_connect(host, port, SMTP_BANNER_TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        banner = read_line(sock, SMTP_BANNER_TIMEOUT)
        out["open"] = True
        out["banner"] = banner
        _send(sock, f"EHLO {EHLO_IDENTITY}")
        while True:
            line = read_line(sock, SMTP_BANNER_TIMEOUT)
            if not line:
                break
            out["ehlo_lines"].append(line)
            if len(line) >= 3 and line[3:4] != "-" and line[:3] == "250":
                break
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except OSError as e:
        out["error"] = f"network_error:{e}"
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def run(ctx: ScanContext) -> None:
    domain = ctx.target_domain
    mx_host = get_smtp_host(ctx)
    result = _collect_banner_and_ehlo(mx_host, SMTP_PORT)
    result["platform_hint"] = platform_hint_from_banner(result.get("banner") or "")
    result["mx_host_used"] = mx_host
    result["port_465"] = _probe_port_smtps(mx_host, SMTP_PORT_SMTPS)
    result["port_587"] = _probe_port_submission(mx_host, SMTP_PORT_SUBMISSION)
    ctx.add_smtp_data("smtp_enum", result)
    from smtp import gateway_detection
    gateway_detection.run(ctx)
    if ctx.verbose:
        logger.debug("SMTP banner: %s", result.get("banner"))
        logger.debug("AUTH: %s | STARTTLS: %s", result.get("auth_mechanisms"), result.get("starttls_supported"))
        logger.debug("Port 465: %s | Port 587: %s", result.get("port_465", {}).get("open"), result.get("port_587", {}).get("open"))
