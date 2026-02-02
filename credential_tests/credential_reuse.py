"""
Credential reuse: same email/password tested on SMTP AUTH, POP3, IMAP.
Maps which protocols accept the test credential (single credential -> multiple attack surfaces).
No mail content read; no data exfiltration.
"""
import base64
import logging
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host, get_pop3_host, get_imap_host
from core.constants import SMTP_PORT, SMTP_PORT_SUBMISSION, SMTP_TIMEOUT, POP3_PORT, POP3S_PORT, IMAP_PORT, IMAPS_PORT, EHLO_IDENTITY

logger = logging.getLogger("mailt.credential_tests")

TIMEOUT = 12.0


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _smtp_auth_login(host: str, port: int, email: str, password: str, use_starttls: bool) -> dict:
    """Try SMTP AUTH (AUTH PLAIN). use_starttls: do STARTTLS before AUTH on port 25."""
    out = {"success": False, "response_code": None, "error": None}
    sock = safe_socket_connect(host, port, TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        read_line(sock, TIMEOUT)
        _send(sock, f"EHLO {EHLO_IDENTITY}")
        while True:
            line = read_line(sock, TIMEOUT)
            if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                break
        if use_starttls:
            _send(sock, "STARTTLS")
            line = read_line(sock, TIMEOUT)
            if not line or not line.startswith("220"):
                out["error"] = "starttls_failed"
                return out
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            _send(sock, f"EHLO {EHLO_IDENTITY}")
            while True:
                line = read_line(sock, TIMEOUT)
                if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                    break
        plain = base64.b64encode(f"\x00{email}\x00{password}".encode("utf-8")).decode("ascii")
        _send(sock, f"AUTH PLAIN {plain}")
        line = read_line(sock, TIMEOUT)
        out["response_code"] = line[:3] if line else None
        out["success"] = line and line.startswith("235")
        if not out["success"] and line:
            out["error"] = (line or "").strip()[:200]
        _send(sock, "QUIT")
    except ssl.SSLError as e:
        out["error"] = f"ssl_error:{e}"
    except Exception as e:
        out["error"] = str(e)[:200]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _pop3_login(host: str, port: int, email: str, password: str, use_tls: bool) -> dict:
    """Try POP3 USER/PASS. use_tls: connect with TLS (995)."""
    out = {"success": False, "error": None}
    sock = safe_socket_connect(host, port, TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        banner = read_line(sock, TIMEOUT)
        if not banner or not banner.startswith("+OK"):
            out["error"] = banner or "no_banner"
            return out
        _send(sock, f"USER {email}")
        r1 = read_line(sock, TIMEOUT)
        if r1 and not r1.startswith("+OK"):
            out["error"] = (r1 or "").strip()[:200]
            return out
        _send(sock, f"PASS {password}")
        r2 = read_line(sock, TIMEOUT)
        out["success"] = r2 and r2.startswith("+OK")
        if not out["success"] and r2:
            out["error"] = (r2 or "").strip()[:200]
        _send(sock, "QUIT")
    except ssl.SSLError as e:
        out["error"] = f"ssl_error:{e}"
    except Exception as e:
        out["error"] = str(e)[:200]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _imap_login(host: str, port: int, email: str, password: str, use_tls: bool) -> dict:
    """Try IMAP LOGIN. use_tls: connect with TLS (993)."""
    out = {"success": False, "error": None}
    sock = safe_socket_connect(host, port, TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        read_line(sock, TIMEOUT)
        _send(sock, f'a001 LOGIN "{email}" "{password}"')
        while True:
            line = read_line(sock, TIMEOUT)
            if not line:
                break
            if "a001 OK" in line or "a001 " in line and "OK" in line:
                out["success"] = "OK" in line and "BAD" not in line and "NO" not in line
                break
            if "a001 NO" in line or "a001 BAD" in line:
                out["error"] = (line or "").strip()[:200]
                break
        _send(sock, "a002 LOGOUT")
    except ssl.SSLError as e:
        out["error"] = f"ssl_error:{e}"
    except Exception as e:
        out["error"] = str(e)[:200]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def run(ctx: ScanContext) -> None:
    if not getattr(ctx, "credential_aware", False) or not getattr(ctx, "test_email", None) or not getattr(ctx, "test_password", None):
        return
    email = (ctx.test_email or "").strip()
    password = ctx.test_password or ""
    if not email:
        return

    smtp_host = get_smtp_host(ctx)
    pop3_host = get_pop3_host(ctx)
    imap_host = get_imap_host(ctx)

    result = {
        "smtp_auth_25_starttls": False,
        "smtp_auth_587": False,
        "pop3_110": False,
        "pop3s_995": False,
        "imap_143": False,
        "imaps_993": False,
        "protocols_accepting_credential": [],
        "detail": {},
    }

    # SMTP AUTH on submission 587 (typically STARTTLS)
    r587 = _smtp_auth_login(smtp_host, SMTP_PORT_SUBMISSION, email, password, use_starttls=True)
    result["smtp_auth_587"] = r587.get("success", False)
    result["detail"]["smtp_587"] = r587

    # SMTP AUTH on port 25 with STARTTLS
    r25 = _smtp_auth_login(smtp_host, SMTP_PORT, email, password, use_starttls=True)
    result["smtp_auth_25_starttls"] = r25.get("success", False)
    result["detail"]["smtp_25"] = r25

    # POP3 plain 110
    r110 = _pop3_login(pop3_host, POP3_PORT, email, password, use_tls=False)
    result["pop3_110"] = r110.get("success", False)
    result["detail"]["pop3_110"] = r110

    # POP3S 995
    r995 = _pop3_login(pop3_host, POP3S_PORT, email, password, use_tls=True)
    result["pop3s_995"] = r995.get("success", False)
    result["detail"]["pop3s_995"] = r995

    # IMAP 143
    r143 = _imap_login(imap_host, IMAP_PORT, email, password, use_tls=False)
    result["imap_143"] = r143.get("success", False)
    result["detail"]["imap_143"] = r143

    # IMAPS 993
    r993 = _imap_login(imap_host, IMAPS_PORT, email, password, use_tls=True)
    result["imaps_993"] = r993.get("success", False)
    result["detail"]["imaps_993"] = r993

    for name, ok in [
        ("SMTP AUTH (587)", result["smtp_auth_587"]),
        ("SMTP AUTH (25+STARTTLS)", result["smtp_auth_25_starttls"]),
        ("POP3 (110)", result["pop3_110"]),
        ("POP3S (995)", result["pop3s_995"]),
        ("IMAP (143)", result["imap_143"]),
        ("IMAPS (993)", result["imaps_993"]),
    ]:
        if ok:
            result["protocols_accepting_credential"].append(name)

    ctx.add_smtp_data("credential_reuse", result)
    if ctx.verbose:
        logger.debug(
            "Credential reuse: protocols=%s",
            result["protocols_accepting_credential"],
        )
