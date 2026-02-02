"""
Catch-all domain check: RCPT TO with non-existent local part.
If server accepts (250), domain may be catch-all (accepts any address).
Anonymous only; no mail sent.
"""
import logging
import random
import string
import socket
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.constants import SMTP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp")


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _check_catch_all(host: str, domain: str, port: int = SMTP_PORT) -> dict:
    """
    Send MAIL FROM and RCPT TO:<randomstring@domain>. 250 on RCPT TO suggests catch-all.
    """
    local = "".join(random.choices(string.ascii_lowercase + string.digits, k=16)) + "-catchall-test"
    addr = f"{local}@{domain}"
    out = {"catch_all_likely": False, "rcpt_code": None, "rcpt_message": None, "test_address": addr, "error": None}
    sock = safe_socket_connect(host, port, SMTP_TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        read_line(sock, SMTP_TIMEOUT)
        _send(sock, f"EHLO {EHLO_IDENTITY}")
        while True:
            line = read_line(sock, SMTP_TIMEOUT)
            if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                break
        _send(sock, "MAIL FROM:<test@external.invalid>")
        line = read_line(sock, SMTP_TIMEOUT)
        if not line or not line.startswith("250"):
            out["error"] = "mail_from_rejected"
            return out
        _send(sock, f"RCPT TO:<{addr}>")
        line = read_line(sock, SMTP_TIMEOUT)
        out["rcpt_code"] = line[:3] if line else None
        out["rcpt_message"] = (line or "").strip()
        if line and line.startswith("250"):
            out["catch_all_likely"] = True
        _send(sock, "QUIT")
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
    mx_host = get_smtp_host(ctx)
    result = _check_catch_all(mx_host, ctx.target_domain, SMTP_PORT)
    ctx.add_smtp_data("catch_all_check", result)
    if ctx.verbose:
        logger.debug("Catch-all check: likely=%s code=%s", result.get("catch_all_likely"), result.get("rcpt_code"))
