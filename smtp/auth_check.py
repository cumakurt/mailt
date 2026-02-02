"""
SMTP AUTH check: whether server accepts AUTH command before STARTTLS.
If AUTH is accepted on plain connection, credentials could be sent in cleartext.
Anonymous only; we only send AUTH PLAIN with dummy data and observe response.
"""
import base64
import logging
import socket
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.constants import SMTP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp")


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _check_auth_without_starttls(host: str, port: int = SMTP_PORT) -> dict:
    """
    Connect, EHLO (do not send STARTTLS), then AUTH PLAIN with dummy.
    If server returns 334 (continue) or 235 (success), it accepts AUTH on plain connection.
    """
    out = {"auth_accepts_without_starttls": False, "auth_response_code": None, "auth_response": None, "error": None}
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
        # Dummy AUTH PLAIN: base64(\0user\0pass) - we do not send real credentials
        dummy = base64.b64encode(b"\x00mailt-test\x00dummy").decode("ascii")
        _send(sock, f"AUTH PLAIN {dummy}")
        line = read_line(sock, SMTP_TIMEOUT)
        out["auth_response"] = (line or "").strip()
        out["auth_response_code"] = line[:3] if line else None
        if line and (line.startswith("334") or line.startswith("235")):
            out["auth_accepts_without_starttls"] = True
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
    result = _check_auth_without_starttls(mx_host, SMTP_PORT)
    ctx.add_smtp_data("auth_check", result)
    if ctx.verbose:
        logger.debug(
            "AUTH without STARTTLS: accepts=%s code=%s",
            result.get("auth_accepts_without_starttls"),
            result.get("auth_response_code"),
        )
