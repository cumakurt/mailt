"""
TLS / STARTTLS credential risk: check if plain authentication is accepted without encryption.
When credential_aware, try AUTH PLAIN on plain connection (no STARTTLS).
If accepted, credentials could be sent in cleartext on the network.
No sniffing/MITM; only protocol response check.
"""
import base64
import logging
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.constants import SMTP_PORT, EHLO_IDENTITY

logger = logging.getLogger("mailt.credential_tests")

TIMEOUT = 12.0


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def run(ctx: ScanContext) -> None:
    if not getattr(ctx, "credential_aware", False) or not getattr(ctx, "test_email", None) or not getattr(ctx, "test_password", None):
        return
    email = (ctx.test_email or "").strip()
    password = ctx.test_password or ""
    if not email:
        return

    host = get_smtp_host(ctx)
    result = {
        "plain_auth_accepted": False,
        "response_code": None,
        "response_preview": None,
        "error": None,
    }
    sock = safe_socket_connect(host, SMTP_PORT, TIMEOUT)
    if not sock:
        result["error"] = "connection_failed"
        ctx.add_smtp_data("credential_tls_risk", result)
        return
    try:
        read_line(sock, TIMEOUT)
        _send(sock, f"EHLO {EHLO_IDENTITY}")
        while True:
            line = read_line(sock, TIMEOUT)
            if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                break
        # Do NOT send STARTTLS; try AUTH PLAIN on plain connection
        plain = base64.b64encode(f"\x00{email}\x00{password}".encode("utf-8")).decode("ascii")
        _send(sock, f"AUTH PLAIN {plain}")
        line = read_line(sock, TIMEOUT)
        result["response_code"] = line[:3] if line else None
        result["response_preview"] = (line or "").strip()[:100] if line else None
        result["plain_auth_accepted"] = line and line.startswith("235")
        _send(sock, "QUIT")
    except Exception as e:
        result["error"] = str(e)[:200]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    ctx.add_smtp_data("credential_tls_risk", result)
    if ctx.verbose:
        logger.debug(
            "TLS credential risk: plain_auth_accepted=%s",
            result["plain_auth_accepted"],
        )
