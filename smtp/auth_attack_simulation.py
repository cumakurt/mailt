"""
SMTP AUTH brute-force simulation — ATTACK MODE only.
Tests if rate limit or lockout exists: 3–5 attempts with dummy credentials only.
No real account compromise; no real credentials.
"""
import logging
import base64
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.attack_mode import require_attack_mode, enforce_rate_limit, MAX_AUTH_ATTEMPTS
from core.constants import SMTP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp.exploit")

DUMMY_USER = "mailt-dummy-user"
DUMMY_PASS = "mailt-dummy-pass-not-real"


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def run(ctx: ScanContext) -> None:
    if not require_attack_mode(ctx):
        return
    enforce_rate_limit("auth_attack_simulation")
    mx_host = get_smtp_host(ctx)
    enum_data = ctx.smtp_data.get("smtp_enum", {})
    if not enum_data.get("auth_mechanisms"):
        ctx.add_smtp_data("auth_attack_simulation", {"exploit_attempted": True, "skipped": True, "reason": "no_auth_advertised"})
        return

    result = {
        "exploit_attempted": True,
        "attempts": 0,
        "rate_limit_detected": False,
        "lockout_detected": False,
        "responses": [],
        "error": None,
    }
    attempts = min(MAX_AUTH_ATTEMPTS, 5)
    for i in range(attempts):
        sock = safe_socket_connect(mx_host, SMTP_PORT, SMTP_TIMEOUT)
        if not sock:
            result["error"] = "connection_failed"
            break
        try:
            read_line(sock, SMTP_TIMEOUT)
            _send(sock, f"EHLO {EHLO_IDENTITY}")
            while True:
                line = read_line(sock, SMTP_TIMEOUT)
                if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                    break
            cred = base64.b64encode(f"\x00{DUMMY_USER}\x00{DUMMY_PASS}".encode("utf-8")).decode("ascii")
            _send(sock, f"AUTH PLAIN {cred}")
            line = read_line(sock, SMTP_TIMEOUT)
            code = line[:3] if line else None
            result["responses"].append({"attempt": i + 1, "code": code, "message": (line or "")[:80]})
            result["attempts"] = i + 1
            if line and ("too many" in line.lower() or "rate" in line.lower() or "try again" in line.lower() or "blocked" in line.lower()):
                result["rate_limit_detected"] = True
            if line and ("lock" in line.lower() or "disabled" in line.lower() or "535" in line):
                result["lockout_detected"] = True
            _send(sock, "QUIT")
        except Exception as e:
            result["error"] = str(e)
            break
        finally:
            try:
                sock.close()
            except OSError:
                pass
        enforce_rate_limit("auth_attack_simulation")
    ctx.add_smtp_data("auth_attack_simulation", result)
    ctx.log_exploit_audit("auth_attack_simulation", "auth_simulation", "completed", {"attempts": result["attempts"], "rate_limit": result["rate_limit_detected"]})
    if ctx.verbose:
        logger.debug("Auth simulation: attempts=%s rate_limit=%s", result["attempts"], result["rate_limit_detected"])
