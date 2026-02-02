"""
Cross-protocol credential reuse test. ATTACK MODE only.
Same dummy credential on SMTP AUTH, POP3, IMAP; compare lockout/response across protocols.
"""
import logging
from core.context import ScanContext
from core.attack_mode import require_attack_mode, enforce_rate_limit
from core.utils import safe_socket_connect, read_line, get_smtp_host, get_pop3_host, get_imap_host
from core.constants import SMTP_PORT, POP3_PORT, IMAP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.mail")

DUMMY_USER = "mailt-cross-dummy"
DUMMY_PASS = "mailt-cross-dummy-not-real"


def _send_smtp(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def run(ctx: ScanContext) -> None:
    if not require_attack_mode(ctx):
        return
    enforce_rate_limit("cross_protocol_attack")
    smtp_host = get_smtp_host(ctx)
    pop3_host = get_pop3_host(ctx)
    imap_host = get_imap_host(ctx)
    result = {"smtp_auth": None, "pop3": None, "imap": None, "lockout_inconsistent": False, "credential_reuse_risk": False}

    # SMTP AUTH (one attempt)
    sock = safe_socket_connect(smtp_host, SMTP_PORT, SMTP_TIMEOUT)
    if sock:
        try:
            read_line(sock, SMTP_TIMEOUT)
            _send_smtp(sock, f"EHLO {EHLO_IDENTITY}")
            while True:
                line = read_line(sock, SMTP_TIMEOUT)
                if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                    break
            import base64
            cred = base64.b64encode(f"\x00{DUMMY_USER}\x00{DUMMY_PASS}".encode()).decode()
            _send_smtp(sock, f"AUTH PLAIN {cred}")
            r = read_line(sock, SMTP_TIMEOUT)
            result["smtp_auth"] = {"code": r[:3] if r else None, "message": (r or "")[:80]}
            sock.close()
        except Exception as e:
            result["smtp_auth"] = {"error": str(e)}
        finally:
            try:
                sock.close()
            except OSError:
                pass
    enforce_rate_limit("cross_protocol_attack")

    # POP3 (one attempt)
    sock = safe_socket_connect(pop3_host, POP3_PORT, SMTP_TIMEOUT)
    if sock:
        try:
            read_line(sock, SMTP_TIMEOUT)
            sock.sendall(f"USER {DUMMY_USER}\r\n".encode())
            r1 = read_line(sock, SMTP_TIMEOUT)
            sock.sendall(f"PASS {DUMMY_PASS}\r\n".encode())
            r2 = read_line(sock, SMTP_TIMEOUT)
            result["pop3"] = {"user_resp": (r1 or "")[:80], "pass_resp": (r2 or "")[:80]}
            sock.close()
        except Exception as e:
            result["pop3"] = {"error": str(e)}
        finally:
            try:
                sock.close()
            except OSError:
                pass
    enforce_rate_limit("cross_protocol_attack")

    # IMAP (one attempt)
    sock = safe_socket_connect(imap_host, IMAP_PORT, SMTP_TIMEOUT)
    if sock:
        try:
            read_line(sock, SMTP_TIMEOUT)
            sock.sendall(f"a001 LOGIN {DUMMY_USER} {DUMMY_PASS}\r\n".encode())
            r = read_line(sock, SMTP_TIMEOUT)
            result["imap"] = {"response": (r or "")[:80]}
            sock.close()
        except Exception as e:
            result["imap"] = {"error": str(e)}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # Inconsistent lockout: one protocol locks, another does not (after same dummy attempts)
    smtp_msg = (result.get("smtp_auth") or {}).get("message") or ""
    pop3_msg = (result.get("pop3") or {}).get("pass_resp") or ""
    imap_msg = (result.get("imap") or {}).get("response") or ""
    lock_smtp = "lock" in smtp_msg.lower() or "blocked" in smtp_msg.lower()
    lock_pop3 = "lock" in pop3_msg.lower() or "blocked" in pop3_msg.lower()
    lock_imap = "lock" in imap_msg.lower() or "blocked" in imap_msg.lower()
    if (lock_smtp, lock_pop3, lock_imap).count(True) in (1, 2):
        result["lockout_inconsistent"] = True
    result["credential_reuse_risk"] = True  # Same cred surface across protocols
    ctx.add_smtp_data("cross_protocol_attack", result)
    ctx.log_exploit_audit("cross_protocol_attack", "cross_probe", "completed", {"lockout_inconsistent": result["lockout_inconsistent"]})
    if ctx.verbose:
        logger.debug("Cross-protocol: lockout_inconsistent=%s", result["lockout_inconsistent"])
