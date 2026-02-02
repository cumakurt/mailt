"""
Open relay misconfiguration check (anonymous only).
We only check if server responds to RCPT TO for external domain without AUTH.
We do NOT attempt to send mail or abuse; we only probe response codes.
"""
import logging
import socket
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.constants import SMTP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp")


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _probe_relay(host: str, from_domain: str, external_rcpt: str, port: int = SMTP_PORT) -> dict:
    """
    MAIL FROM and RCPT TO only; no DATA or actual send.
    relay_likely = True if server accepts RCPT TO external without AUTH.
    """
    out = {"relay_likely": False, "mail_from_code": None, "rcpt_to_code": None, "error": None}
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
        _send(sock, f"MAIL FROM:<test@{from_domain}>")
        line = read_line(sock, SMTP_TIMEOUT)
        out["mail_from_code"] = line[:3] if line else None
        if line and not line.startswith("250"):
            return out
        _send(sock, f"RCPT TO:<test@{external_rcpt}>")
        line = read_line(sock, SMTP_TIMEOUT)
        out["rcpt_to_code"] = line[:3] if line else None
        if line and line.startswith("250"):
            out["relay_likely"] = True
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


def _probe_null_sender_relay(host: str, external_rcpt: str, port: int = SMTP_PORT) -> dict:
    """Probe open relay with null sender MAIL FROM:<>; external RCPT TO."""
    out = {"null_sender_relay_likely": False, "mail_from_code": None, "rcpt_to_code": None, "error": None}
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
        _send(sock, "MAIL FROM:<>")
        line = read_line(sock, SMTP_TIMEOUT)
        out["mail_from_code"] = line[:3] if line else None
        if line and not line.startswith("250"):
            return out
        _send(sock, f"RCPT TO:<test@{external_rcpt}>")
        line = read_line(sock, SMTP_TIMEOUT)
        out["rcpt_to_code"] = line[:3] if line else None
        if line and line.startswith("250"):
            out["null_sender_relay_likely"] = True
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
    external = "external-relay-test.invalid"
    result = _probe_relay(mx_host, ctx.target_domain, external, SMTP_PORT)
    null_result = _probe_null_sender_relay(mx_host, external, SMTP_PORT)
    result["null_sender_relay_likely"] = null_result.get("null_sender_relay_likely", False)
    result["null_sender_mail_from_code"] = null_result.get("mail_from_code")
    result["null_sender_rcpt_to_code"] = null_result.get("rcpt_to_code")
    ctx.add_smtp_data("open_relay", result)
    if ctx.verbose:
        logger.debug(
            "Open relay: relay_likely=%s null_sender_relay=%s",
            result.get("relay_likely"),
            result.get("null_sender_relay_likely"),
        )
