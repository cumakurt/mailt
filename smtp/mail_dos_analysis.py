"""
DoS & resource exhaustion analysis. SAFE: IDLE/NOOP limits, connection threshold. ATTACK: very low frequency, slow-style test.
Service impact minimal; threshold measurement only.
"""
import logging
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.attack_mode import require_attack_mode, enforce_rate_limit
from core.constants import SMTP_PORT, IMAP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.mail")

# Slightly shorter for NOOP/IDLE probes
PROBE_TIMEOUT = 6.0


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def run(ctx: ScanContext) -> None:
    mx_host = get_smtp_host(ctx)
    result = {"smtp_noop": None, "imap_idle_hint": None, "attack_probe": None}

    # SAFE: SMTP NOOP
    sock = safe_socket_connect(mx_host, SMTP_PORT, PROBE_TIMEOUT)
    if sock:
        try:
            read_line(sock, PROBE_TIMEOUT)
            _send(sock, f"EHLO {EHLO_IDENTITY}")
            while True:
                line = read_line(sock, PROBE_TIMEOUT)
                if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                    break
            _send(sock, "NOOP")
            r = read_line(sock, PROBE_TIMEOUT)
            result["smtp_noop"] = {"supported": bool(r and r.startswith("250")), "response": (r or "")[:80]}
            sock.close()
        except Exception as e:
            result["smtp_noop"] = {"error": str(e)}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # SAFE: IMAP IDLE capability (already in imap_security; we just note)
    imap = ctx.smtp_data.get("imap_security", {})
    result["imap_idle_hint"] = imap.get("imap_143", {}).get("idle", False)

    if require_attack_mode(ctx):
        enforce_rate_limit("mail_dos_analysis")
        # One very slow connection: connect, wait 2s, send one command, disconnect. No flood.
        sock = safe_socket_connect(mx_host, SMTP_PORT, timeout=4.0)
        if sock:
            import time
            time.sleep(2.0)
            try:
                read_line(sock, 2.0)
                _send(sock, "NOOP")
                r = read_line(sock, 2.0)
                result["attack_probe"] = {"slow_connect_ok": bool(r), "response": (r or "")[:40]}
            except Exception as e:
                result["attack_probe"] = {"error": str(e)}
            finally:
                try:
                    sock.close()
                except OSError:
                    pass
        ctx.log_exploit_audit("mail_dos_analysis", "slow_probe", "completed", {})

    ctx.add_smtp_data("mail_dos_analysis", result)
    if ctx.verbose:
        logger.debug("Mail DoS analysis: smtp_noop=%s", result.get("smtp_noop"))
