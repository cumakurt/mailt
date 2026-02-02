"""
IMAP / IMAPS security analysis. SAFE: CAPABILITY, STARTTLS, IDLE. ATTACK: LOGIN response, rate limit, LIST (read-only).
No mail content reading; no data exfiltration.
"""
import logging
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_imap_host
from core.attack_mode import require_attack_mode, enforce_rate_limit, MAX_AUTH_ATTEMPTS

logger = logging.getLogger("mailt.mail")

IMAP_PORT = 143
IMAPS_PORT = 993
TIMEOUT = 10.0
DUMMY_USER = "mailt-dummy"
DUMMY_PASS = "mailt-dummy-not-real"


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _probe_imap_plain(host: str, port: int = IMAP_PORT) -> dict:
    out = {"open": False, "banner": None, "capability": [], "starttls": False, "idle": False, "error": None}
    sock = safe_socket_connect(host, port, TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        banner = read_line(sock, TIMEOUT)
        out["open"] = banner and "* OK" in banner
        out["banner"] = banner
        if out["open"]:
            _send(sock, "a001 CAPABILITY")
            while True:
                line = read_line(sock, TIMEOUT)
                if not line:
                    break
                out["capability"].append(line)
                if "CAPABILITY" in line.upper():
                    cap = line.upper()
                    if "STARTTLS" in cap:
                        out["starttls"] = True
                    if "IDLE" in cap:
                        out["idle"] = True
                if line.startswith("a001 ") and ("OK" in line or "BAD" in line):
                    break
        sock.close()
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _probe_imaps(host: str, port: int = IMAPS_PORT) -> dict:
    out = {"open": False, "banner": None, "error": None}
    sock = safe_socket_connect(host, port, TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        banner = read_line(tls_sock, TIMEOUT)
        out["open"] = banner and "* OK" in banner
        out["banner"] = banner
        tls_sock.close()
    except ssl.SSLError as e:
        out["error"] = f"ssl_error:{e}"
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _attack_login_probe(host: str, port: int, attempts: int = min(MAX_AUTH_ATTEMPTS, 5)) -> dict:
    """ATTACK MODE: LOGIN with dummy; response differences, rate limit. Optional LIST (read-only, no content)."""
    out = {"attempts": 0, "responses": [], "rate_limit_detected": False, "list_folders": False}
    for i in range(attempts):
        sock = safe_socket_connect(host, port, TIMEOUT)
        if not sock:
            break
        try:
            read_line(sock, TIMEOUT)
            tag = f"a{i:03d}"
            _send(sock, f"{tag} LOGIN {DUMMY_USER} {DUMMY_PASS}")
            while True:
                line = read_line(sock, TIMEOUT)
                if not line:
                    break
                out["responses"].append({"attempt": i + 1, "line": line[:100]})
                if line.startswith(tag.upper()) or line.startswith(tag):
                    if "NO" in line or "BAD" in line:
                        if "rate" in line.lower() or "lock" in line.lower() or "try again" in line.lower():
                            out["rate_limit_detected"] = True
                    break
            sock.close()
        except Exception:
            break
        finally:
            try:
                sock.close()
            except OSError:
                pass
        enforce_rate_limit("imap_security")
    return out


def run(ctx: ScanContext) -> None:
    imap_host = get_imap_host(ctx)
    result = {
        "imap_143": _probe_imap_plain(imap_host, IMAP_PORT),
        "imaps_993": _probe_imaps(imap_host, IMAPS_PORT),
        "attack_probe": None,
    }
    if require_attack_mode(ctx):
        enforce_rate_limit("imap_security")
        if result["imap_143"].get("open"):
            result["attack_probe"] = _attack_login_probe(imap_host, IMAP_PORT)
            ctx.log_exploit_audit("imap_security", "login_probe", "completed", {"attempts": result["attack_probe"].get("attempts")})
    ctx.add_smtp_data("imap_security", result)
    if ctx.verbose:
        logger.debug("IMAP: 143 open=%s 993 open=%s", result["imap_143"].get("open"), result["imaps_993"].get("open"))
