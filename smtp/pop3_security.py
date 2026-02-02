"""
POP3 / POP3S security analysis. SAFE: banner, plain-text, STARTTLS, AUTH. ATTACK: controlled auth probe (3-5 attempts).
"""
import logging
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_pop3_host
from core.attack_mode import require_attack_mode, enforce_rate_limit, MAX_AUTH_ATTEMPTS

logger = logging.getLogger("mailt.mail")

POP3_PORT = 110
POP3S_PORT = 995
TIMEOUT = 10.0
DUMMY_USER = "mailt-dummy"
DUMMY_PASS = "mailt-dummy-not-real"


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _probe_pop3_plain(host: str, port: int = POP3_PORT) -> dict:
    out = {"open": False, "banner": None, "capa": [], "stls": False, "error": None}
    sock = safe_socket_connect(host, port, TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        banner = read_line(sock, TIMEOUT)
        out["open"] = banner and banner.startswith("+OK")
        out["banner"] = banner
        if out["open"]:
            _send(sock, "CAPA")
            while True:
                line = read_line(sock, TIMEOUT)
                if not line or line == ".":
                    break
                if line.startswith("+") or line.startswith("-"):
                    continue
                out["capa"].append(line.strip().upper())
                if "STLS" in line.upper():
                    out["stls"] = True
        sock.close()
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _probe_pop3s(host: str, port: int = POP3S_PORT) -> dict:
    out = {"open": False, "banner": None, "error": None}
    sock = safe_socket_connect(host, port, TIMEOUT)
    if not sock:
        out["error"] = "connection_failed"
        return out
    try:
        ctx = ssl.create_default_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        banner = read_line(tls_sock, TIMEOUT)
        out["open"] = banner and banner.startswith("+OK")
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


def _attack_auth_probe(host: str, port: int, attempts: int = min(MAX_AUTH_ATTEMPTS, 5)) -> dict:
    """ATTACK MODE: 3-5 USER/PASS with dummy; check response differences (enum), rate limit."""
    out = {"attempts": 0, "responses": [], "rate_limit_detected": False, "user_enum_hint": False}
    for i in range(attempts):
        sock = safe_socket_connect(host, port, TIMEOUT)
        if not sock:
            break
        try:
            read_line(sock, TIMEOUT)
            _send(sock, f"USER {DUMMY_USER}")
            r1 = read_line(sock, TIMEOUT)
            _send(sock, f"PASS {DUMMY_PASS}")
            r2 = read_line(sock, TIMEOUT)
            out["responses"].append({"attempt": i + 1, "user_resp": r1[:80] if r1 else None, "pass_resp": r2[:80] if r2 else None})
            out["attempts"] = i + 1
            if r2 and ("lock" in (r2 or "").lower() or "too many" in (r2 or "").lower() or "blocked" in (r2 or "").lower()):
                out["rate_limit_detected"] = True
            sock.close()
        except Exception:
            break
        finally:
            try:
                sock.close()
            except OSError:
                pass
        enforce_rate_limit("pop3_security")
    # User enum hint: different -ERR for USER vs PASS (e.g. "unknown user" vs "invalid password")
    if len(out["responses"]) >= 2:
        first = out["responses"][0].get("user_resp") or ""
        if "-ERR" in first and "invalid" not in first.lower() and "pass" not in first.lower():
            out["user_enum_hint"] = True
    return out


def run(ctx: ScanContext) -> None:
    pop3_host = get_pop3_host(ctx)
    result = {
        "pop3_110": _probe_pop3_plain(pop3_host, POP3_PORT),
        "pop3s_995": _probe_pop3s(pop3_host, POP3S_PORT),
        "attack_probe": None,
    }
    if require_attack_mode(ctx):
        enforce_rate_limit("pop3_security")
        if result["pop3_110"].get("open"):
            result["attack_probe"] = _attack_auth_probe(pop3_host, POP3_PORT)
            ctx.log_exploit_audit("pop3_security", "auth_probe", "completed", {"attempts": result["attack_probe"].get("attempts")})
    ctx.add_smtp_data("pop3_security", result)
    if ctx.verbose:
        logger.debug("POP3: 110 open=%s 995 open=%s", result["pop3_110"].get("open"), result["pop3s_995"].get("open"))
