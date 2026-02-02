"""
STARTTLS support check: upgrade and verify TLS after EHLO.
"""
import logging
import socket
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.constants import SMTP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp")


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _check_starttls(host: str, port: int = SMTP_PORT) -> dict:
    out = {"supported": False, "error": None, "version_after_upgrade": None}
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
        _send(sock, "STARTTLS")
        line = read_line(sock, SMTP_TIMEOUT)
        if not line or not line.startswith("220"):
            out["error"] = "starttls_rejected"
            return out
        out["supported"] = True
        ssl_ctx = ssl.create_default_context()
        tls_sock = ssl_ctx.wrap_socket(sock, server_hostname=host)
        out["version_after_upgrade"] = tls_sock.version()
        tls_sock.close()
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except ssl.SSLError as e:
        out["error"] = f"ssl_error:{e}"
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
    result = _check_starttls(mx_host, SMTP_PORT)
    ctx.add_smtp_data("starttls", result)
    if ctx.verbose:
        logger.debug("STARTTLS: supported=%s version=%s", result.get("supported"), result.get("version_after_upgrade"))
