"""
TLS version, cipher suite and certificate analysis after STARTTLS.
"""
import logging
import socket
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.constants import SMTP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp")

# Weak ciphers / protocols we flag
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _cert_dict(cert: dict | None) -> dict:
    if not cert:
        return {}
    out = {}
    for key in ("subject", "issuer"):
        items = cert.get(key, [])
        d = {}
        for part in (items if isinstance(items, (list, tuple)) else []):
            if isinstance(part, (list, tuple)) and len(part) >= 1:
                t = part[0] if isinstance(part[0], (list, tuple)) else part
                if isinstance(t, (list, tuple)) and len(t) >= 2:
                    d[str(t[0])] = t[1]
        out[key] = d
    for key in ("notBefore", "notAfter"):
        val = cert.get(key)
        if val:
            out[key] = val
    return out


def _get_tls_info(host: str, port: int = SMTP_PORT) -> dict:
    out = {
        "protocol": None,
        "cipher": None,
        "weak_protocol": False,
        "weak_cipher_hint": False,
        "certificate": None,
    }
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
            out["error"] = "no_starttls"
            return out
        ssl_ctx = ssl.create_default_context()
        tls_sock = ssl_ctx.wrap_socket(sock, server_hostname=host)
        out["protocol"] = tls_sock.version()
        out["cipher"] = tls_sock.cipher()
        if out["protocol"] in WEAK_PROTOCOLS:
            out["weak_protocol"] = True
        if out["cipher"]:
            name = out["cipher"][0].upper() if isinstance(out["cipher"], (list, tuple)) else str(out["cipher"]).upper()
            if "NULL" in name or "EXP" in name or "DES" in name or "RC4" in name:
                out["weak_cipher_hint"] = True
        cert = tls_sock.getpeercert()
        if cert:
            out["certificate"] = _cert_dict(cert)
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
    result = _get_tls_info(mx_host, SMTP_PORT)
    ctx.add_smtp_data("tls_analysis", result)
    if ctx.verbose:
        logger.debug("TLS: %s | cipher: %s | weak: %s", result.get("protocol"), result.get("cipher"), result.get("weak_protocol"))
