"""
Advanced open relay tests: backup MX, internal-domain trust, IP trust hints, pipelining.
Anonymous only; no mail sent. Evidence-based to avoid false positives.
"""
import logging
import re
import socket
from core.context import ScanContext
from core.utils import (
    safe_socket_connect,
    read_line,
    get_smtp_host,
    get_mx_hosts_sorted,
)
from core.constants import SMTP_PORT, SMTP_TIMEOUT, EHLO_IDENTITY

logger = logging.getLogger("mailt.smtp")

EXTERNAL_RCPT = "external-relay-test.invalid"

# Banner/response phrases that may indicate IP-based trust (informational only)
IP_TRUST_PATTERNS = [
    re.compile(r"trusted\s+network", re.I),
    re.compile(r"internal\s+relay", re.I),
    re.compile(r"not\s+allowed\s+from\s+your\s+ip", re.I),
    re.compile(r"your\s+ip\s+.*\s+not\s+allowed", re.I),
    re.compile(r"relay\s+denied", re.I),
    re.compile(r"relay\s+not\s+permitted", re.I),
]


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def _probe_relay(host: str, from_domain: str, rcpt_domain: str, port: int = SMTP_PORT) -> dict:
    """MAIL FROM and RCPT TO only; no DATA. Returns relay_likely, codes, error."""
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
        if not line or not line.startswith("250"):
            return out
        _send(sock, f"RCPT TO:<test@{rcpt_domain}>")
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


def _parse_ip_trust_hints(banner: str, ehlo_lines: list) -> list[str]:
    """Return list of matched IP-trust-related phrases (informational)."""
    text = (banner or "") + " " + " ".join(ehlo_lines or [])
    found = []
    for pat in IP_TRUST_PATTERNS:
        for m in pat.finditer(text):
            found.append(m.group(0).strip())
    return list(dict.fromkeys(found))


def _probe_pipelining(host: str, from_domain: str, rcpt_domain: str, port: int = SMTP_PORT) -> dict:
    """
    Safe pipelining test: send EHLO then MAIL FROM + RCPT TO without waiting for 250.
    Then read responses. If server accepts (250 on RCPT TO), pipeline worked.
    We do NOT send DATA; we only detect if server accepts pipelined commands.
    """
    out = {"pipeline_accepted": False, "mail_from_code": None, "rcpt_to_code": None, "error": None}
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
        # Pipeline: send MAIL FROM and RCPT TO without reading 250 in between
        _send(sock, f"MAIL FROM:<test@{from_domain}>")
        _send(sock, f"RCPT TO:<test@{rcpt_domain}>")
        line1 = read_line(sock, SMTP_TIMEOUT)
        line2 = read_line(sock, SMTP_TIMEOUT)
        out["mail_from_code"] = line1[:3] if line1 else None
        out["rcpt_to_code"] = line2[:3] if line2 else None
        if line2 and line2.startswith("250"):
            out["pipeline_accepted"] = True
        _send(sock, "QUIT")
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except OSError as e:
        out["error"] = "network_error"
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def run(ctx: ScanContext) -> None:
    mx_list = ctx.dns_data.get("mx", [])
    sorted_mx = get_mx_hosts_sorted(mx_list)
    domain = ctx.target_domain
    primary_host = get_smtp_host(ctx)

    result = {
        "backup_mx_relays": [],
        "internal_domain_relay_likely": False,
        "ip_trust_hints": [],
        "pipelining": None,
    }

    # 1) Backup MX open relay: primary = first MX, backup = all others
    backup_hosts = sorted_mx[1:] if len(sorted_mx) > 1 else []

    for pref, host in backup_hosts:
        if not host:
            continue
        probe = _probe_relay(host, domain, EXTERNAL_RCPT, SMTP_PORT)
        result["backup_mx_relays"].append({
            "host": host,
            "preference": pref,
            "relay_likely": probe.get("relay_likely", False),
            "mail_from_code": probe.get("mail_from_code"),
            "rcpt_to_code": probe.get("rcpt_to_code"),
            "error": probe.get("error"),
        })

    # 2) Internal domain trust relay: MAIL FROM target domain, RCPT TO external (reuse primary probe)
    internal_probe = _probe_relay(primary_host, domain, EXTERNAL_RCPT, SMTP_PORT)
    result["internal_domain_relay_likely"] = internal_probe.get("relay_likely", False)
    result["internal_domain_codes"] = {
        "mail_from_code": internal_probe.get("mail_from_code"),
        "rcpt_to_code": internal_probe.get("rcpt_to_code"),
    }

    # 3) Null sender: already in open_relay; we do not re-run, analysis will use open_relay result

    # 4) IP-based trust hints: parse banner and EHLO from primary
    enum_data = ctx.smtp_data.get("smtp_enum", {})
    banner = enum_data.get("banner") or ""
    ehlo_lines = enum_data.get("ehlo_lines") or []
    result["ip_trust_hints"] = _parse_ip_trust_hints(banner, ehlo_lines)

    # 5) Pipelining (safe): no DATA, only command order test
    result["pipelining"] = _probe_pipelining(primary_host, domain, EXTERNAL_RCPT, SMTP_PORT)

    ctx.add_smtp_data("open_relay_advanced", result)
    if ctx.verbose:
        logger.debug(
            "Advanced relay: backup_mx_relays=%s internal_domain_relay=%s ip_hints=%s pipeline=%s",
            [r.get("relay_likely") for r in result["backup_mx_relays"]],
            result["internal_domain_relay_likely"],
            result["ip_trust_hints"],
            result.get("pipelining", {}).get("pipeline_accepted"),
        )
