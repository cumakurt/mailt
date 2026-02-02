"""
Authenticated spoof PoC: after SMTP AUTH login, test From header / display name manipulation.
Sends only to the test account itself (RCPT TO test_email); no real third party.
PoC mail is empty/descriptive only; no links, attachments, or social engineering content.
"""
import base64
import logging
import ssl
from core.context import ScanContext
from core.utils import safe_socket_connect, read_line, get_smtp_host
from core.constants import SMTP_PORT, SMTP_PORT_SUBMISSION, EHLO_IDENTITY

logger = logging.getLogger("mailt.credential_tests")

TIMEOUT = 15.0


def _send(sock, cmd: str) -> None:
    sock.sendall((cmd + "\r\n").encode("utf-8"))


def run(ctx: ScanContext) -> None:
    if not getattr(ctx, "credential_aware", False) or not getattr(ctx, "test_email", None) or not getattr(ctx, "test_password", None):
        return
    email = (ctx.test_email or "").strip()
    password = ctx.test_password or ""
    if not email:
        return

    host = get_smtp_host(ctx)
    result = {
        "exploit_attempted": True,
        "exploit_success": False,
        "auth_success": False,
        "mail_accepted": False,
        "from_manipulation_accepted": None,
        "proof_of_execution": None,
        "error": None,
    }

    # Prefer submission 587 (STARTTLS) for authenticated send
    for port, use_starttls in [(SMTP_PORT_SUBMISSION, True), (SMTP_PORT, True)]:
        sock = safe_socket_connect(host, port, TIMEOUT)
        if not sock:
            continue
        try:
            read_line(sock, TIMEOUT)
            _send(sock, f"EHLO {EHLO_IDENTITY}")
            while True:
                line = read_line(sock, TIMEOUT)
                if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                    break
            if use_starttls:
                _send(sock, "STARTTLS")
                line = read_line(sock, TIMEOUT)
                if not line or not line.startswith("220"):
                    continue
                ssl_ctx = ssl.create_default_context()
                sock = ssl_ctx.wrap_socket(sock, server_hostname=host)
                _send(sock, f"EHLO {EHLO_IDENTITY}")
                while True:
                    line = read_line(sock, TIMEOUT)
                    if not line or (len(line) >= 3 and line[3:4] != "-" and line[:3] == "250"):
                        break
            plain = base64.b64encode(f"\x00{email}\x00{password}".encode("utf-8")).decode("ascii")
            _send(sock, f"AUTH PLAIN {plain}")
            line = read_line(sock, TIMEOUT)
            if not line or not line.startswith("235"):
                result["proof_of_execution"] = (line or "").strip()[:200]
                break
            result["auth_success"] = True
            _send(sock, f"MAIL FROM:<{email}>")
            line = read_line(sock, TIMEOUT)
            if not line or not line.startswith("250"):
                result["proof_of_execution"] = (line or "").strip()[:200]
                break
            _send(sock, f"RCPT TO:<{email}>")
            line = read_line(sock, TIMEOUT)
            if not line or not line.startswith("250"):
                result["proof_of_execution"] = (line or "").strip()[:200]
                break
            _send(sock, "DATA")
            line = read_line(sock, TIMEOUT)
            if not line or not line.startswith("354"):
                result["proof_of_execution"] = (line or "").strip()[:200]
                break
            # PoC: From header / display name manipulation (internal); no links, no attachments
            body = (
                f"From: Internal Spoof PoC <{email}>\r\n"
                f"To: {email}\r\n"
                "Subject: MailT Credential Test - Authenticated From/Display Name PoC\r\n"
                "Date: Mon, 1 Jan 2020 00:00:00 +0000\r\n"
                "\r\n"
                "This is a controlled PoC message. No social engineering content.\r\n"
                ".\r\n"
            )
            _send(sock, body)
            line = read_line(sock, TIMEOUT)
            result["mail_accepted"] = line and line.startswith("250")
            result["from_manipulation_accepted"] = result["mail_accepted"]
            result["exploit_success"] = result["mail_accepted"]
            result["proof_of_execution"] = (line or "").strip()[:200] if line else None
            _send(sock, "QUIT")
        except Exception as e:
            result["error"] = str(e)[:200]
        finally:
            try:
                sock.close()
            except OSError:
                pass
        if result["auth_success"]:
            break

    ctx.add_smtp_data("credential_auth_spoof", result)
    if ctx.verbose:
        logger.debug(
            "Authenticated spoof PoC: auth=%s mail_accepted=%s",
            result["auth_success"],
            result["mail_accepted"],
        )
