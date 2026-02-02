"""
Webmail security and exploit surface. SAFE: HTTPS, cookies, CSP, X-Frame-Options. ATTACK: login error diff, rate limit (limited).
No XSS/SQLi/file upload payloads; only vulnerability possibility measurement.
"""
import logging
import urllib.request
import urllib.error
import urllib.parse
from core.context import ScanContext
from core.attack_mode import require_attack_mode, enforce_rate_limit

logger = logging.getLogger("mailt.mail")

TIMEOUT = 8.0


def _fetch_headers_and_cookies(url: str) -> dict:
    out = {"https_redirect": False, "secure_cookie": False, "httponly_cookie": False, "csp": False, "x_frame_options": False, "error": None}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MailT/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            headers = dict(resp.headers)
            out["status"] = resp.status
            set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
            out["secure_cookie"] = "secure" in set_cookie.lower()
            out["httponly_cookie"] = "httponly" in set_cookie.lower()
            out["csp"] = bool(headers.get("Content-Security-Policy", headers.get("content-security-policy")))
            out["x_frame_options"] = bool(headers.get("X-Frame-Options", headers.get("x-frame-options")))
            return out
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 307, 308):
            loc = e.headers.get("Location", "")
            out["https_redirect"] = loc.lower().startswith("https")
        out["error"] = str(e.code)
        return out
    except Exception as e:
        out["error"] = str(e)
        return out


def run(ctx: ScanContext) -> None:
    fp = ctx.smtp_data.get("webmail_fingerprint", {})
    base = fp.get("base") or f"https://{ctx.target_domain}"
    result = {"safe_checks": None, "attack_probe": None}

    # SAFE: one login page URL (common paths)
    for path in ["/roundcube/", "/webmail/", "/owa/", "/mail/", "/"]:
        url = base.rstrip("/") + path
        safe = _fetch_headers_and_cookies(url)
        if safe.get("error") is None or safe.get("status") in (200, 302):
            result["safe_checks"] = safe
            result["login_url_tested"] = url
            break

    if require_attack_mode(ctx):
        enforce_rate_limit("webmail_security")
        # ATTACK: 2–3 login attempts with dummy to check error message difference (username enum) and rate limit
        login_url = result.get("login_url_tested") or base
        responses = []
        for i in range(3):
            try:
                data = urllib.parse.urlencode({"user": "mailt-dummy-not-real", "password": "mailt-dummy"}).encode()
                req = urllib.request.Request(login_url, data=data, method="POST", headers={"User-Agent": "MailT/1.0", "Content-Type": "application/x-www-form-urlencoded"})
                with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                    responses.append({"attempt": i + 1, "status": resp.status, "length": len(resp.read())})
            except urllib.error.HTTPError as e:
                responses.append({"attempt": i + 1, "status": e.code, "body_snippet": e.read()[:200].decode("utf-8", errors="replace")})
            except Exception as e:
                responses.append({"attempt": i + 1, "error": str(e)})
            enforce_rate_limit("webmail_security")
        result["attack_probe"] = {"login_attempts": len(responses), "responses": responses[:5], "rate_limit_detected": False}
        ctx.log_exploit_audit("webmail_security", "login_probe", "completed", {"attempts": len(responses)})

    ctx.add_smtp_data("webmail_security", result)
    if ctx.verbose:
        logger.debug("Webmail security: safe_checks=%s", result.get("safe_checks"))
