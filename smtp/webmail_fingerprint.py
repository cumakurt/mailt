"""
Webmail discovery and fingerprinting. SAFE MODE.
URL pattern detection, header/HTML fingerprint, version disclosure.
Uses mail_service_discovery webmail result if present; otherwise probes target domain.
"""
import logging
from core.context import ScanContext

logger = logging.getLogger("mailt.mail")


def run(ctx: ScanContext) -> None:
    discovery = ctx.smtp_data.get("mail_service_discovery", {})
    webmail = discovery.get("webmail")
    domain = ctx.target_domain
    if not webmail and discovery:
        ctx.add_smtp_data("webmail_fingerprint", {"detected": [], "base": f"https://{domain}", "source": "no_webmail"})
        return
    if not webmail:
        import urllib.request
        import urllib.error
        base = f"https://{domain}"
        detected = []
        for path in ["/", "/owa/", "/roundcube/", "/webmail/", "/mail/"]:
            try:
                req = urllib.request.Request(base + path, headers={"User-Agent": "MailT/1.0"})
                with urllib.request.urlopen(req, timeout=6) as resp:
                    html = resp.read().decode("utf-8", errors="replace")[:4096].lower()
                    if "roundcube" in html:
                        detected.append({"path": path, "product": "Roundcube", "version": None})
                    if "owa" in path or "exchange" in html:
                        detected.append({"path": path, "product": "OWA/Exchange", "version": None})
                    if "zimbra" in html:
                        detected.append({"path": path, "product": "Zimbra", "version": None})
            except Exception:
                continue
        webmail = {"detected": detected[:5], "base": base}
    result = {"detected": webmail.get("detected", []), "base": webmail.get("base", f"https://{domain}"), "version_disclosed": []}
    for d in result["detected"]:
        if d.get("version"):
            result["version_disclosed"].append(f"{d.get('product')} {d.get('version')}")
    ctx.add_smtp_data("webmail_fingerprint", result)
    if ctx.verbose:
        logger.debug("Webmail fingerprint: %s", result.get("detected"))
