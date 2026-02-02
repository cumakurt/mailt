"""
Mail account takeover chain analysis. Correlates POP3/IMAP weak auth, webmail rate-limit, no MFA → single attack path.
Produces chained finding: CRITICAL. No exploit; correlation only.
"""
import logging
from core.context import ScanContext

logger = logging.getLogger("mailt.mail")


def run(ctx: ScanContext) -> None:
    pop3 = ctx.smtp_data.get("pop3_security", {})
    imap = ctx.smtp_data.get("imap_security", {})
    webmail = ctx.smtp_data.get("webmail_security", {})
    auth_sim = ctx.smtp_data.get("auth_attack_simulation", {})

    pop3_open_plain = pop3.get("pop3_110", {}).get("open", False)
    pop3_no_rate = not (pop3.get("attack_probe") or {}).get("rate_limit_detected", False)
    imap_open_plain = imap.get("imap_143", {}).get("open", False)
    imap_no_rate = not (imap.get("attack_probe") or {}).get("rate_limit_detected", False)
    webmail_no_rate = not (webmail.get("attack_probe") or {}).get("rate_limit_detected", True)
    smtp_auth_no_rate = bool(auth_sim.get("exploit_attempted") and not auth_sim.get("rate_limit_detected"))

    chained_risk = (
        (pop3_open_plain and pop3_no_rate) or
        (imap_open_plain and imap_no_rate) or
        (smtp_auth_no_rate and auth_sim.get("attempts", 0) >= 3)
    ) and webmail_no_rate

    ctx.add_smtp_data("mail_account_takeover_chain", {
        "chained_risk": chained_risk,
        "pop3_weak": pop3_open_plain and pop3_no_rate,
        "imap_weak": imap_open_plain and imap_no_rate,
        "webmail_weak_rate": webmail_no_rate,
        "smtp_auth_weak": smtp_auth_no_rate,
    })
    if ctx.verbose:
        logger.debug("Account takeover chain: chained_risk=%s", chained_risk)
