"""
Test orchestration: runs DNS and SMTP modules, then analysis and reporting.
Reports progress: current step, total steps, elapsed time, percentage, remaining.
Steps run in try/except; failures are recorded and scan continues.
"""
import logging
import threading
import time
from core.context import ScanContext
from core.progress import ProgressReporter, build_step_list

logger = logging.getLogger("mailt")


def _run_step(ctx: ScanContext, name: str, fn, step_done_detail_fn=None) -> None:
    """Run a single step; on exception log and record in ctx.step_errors, then continue."""
    try:
        fn(ctx)
    except Exception as e:
        logger.exception("Step %s failed: %s", name, e)
        ctx.add_step_error(name, str(e))
    if ctx.progress and step_done_detail_fn:
        ctx.progress.step_done(step_done_detail_fn(ctx, name))


def run_dns_checks(ctx: ScanContext) -> None:
    """Run all DNS-based checks and store results in context."""
    from dns_checks import dns_enum
    from dns_checks import spf
    from dns_checks import dkim
    from dns_checks import dmarc
    from dns_checks import bimi
    from dns_checks import rbl_check

    dns_steps = [
        ("DNS: Resolve MX, A, AAAA, TXT, NS", dns_enum.run),
        ("DNS: SPF record lookup", spf.run),
        ("DNS: DKIM selector discovery", dkim.run),
        ("DNS: DMARC policy lookup", dmarc.run),
        ("DNS: BIMI check", bimi.run),
        ("DNS: SPF bypass / policy analysis", lambda c: __import__("dns_checks.spf_bypass", fromlist=["run"]).run(c)),
        ("DNS: RBL/DNSBL blacklist check", rbl_check.run),
    ]
    for name, fn in dns_steps:
        if ctx.progress:
            ctx.progress.advance(name)
        _run_step(ctx, name, fn, _dns_step_result)




def _dns_step_result(ctx: ScanContext, name: str) -> str | None:
    """One-line result after step for verbose."""
    if not ctx.verbose:
        return None
    d = ctx.dns_data
    if "Resolve MX" in name:
        mx = d.get("mx", [])
        st = d.get("mx_status", "?")
        if st == "ok" and mx:
            return f"Pass: {len(mx)} MX record(s)"
        if st == "empty":
            return "No MX records"
        if st in ("timeout", "error"):
            return f"Inconclusive: {st}"
        return f"Status: {st}"
    if "SPF" in name:
        rec = d.get("spf_record")
        if rec:
            return f"Pass: SPF found ({len(rec)} chars)"
        return "No SPF record"
    if "DKIM" in name:
        sel = d.get("dkim_selectors", [])
        if sel:
            return f"Pass: {len(sel)} selector(s) found"
        return "No DKIM selectors found"
    if "DMARC" in name:
        rec = d.get("dmarc_record")
        if rec:
            pol = (d.get("dmarc_parsed") or {}).get("policy", "?")
            return f"Pass: DMARC policy={pol}"
        return "No DMARC record"
    if "BIMI" in name:
        rec = d.get("bimi_record")
        return "Pass: BIMI found" if rec else "No BIMI record"
    if "SPF bypass" in name:
        bypass = d.get("spf_bypass", {})
        sub = bypass.get("subdomain_no_spf", [])
        return f"+all: {bypass.get('spf_plus_all')}, subdomain_no_spf: {len(sub)}"
    if "RBL" in name or "DNSBL" in name:
        rbl = ctx.smtp_data.get("rbl_check", {})
        s = rbl.get("summary", {})
        total = s.get("total_ips", 0)
        listed = s.get("ips_listed_count", 0)
        return f"IPs tested: {total}, listed: {listed}" if total else "No SMTP IPs to test"
    return None


def run_smtp_checks(ctx: ScanContext) -> None:
    """Run all SMTP/TLS and mail ecosystem checks and store results in context."""
    from smtp import (
        smtp_enum, starttls, tls_analysis, open_relay, open_relay_advanced, catch_all, auth_check,
        mail_service_discovery, pop3_security, imap_security, webmail_fingerprint, webmail_security,
        mail_account_takeover_chain, mail_dos_analysis,
    )

    smtp_steps = [
        ("SMTP: Connect and EHLO (banner)", smtp_enum.run),
        ("SMTP: STARTTLS upgrade", starttls.run),
        ("SMTP: TLS version and cipher", tls_analysis.run),
        ("SMTP: Open relay probe", open_relay.run),
        ("SMTP: Advanced open relay (backup MX, internal trust, pipelining)", open_relay_advanced.run),
        ("SMTP: Catch-all check", catch_all.run),
        ("SMTP: AUTH without STARTTLS check", auth_check.run),
        ("Mail: Protocol surface discovery (SMTP/POP3/IMAP/Webmail)", mail_service_discovery.run),
        ("Mail: POP3/POP3S security", pop3_security.run),
        ("Mail: IMAP/IMAPS security", imap_security.run),
        ("Mail: Webmail fingerprint", webmail_fingerprint.run),
        ("Mail: Webmail security (HTTPS, cookies, CSP)", webmail_security.run),
        ("Mail: Account takeover chain analysis", mail_account_takeover_chain.run),
        ("Mail: DoS/resource analysis", mail_dos_analysis.run),
    ]
    for name, fn in smtp_steps:
        if ctx.progress:
            ctx.progress.advance(name)
        _run_step(ctx, name, fn, _smtp_step_result)


def _smtp_step_result(ctx: ScanContext, name: str) -> str | None:
    if not ctx.verbose:
        return None
    s = ctx.smtp_data
    if "Connect and EHLO" in name:
        e = s.get("smtp_enum", {})
        return f"Banner: {e.get('banner', '')[:50]}..." if e.get("banner") else "No banner"
    if "STARTTLS upgrade" in name:
        st = s.get("starttls", {})
        return f"STARTTLS: {'yes' if st.get('supported') else 'no'}"
    if "TLS version" in name:
        t = s.get("tls_analysis", {})
        return f"TLS: {t.get('protocol', '?')}" if t.get("protocol") else "N/A"
    if "Open relay probe" in name:
        r = s.get("open_relay", {})
        return f"Relay: {'likely' if r.get('relay_likely') else 'no'}"
    if "Catch-all" in name:
        c = s.get("catch_all_check", {})
        return f"Catch-all: {'likely' if c.get('catch_all_likely') else 'no'}"
    if "AUTH without" in name:
        a = s.get("auth_check", {})
        return f"AUTH without TLS: {'yes' if a.get('auth_accepts_without_starttls') else 'no'}"
    if "Advanced open relay" in name:
        adv = s.get("open_relay_advanced", {})
        backup_relay = any(r.get("relay_likely") for r in adv.get("backup_mx_relays", []))
        return f"Backup MX relay: {'yes' if backup_relay else 'no'}, internal: {adv.get('internal_domain_relay_likely')}"
    if "Protocol surface" in name:
        d = s.get("mail_service_discovery", {})
        ports = d.get("ports", {})
        open_p = [k for k, v in ports.items() if v.get("open")]
        return f"Open: {open_p[:6]}" if open_p else "none"
    if "POP3" in name and "security" in name:
        p = s.get("pop3_security", {})
        return f"110: {p.get('pop3_110', {}).get('open')} 995: {p.get('pop3s_995', {}).get('open')}"
    if "IMAP" in name and "security" in name:
        i = s.get("imap_security", {})
        return f"143: {i.get('imap_143', {}).get('open')} 993: {i.get('imaps_993', {}).get('open')}"
    if "Webmail fingerprint" in name:
        w = s.get("webmail_fingerprint", {})
        return f"Detected: {[d.get('product') for d in w.get('detected', [])]}"
    if "Account takeover" in name:
        c = s.get("mail_account_takeover_chain", {})
        return f"Chained risk: {c.get('chained_risk')}"
    return None


def run_analysis(ctx: ScanContext) -> None:
    """Normalize raw data into findings, apply CVSS and MITRE."""
    from analysis.findings import collect_findings_from_context
    from analysis.risk_engine import apply_cvss_to_findings
    from analysis.mitre_mapper import apply_mitre_to_findings

    if ctx.progress:
        ctx.progress.advance("Analysis: Normalize findings, CVSS, MITRE")
    collect_findings_from_context(ctx)
    apply_cvss_to_findings(ctx.findings)
    apply_mitre_to_findings(ctx.findings)
    if ctx.progress:
        ctx.progress.step_done(f"{len(ctx.findings)} finding(s)" if ctx.verbose else None)


def run_reporting(ctx: ScanContext) -> None:
    """Generate report(s) from findings (HTML, JSON, Markdown per ctx.output_format)."""
    from reporting.html_report import generate as generate_html
    from reporting.json_report import generate as generate_json
    from reporting.markdown_report import generate as generate_markdown

    fmt = (ctx.output_format or "html").lower()
    if fmt in ("html", "all"):
        if ctx.progress:
            ctx.progress.advance("Reporting: Generate HTML report")
        try:
            p = generate_html(ctx)
            if ctx.progress:
                ctx.progress.step_done(p if ctx.verbose else None)
        except Exception as e:
            logger.exception("HTML report failed: %s", e)
            ctx.add_step_error("Reporting: Generate HTML report", str(e))
            if ctx.progress:
                ctx.progress.step_done(None)
    if fmt in ("json", "all"):
        if ctx.progress:
            ctx.progress.advance("Reporting: Generate JSON report")
        try:
            p = generate_json(ctx)
            if ctx.progress:
                ctx.progress.step_done(p if ctx.verbose else None)
        except Exception as e:
            logger.exception("JSON report failed: %s", e)
            ctx.add_step_error("Reporting: Generate JSON report", str(e))
            if ctx.progress:
                ctx.progress.step_done(None)
    if fmt in ("markdown", "all"):
        if ctx.progress:
            ctx.progress.advance("Reporting: Generate Markdown report")
        try:
            p = generate_markdown(ctx)
            if ctx.progress:
                ctx.progress.step_done(p if ctx.verbose else None)
        except Exception as e:
            logger.exception("Markdown report failed: %s", e)
            ctx.add_step_error("Reporting: Generate Markdown report", str(e))
            if ctx.progress:
                ctx.progress.step_done(None)


def run_exploit_phase(ctx: ScanContext) -> None:
    """Run exploit/PoC modules only when attack_mode is enabled. No exploit code runs without both flags."""
    from core.attack_mode import log_attack_warning
    from smtp import (
        open_relay_exploit, spoof_exploit, display_name_exploit, auth_attack_simulation,
        internal_trust_exploit, smtp_smuggling_poc, cross_protocol_attack,
    )

    if not ctx.attack_mode:
        return
    log_attack_warning()
    exploit_steps = [
        ("EXPLOIT: Open relay PoC", open_relay_exploit.run),
        ("EXPLOIT: SPF/DMARC spoof PoC", spoof_exploit.run),
        ("EXPLOIT: Display name spoof PoC", display_name_exploit.run),
        ("EXPLOIT: AUTH brute simulation", auth_attack_simulation.run),
        ("EXPLOIT: Internal trust PoC", internal_trust_exploit.run),
        ("EXPLOIT: SMTP smuggling PoC", smtp_smuggling_poc.run),
        ("EXPLOIT: Cross-protocol credential reuse", cross_protocol_attack.run),
    ]
    for name, fn in exploit_steps:
        if ctx.progress:
            ctx.progress.advance(name)
        _run_step(ctx, name, fn, _exploit_step_result)


def _exploit_step_result(ctx: ScanContext, name: str) -> str | None:
    if not ctx.verbose:
        return None
    s = ctx.smtp_data
    if "Open relay PoC" in name:
        r = s.get("open_relay_exploit", {})
        return f"success={r.get('exploit_success')}" if r.get("exploit_attempted") else "skipped"
    if "SPF/DMARC spoof" in name:
        r = s.get("spoof_exploit", {})
        return f"success={r.get('exploit_success')}" if r.get("exploit_attempted") else "skipped"
    if "Display name" in name:
        r = s.get("display_name_exploit", {})
        return f"success={r.get('exploit_success')}" if r.get("exploit_attempted") else "skipped"
    if "AUTH brute" in name:
        r = s.get("auth_attack_simulation", {})
        return f"attempts={r.get('attempts')} rate_limit={r.get('rate_limit_detected')}" if r.get("exploit_attempted") else "skipped"
    if "Internal trust" in name:
        r = s.get("internal_trust_exploit", {})
        return f"success={r.get('exploit_success')}" if r.get("exploit_attempted") else "skipped"
    if "SMTP smuggling" in name:
        r = s.get("smtp_smuggling_poc", {})
        return f"pipeline_accept={r.get('frontend_reject_backend_accept')}" if r.get("exploit_attempted") else "skipped"
    if "Cross-protocol" in name:
        r = s.get("cross_protocol_attack", {})
        return f"credential_reuse_risk={r.get('credential_reuse_risk')} lockout_inconsistent={r.get('lockout_inconsistent')}" if r else "skipped"
    return None


def _apply_timeouts(ctx: ScanContext) -> dict:
    """Apply ctx timeouts to core.utils and core.constants for this scan. Returns saved state for restore."""
    from core import utils as core_utils
    from core import constants as core_constants
    saved: dict = {}
    if ctx.dns_timeout is not None:
        saved["utils"] = (core_utils.DNS_TIMEOUT, core_utils.DNS_LIFETIME)
        core_utils.DNS_TIMEOUT = float(ctx.dns_timeout)
        core_utils.DNS_LIFETIME = max(core_utils.DNS_TIMEOUT * 2, core_utils.DNS_LIFETIME)
    if ctx.smtp_timeout is not None:
        saved["constants"] = (
            core_constants.SMTP_TIMEOUT,
            core_constants.SMTP_BANNER_TIMEOUT,
            core_constants.SMTP_EXPLOIT_TIMEOUT,
        )
        core_constants.SMTP_TIMEOUT = float(ctx.smtp_timeout)
        core_constants.SMTP_BANNER_TIMEOUT = float(ctx.smtp_timeout)
        core_constants.SMTP_EXPLOIT_TIMEOUT = max(15.0, float(ctx.smtp_timeout) + 5)
    return saved


def _restore_timeouts(saved: dict) -> None:
    """Restore module timeout globals after scan so sequential scans get default timeouts."""
    if not saved:
        return
    from core import utils as core_utils
    from core import constants as core_constants
    if "utils" in saved:
        core_utils.DNS_TIMEOUT, core_utils.DNS_LIFETIME = saved["utils"]
    if "constants" in saved:
        core_constants.SMTP_TIMEOUT, core_constants.SMTP_BANNER_TIMEOUT, core_constants.SMTP_EXPLOIT_TIMEOUT = saved["constants"]


def run_credential_phase(ctx: ScanContext) -> None:
    """Run credential-aware (user-based) tests when --email and --password are provided."""
    if not ctx.credential_aware:
        return
    from credential_tests import credential_reuse, tls_credential_risk, auth_spoof_authenticated

    cred_steps = [
        ("Credential: Reuse (SMTP AUTH, POP3, IMAP)", credential_reuse.run),
        ("Credential: TLS/plain auth risk", tls_credential_risk.run),
        ("Credential: Authenticated From/Display name PoC", auth_spoof_authenticated.run),
    ]
    for name, fn in cred_steps:
        if ctx.progress:
            ctx.progress.advance(name)
        _run_step(ctx, name, fn, _credential_step_result)

    # Notify on screen if login failed (no protocol accepted the credentials)
    reuse = ctx.smtp_data.get("credential_reuse", {})
    protocols_ok = reuse.get("protocols_accepting_credential", [])
    if not protocols_ok:
        logger.warning(
            "Credential-aware: Login failed. The provided --email and --password were not accepted by any protocol (SMTP AUTH, POP3, IMAP). Check credentials and server availability."
        )


def _credential_step_result(ctx: ScanContext, name: str) -> str | None:
    if not ctx.verbose:
        return None
    s = ctx.smtp_data
    if "Reuse" in name:
        r = s.get("credential_reuse", {})
        protocols = r.get("protocols_accepting_credential", [])
        return f"protocols={protocols}" if protocols else "none"
    if "TLS/plain" in name:
        r = s.get("credential_tls_risk", {})
        return f"plain_auth_accepted={r.get('plain_auth_accepted')}"
    if "Authenticated From" in name:
        r = s.get("credential_auth_spoof", {})
        return f"auth_ok={r.get('auth_success')} mail_accepted={r.get('mail_accepted')}"
    return None


def run_scan(ctx: ScanContext) -> None:
    """Full scan: DNS -> SMTP [-> Credential if credential_aware] [-> EXPLOIT if attack_mode] -> Analysis -> Reporting."""
    timeout_saved = _apply_timeouts(ctx)
    output_fmt = ctx.output_format or "html"
    step_names = build_step_list(
        ctx.run_dns,
        ctx.run_smtp,
        ctx.attack_mode,
        ctx.credential_aware,
        output_format=output_fmt,
    )
    total = len(step_names)
    progress = ProgressReporter(total, verbose=ctx.verbose, quiet=ctx.quiet)
    ctx.progress = progress
    progress.start(step_names)
    try:
        if ctx.run_dns:
            run_dns_checks(ctx)
        if ctx.run_smtp:
            run_smtp_checks(ctx)
        if ctx.credential_aware:
            run_credential_phase(ctx)
        if ctx.attack_mode:
            run_exploit_phase(ctx)
        try:
            run_analysis(ctx)
        except Exception as e:
            logger.exception("Analysis failed: %s", e)
            ctx.add_step_error("Analysis: Normalize findings, CVSS, MITRE", str(e))
            if ctx.progress:
                ctx.progress.advance("Analysis: Normalize findings, CVSS, MITRE")
                ctx.progress.step_done(None)
        run_reporting(ctx)
    finally:
        progress.done()
        ctx.progress = None
        _restore_timeouts(timeout_saved)


def main_scan(ctx: ScanContext) -> None:
    """Entry point for scan; handles logging, log file, timeout, and errors."""
    log_format = "%(name)s %(levelname)s %(message)s" if ctx.verbose else "%(message)s"
    log_level = logging.DEBUG if ctx.verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if ctx.log_file:
        try:
            fh = logging.FileHandler(ctx.log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter(log_format))
            handlers.append(fh)
        except OSError as e:
            logger.warning("Could not open log file %s: %s", ctx.log_file, e)
    logging.basicConfig(level=log_level, format=log_format, handlers=handlers, force=True)

    logger.info("MailT — Email Security Analysis | Target: %s", ctx.target_domain)
    if ctx.attack_mode:
        logger.warning("[WARNING] ATTACK MODE enabled. Exploit/PoC modules will run. Use only on authorized targets.")

    timeout_sec = ctx.scan_timeout_seconds
    if timeout_sec and float(timeout_sec) > 0:
        scan_done: list[bool] = []

        def run_scan_thread() -> None:
            run_scan(ctx)
            scan_done.append(True)

        t = threading.Thread(target=run_scan_thread, daemon=True)
        t.start()
        t.join(timeout=float(timeout_sec))
        if not scan_done:
            ctx.add_step_error("Scan", f"Scan timed out after {timeout_sec}s")
            logger.warning("Scan timed out after %s seconds", timeout_sec)
    else:
        run_scan(ctx)

    logger.info("Scan complete. Findings: %d", len(ctx.findings))
    if ctx.step_errors:
        logger.warning("Step errors: %d", len(ctx.step_errors))
        for err in ctx.step_errors:
            logger.warning("  %s: %s", err.get("step"), err.get("error", ""))
