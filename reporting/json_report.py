"""
JSON report generation. Findings, summary, and scan metadata for CI/automation.
"""
import json
import os
from datetime import datetime, timezone
from core.context import ScanContext


def _credential_tests_payload(ctx: ScanContext) -> dict | None:
    """Credential-aware tests summary for JSON report."""
    if not getattr(ctx, "credential_aware", False):
        return None
    reuse = ctx.smtp_data.get("credential_reuse", {})
    protocols = reuse.get("protocols_accepting_credential", [])
    tls_risk = ctx.smtp_data.get("credential_tls_risk", {})
    spoof = ctx.smtp_data.get("credential_auth_spoof", {})
    return {
        "test_email": (ctx.test_email or "").strip(),
        "login_success": len(protocols) > 0,
        "login_failed": len(protocols) == 0,
        "protocols_accepting_credential": protocols,
        "credential_reuse": {
            "smtp_auth_587": reuse.get("smtp_auth_587", False),
            "smtp_auth_25_starttls": reuse.get("smtp_auth_25_starttls", False),
            "pop3_110": reuse.get("pop3_110", False),
            "pop3s_995": reuse.get("pop3s_995", False),
            "imap_143": reuse.get("imap_143", False),
            "imaps_993": reuse.get("imaps_993", False),
        },
        "tls_plain_auth_accepted": tls_risk.get("plain_auth_accepted", False),
        "authenticated_spoof_poc_success": spoof.get("exploit_success", False),
    }


def generate(ctx: ScanContext) -> str:
    """Generate JSON report; return path to saved file. Uses ctx.output_dir if set. Filename includes UTC timestamp."""
    now = datetime.now(timezone.utc)
    scan_date = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    if getattr(ctx, "output_dir", None) and ctx.output_dir:
        out_dir = os.path.abspath(ctx.output_dir)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out_dir = os.path.join(base_dir, "reports")
    os.makedirs(out_dir, exist_ok=True)
    safe_domain = "".join(c if c.isalnum() or c in ".-" else "_" for c in ctx.target_domain)
    out_path = os.path.join(out_dir, f"mailt_report_{safe_domain}_{timestamp}.json")
    credential_aware = getattr(ctx, "credential_aware", False)
    reuse = ctx.smtp_data.get("credential_reuse", {}) if credential_aware else {}
    protocols_ok = reuse.get("protocols_accepting_credential", [])
    credential_login_success = len(protocols_ok) > 0

    payload = {
        "target_domain": ctx.target_domain,
        "scan_date": scan_date,
        "tool": "MailT",
        "author": "Cuma KURT",
        "author_email": "cumakurt@gmail.com",
        "repository": "https://github.com/cumakurt/mailt",
        "attack_mode": getattr(ctx, "attack_mode", False),
        "credential_aware": credential_aware,
        "test_email": (ctx.test_email or "").strip() if credential_aware else None,
        "credential_login_success": credential_login_success if credential_aware else None,
        "credential_login_failed": (not credential_login_success) if credential_aware else None,
        "findings_count": len(ctx.findings),
        "step_errors_count": len(ctx.step_errors),
        "findings": ctx.findings,
        "step_errors": ctx.step_errors,
        "credential_tests": _credential_tests_payload(ctx) if credential_aware else None,
        "dns_summary": {
            "mx_status": ctx.dns_data.get("mx_status"),
            "spf_present": bool(ctx.dns_data.get("spf_record")),
            "dmarc_present": bool(ctx.dns_data.get("dmarc_record")),
            "dkim_selectors_count": len(ctx.dns_data.get("dkim_selectors") or []),
        },
        "smtp_summary": {
            "banner": ((ctx.smtp_data.get("smtp_enum") or {}).get("banner") or "")[:200],
            "starttls": (ctx.smtp_data.get("starttls") or {}).get("supported"),
            "open_relay_likely": (ctx.smtp_data.get("open_relay") or {}).get("relay_likely"),
        },
        "rbl_check": ctx.smtp_data.get("rbl_check"),
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return out_path
