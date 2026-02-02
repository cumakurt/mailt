"""
Markdown report generation. Human-readable summary and findings list.
"""
import os
from datetime import datetime, timezone
from core.context import ScanContext


def _escape_md(s: str) -> str:
    if not isinstance(s, str):
        s = str(s)
    return s.replace("|", "\\|").replace("\n", " ")


def generate(ctx: ScanContext) -> str:
    """Generate Markdown report; return path to saved file. Uses ctx.output_dir if set. Filename includes UTC timestamp."""
    now = datetime.now(timezone.utc)
    scan_date = now.strftime("%Y-%m-%d %H:%M UTC")
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    if getattr(ctx, "output_dir", None) and ctx.output_dir:
        out_dir = os.path.abspath(ctx.output_dir)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out_dir = os.path.join(base_dir, "reports")
    os.makedirs(out_dir, exist_ok=True)
    safe_domain = "".join(c if c.isalnum() or c in ".-" else "_" for c in ctx.target_domain)
    out_path = os.path.join(out_dir, f"mailt_report_{safe_domain}_{timestamp}.md")
    mode = "ATTACK (exploit PoC)" if getattr(ctx, "attack_mode", False) else "SAFE"
    credential_aware = getattr(ctx, "credential_aware", False)
    test_email = (ctx.test_email or "").strip() if credential_aware else None
    reuse = ctx.smtp_data.get("credential_reuse", {}) if credential_aware else {}
    protocols_ok = reuse.get("protocols_accepting_credential", [])
    credential_login_success = len(protocols_ok) > 0

    lines = [
        "# MailT — Email Security Report",
        "",
        f"**Target:** `{_escape_md(ctx.target_domain)}`  |  **Scan date:** {scan_date}  |  **Findings:** {len(ctx.findings)}  |  **Mode:** {mode}",
        "",
        "## Executive Summary",
        "",
        "This report summarizes the email security posture of the target domain based on anonymous DNS and SMTP checks.",
        "",
    ]
    if credential_aware and test_email:
        login_status = "Succeeded" if credential_login_success else "Failed"
        lines.extend([
            "## Scope",
            "",
            f"Single mail domain. Anonymous checks; test mailbox (credential-aware): `{_escape_md(test_email)}`. **Login:** {login_status}.",
            "",
        ])
    lines.extend([
        "## Scan Results Summary",
        "",
        "| Item | Value |",
        "|------|-------|",
        f"| MX status | {ctx.dns_data.get('mx_status', '—')} |",
        f"| SPF | {'Present' if ctx.dns_data.get('spf_record') else 'Not found'} |",
        f"| DMARC | {'Present' if ctx.dns_data.get('dmarc_record') else 'Not found'} |",
        f"| DKIM selectors | {len(ctx.dns_data.get('dkim_selectors') or [])} |",
        f"| STARTTLS | {'Yes' if (ctx.smtp_data.get('starttls') or {}).get('supported') else 'No'} |",
        f"| Open relay likely | {'Yes' if (ctx.smtp_data.get('open_relay') or {}).get('relay_likely') else 'No'} |",
        "",
    ])
    if credential_aware:
        tls_risk = ctx.smtp_data.get("credential_tls_risk", {})
        spoof = ctx.smtp_data.get("credential_auth_spoof", {})
        lines.extend([
            "## Credential-aware tests",
            "",
            f"**Test mailbox:** `{_escape_md(test_email or '')}`",
            "",
            f"**Login status:** " + ("Succeeded (at least one protocol accepted)." if credential_login_success else "**Failed** (no protocol accepted the provided --email and --password)."),
            "",
            "| Protocol | Credential accepted |",
            "|----------|---------------------|",
            f"| SMTP AUTH (587) | {'Yes' if reuse.get('smtp_auth_587') else 'No'} |",
            f"| SMTP AUTH (25+STARTTLS) | {'Yes' if reuse.get('smtp_auth_25_starttls') else 'No'} |",
            f"| POP3 (110) | {'Yes' if reuse.get('pop3_110') else 'No'} |",
            f"| POP3S (995) | {'Yes' if reuse.get('pop3s_995') else 'No'} |",
            f"| IMAP (143) | {'Yes' if reuse.get('imap_143') else 'No'} |",
            f"| IMAPS (993) | {'Yes' if reuse.get('imaps_993') else 'No'} |",
            "",
            f"**TLS / plain auth accepted (no STARTTLS):** {'Yes' if tls_risk.get('plain_auth_accepted') else 'No'}",
            "",
            f"**Authenticated From/Display name PoC:** {'Success' if spoof.get('exploit_success') else 'Failed or not attempted'}",
            "",
        ])
    # RBL / DNSBL section
    rbl = ctx.smtp_data.get("rbl_check", {})
    if rbl:
        summary = rbl.get("summary", {})
        by_ip = rbl.get("by_ip", {})
        total_ips = summary.get("total_ips", 0)
        ips_listed = summary.get("ips_listed_count", 0)
        lines.extend([
            "## RBL / DNSBL Blacklist Results",
            "",
            f"**Summary:** {total_ips} SMTP IP(s) tested. IPs listed on at least one blacklist: **{ips_listed}**.",
            "",
        ])
        if by_ip:
            lines.append("| IP | Host | Source | Reputation score | Listed |")
            lines.append("|----|------|--------|-------------------|--------|")
            for ip, data in by_ip.items():
                host = _escape_md(data.get("host", ip))
                source = _escape_md(data.get("source", "mx"))
                score = data.get("reputation_score", 0.0)
                listed = data.get("listed_count", 0)
                total_checked = data.get("total_checked", 0)
                lines.append(f"| {ip} | {host} | {source} | {score:.2f} | {listed}/{total_checked} |")
            lines.append("")
    lines.extend([
        "## Findings",
        "",
    ])
    if not ctx.findings:
        lines.append("No findings.")
    else:
        lines.append("| Severity | Title | Category |")
        lines.append("|----------|-------|----------|")
        for f in ctx.findings:
            sev = (f.get("cvss_severity") or f.get("severity_hint") or "—")
            title = _escape_md((f.get("title") or "")[:60])
            cat = _escape_md((f.get("category") or "")[:30])
            lines.append(f"| {sev} | {title} | {cat} |")
    if ctx.step_errors:
        lines.extend(["", "## Step Errors", ""])
        for err in ctx.step_errors:
            lines.append(f"- **{err.get('step', '')}**: {err.get('error', '')}")
    lines.extend([
        "",
        "---",
        "*MailT by [Cuma KURT](https://www.linkedin.com/in/cuma-kurt-34414917/) — cumakurt@gmail.com | [GitHub](https://github.com/cumakurt/mailt)*",
        "",
    ])
    content = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return out_path
