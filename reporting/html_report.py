"""
HTML report generation. Modern, colorful; full DKIM list, relay summary, TLS alerts, gateway detection.
"""
import html
import os
from datetime import datetime, timezone
from core.context import ScanContext


def _escape(s: str) -> str:
    if not isinstance(s, str):
        s = str(s)
    return html.escape(s)


def _severity_class(sev: str) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "sev-critical"
    if s == "high":
        return "sev-high"
    if s == "medium":
        return "sev-medium"
    if s == "low":
        return "sev-low"
    return "sev-none"


def _executive_summary_mode_text(ctx: ScanContext) -> str:
    """Return Executive Summary sentence depending on SAFE vs ATTACK mode."""
    if getattr(ctx, "attack_mode", False):
        return "In ATTACK MODE, controlled exploit/PoC attempts were run using RFC test domains and test mailbox only; no real recipients or abuse."
    return "No credentials or exploit attempts were used (SAFE MODE)."


def _credential_login_success(ctx: ScanContext) -> bool:
    """True if at least one protocol accepted the test credential."""
    if not getattr(ctx, "credential_aware", False):
        return False
    reuse = ctx.smtp_data.get("credential_reuse", {})
    protocols = reuse.get("protocols_accepting_credential", [])
    return len(protocols) > 0


def _scope_credential_text(ctx: ScanContext) -> str:
    """Return Scope sentence for credential-aware scan: test email and login status."""
    if not getattr(ctx, "credential_aware", False) or not getattr(ctx, "test_email", None):
        return ""
    email = _escape((ctx.test_email or "").strip())
    login_ok = _credential_login_success(ctx)
    status = "Login: <strong>Succeeded</strong> (at least one protocol accepted the credentials)." if login_ok else "Login: <strong>Failed</strong> (no protocol accepted the provided credentials)."
    return f" Test mailbox (credential-aware): <code>{email}</code>. {status}"


def _scan_results_html(ctx: ScanContext) -> str:
    d = ctx.dns_data
    s = ctx.smtp_data
    parts = []
    # MX
    mx_list = d.get("mx", [])
    mx_status = d.get("mx_status", "?")
    valid_mx = [(pref, (host or "").strip()) for pref, host in mx_list if (host or "").strip()]
    valid_mx.sort(key=lambda x: (x[0], x[1]))
    if valid_mx:
        parts.append("<tr><td><strong>MX</strong></td><td>status: " + _escape(mx_status) + "</td></tr>")
        for pref, host in valid_mx[:10]:
            parts.append(f"<tr><td></td><td>{pref} <code>{_escape(host)}</code></td></tr>")
        if len(valid_mx) > 10:
            parts.append("<tr><td></td><td>...</td></tr>")
    else:
        parts.append("<tr><td><strong>MX</strong></td><td>No valid hostname (status: " + _escape(mx_status) + ")</td></tr>")
    # SPF
    spf = d.get("spf_record")
    spf_status = d.get("spf_status", "?")
    if spf:
        snippet = (spf[:120] + "..." if len(spf) > 120 else spf)
        parts.append("<tr><td><strong>SPF</strong></td><td>Present (" + _escape(spf_status) + "). <code>" + _escape(snippet) + "</code></td></tr>")
    else:
        parts.append("<tr><td><strong>SPF</strong></td><td>Not found (" + _escape(spf_status) + ")</td></tr>")
    # DMARC
    dmarc = d.get("dmarc_record")
    dmarc_parsed = d.get("dmarc_parsed") or {}
    dmarc_status = d.get("dmarc_status", "?")
    policy = dmarc_parsed.get("policy", "?") if dmarc else "—"
    if dmarc:
        parts.append("<tr><td><strong>DMARC</strong></td><td>Present (" + _escape(dmarc_status) + "). Policy: <code>p=" + _escape(policy) + "</code></td></tr>")
    else:
        parts.append("<tr><td><strong>DMARC</strong></td><td>Not found (" + _escape(dmarc_status) + ")</td></tr>")
    # DKIM: count only here; full list in separate section
    dkim = d.get("dkim_selectors", [])
    parts.append("<tr><td><strong>DKIM</strong></td><td>" + str(len(dkim)) + " selector(s) found (see DKIM Selectors section)</td></tr>")
    # BIMI
    bimi = d.get("bimi_record")
    parts.append("<tr><td><strong>BIMI</strong></td><td>" + ("Present" if bimi else "Not found") + "</td></tr>")
    # SMTP
    e = s.get("smtp_enum", {})
    mx_host = e.get("mx_host_used", "")
    parts.append("<tr><td><strong>SMTP host</strong></td><td><code>" + _escape(mx_host) + "</code></td></tr>")
    if e.get("error"):
        parts.append("<tr><td><strong>SMTP connection</strong></td><td>Failed: " + _escape(str(e.get("error"))[:80]) + "</td></tr>")
    else:
        banner = e.get("banner") or ""
        parts.append("<tr><td><strong>Banner</strong></td><td><code>" + _escape((banner[:100] + "..." if len(banner) > 100 else banner)) + "</code></td></tr>")
        if e.get("platform_hint"):
            parts.append("<tr><td><strong>Platform hint</strong></td><td>" + _escape(e.get("platform_hint")) + "</td></tr>")
        st = s.get("starttls", {})
        parts.append("<tr><td><strong>STARTTLS</strong></td><td>" + ("Yes" if st.get("supported") else "No") + (" (" + _escape(st.get("error") or "") + ")" if st.get("error") else "") + "</td></tr>")
        tls = s.get("tls_analysis", {})
        if tls.get("protocol"):
            parts.append("<tr><td><strong>TLS version</strong></td><td>" + _escape(tls.get("protocol", "")) + "</td></tr>")
    return "\n".join(parts)


def _dkim_selectors_html(ctx: ScanContext) -> str:
    dkim = ctx.dns_data.get("dkim_selectors", [])
    if not dkim:
        return "<p>No DKIM selectors discovered.</p>"
    rows = []
    for sel in dkim:
        selector = _escape(sel.get("selector", ""))
        record = (sel.get("record") or "")[:150]
        if len(sel.get("record") or "") > 150:
            record += "..."
        record = _escape(record)
        rows.append(f"<tr><td><code>{selector}</code></td><td><code>{record}</code></td></tr>")
    return "<table class=\"tbl\"><thead><tr><th>Selector</th><th>Record (snippet)</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def _open_relay_summary_html(ctx: ScanContext) -> str:
    r = ctx.smtp_data.get("open_relay", {})
    likely = r.get("relay_likely", False)
    mail_code = r.get("mail_from_code", "—")
    rcpt_code = r.get("rcpt_to_code", "—")
    err = r.get("error")
    status = "Open relay likely (RCPT TO accepted without AUTH)" if likely else "Open relay not detected"
    status_class = "relay-warn" if likely else "relay-ok"
    parts = [f"<p class=\"relay-summary {status_class}\"><strong>Result:</strong> {_escape(status)}</p>"]
    parts.append("<table class=\"tbl\"><tr><th>MAIL FROM code</th><th>RCPT TO code</th><th>Error</th></tr>")
    parts.append(f"<tr><td>{_escape(str(mail_code))}</td><td>{_escape(str(rcpt_code))}</td><td>{_escape(str(err) if err else '—')}</td></tr></table>")
    return "\n".join(parts)


def _tls_security_html(ctx: ScanContext) -> str:
    tls = ctx.smtp_data.get("tls_analysis", {})
    weak_proto = tls.get("weak_protocol", False)
    weak_cipher = tls.get("weak_cipher_hint", False)
    findings_tls = [f for f in ctx.findings if f.get("category") == "TLS" or f.get("id", "").startswith("tls_")]
    if not weak_proto and not weak_cipher and not findings_tls:
        return "<p class=\"tls-ok\">No TLS security issues detected. Protocol and cipher appear adequate.</p>"
    parts = ['<div class="tls-alert">']
    parts.append("<p><strong>TLS security issues detected</strong></p><ul>")
    if weak_proto:
        parts.append("<li>Weak or deprecated TLS protocol: " + _escape(str(tls.get("protocol", "?"))) + " — upgrade to TLS 1.2+.</li>")
    if weak_cipher:
        parts.append("<li>Weak cipher suite possible: " + _escape(str(tls.get("cipher", "?"))) + " — disable NULL/EXP/DES/RC4.</li>")
    for f in findings_tls:
        parts.append("<li>" + _escape(f.get("title", "")) + ": " + _escape(f.get("description", "")[:120]) + "</li>")
    parts.append("</ul><p>Recommendation: Enforce TLS 1.2 or 1.3 and strong AEAD ciphers only.</p></div>")
    return "\n".join(parts)


def _ptr_results_html(ctx: ScanContext) -> str:
    ptr_list = ctx.dns_data.get("ptr_results", [])
    if not ptr_list:
        return "<p>No PTR (reverse DNS) data collected.</p>"
    rows = []
    for r in ptr_list:
        mx = _escape(r.get("mx_host", ""))
        ip = _escape(r.get("ip", ""))
        ptr = r.get("ptr", [])
        status = _escape(r.get("ptr_status", "?"))
        ptr_str = ", ".join(_escape(p) for p in ptr[:3]) if ptr else "—"
        if len(ptr) > 3:
            ptr_str += " …"
        rows.append(f"<tr><td><code>{mx}</code></td><td><code>{ip}</code></td><td>{ptr_str}</td><td>{status}</td></tr>")
    return "<table class=\"tbl\"><thead><tr><th>MX host</th><th>IP</th><th>PTR</th><th>Status</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def _smtp_ports_html(ctx: ScanContext) -> str:
    e = ctx.smtp_data.get("smtp_enum", {})
    p25_open = not e.get("error") and bool(e.get("banner"))
    p25_note = ("Banner: " + _escape((e.get("banner") or "")[:80])) if e.get("banner") else (_escape(str(e.get("error", "—"))[:80]))
    p465 = e.get("port_465", {})
    p587 = e.get("port_587", {})
    rows = [
        f"<tr><td>25</td><td>{'Open' if p25_open else 'Closed'}</td><td><code>{p25_note}</code></td></tr>",
        f"<tr><td>465 (SMTPS)</td><td>{'Open' if p465.get('open') else 'Closed'}</td><td><code>{_escape((p465.get('banner') or p465.get('error') or '—')[:80])}</code></td></tr>",
        f"<tr><td>587 (Submission)</td><td>{'Open' if p587.get('open') else 'Closed'}</td><td><code>{_escape((p587.get('banner') or p587.get('error') or '—')[:80])}</code></td></tr>",
    ]
    return "<table class=\"tbl\"><thead><tr><th>Port</th><th>Status</th><th>Banner / note</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def _help_response_html(ctx: ScanContext) -> str:
    help_lines = (ctx.smtp_data.get("smtp_enum") or {}).get("help_response", [])
    if not help_lines:
        return "<p>HELP response not collected or empty.</p>"
    escaped = [_escape(line) for line in help_lines[:20]]
    return "<pre class=\"tbl\" style=\"padding:1rem;overflow:auto;\">" + "\n".join(escaped) + "</pre>"


def _catch_all_html(ctx: ScanContext) -> str:
    c = ctx.smtp_data.get("catch_all_check", {})
    likely = c.get("catch_all_likely", False)
    code = c.get("rcpt_code", "—")
    msg = _escape((c.get("rcpt_message") or "")[:100])
    addr = _escape(c.get("test_address", ""))
    status = "Catch-all likely (RCPT TO accepted for non-existent local part)" if likely else "Catch-all not detected"
    cls = "relay-warn" if likely else "relay-ok"
    return f"<p class=\"relay-summary {cls}\"><strong>Result:</strong> {_escape(status)}</p><p class=\"meta\">Test address: <code>{addr}</code> — Code: {_escape(str(code))} — {msg}</p>"


def _null_sender_relay_html(ctx: ScanContext) -> str:
    r = ctx.smtp_data.get("open_relay", {})
    likely = r.get("null_sender_relay_likely", False)
    mail_code = r.get("null_sender_mail_from_code", "—")
    rcpt_code = r.get("null_sender_rcpt_to_code", "—")
    status = "Null sender relay likely (MAIL FROM:&lt;&gt; + RCPT TO accepted)" if likely else "Null sender relay not detected"
    cls = "relay-warn" if likely else "relay-ok"
    parts = [f"<p class=\"relay-summary {cls}\"><strong>Result:</strong> {_escape(status)}</p>"]
    parts.append("<table class=\"tbl\"><tr><th>MAIL FROM:&lt;&gt; code</th><th>RCPT TO code</th></tr>")
    parts.append(f"<tr><td>{_escape(str(mail_code))}</td><td>{_escape(str(rcpt_code))}</td></tr></table>")
    return "\n".join(parts)


def _certificate_html(ctx: ScanContext) -> str:
    tls = ctx.smtp_data.get("tls_analysis", {})
    cert = tls.get("certificate") or {}
    if not cert:
        return "<p>Certificate not collected (STARTTLS failed or not supported).</p>"
    parts = []
    for key in ("subject", "issuer"):
        d = cert.get(key) or {}
        if isinstance(d, dict) and d:
            parts.append(f"<p><strong>{key.title()}:</strong> " + ", ".join(f"{_escape(k)}={_escape(str(v))}" for k, v in list(d.items())[:5]) + "</p>")
    for key in ("notBefore", "notAfter"):
        val = cert.get(key)
        if val:
            parts.append(f"<p><strong>{key}:</strong> <code>{_escape(str(val))}</code></p>")
    return "\n".join(parts) if parts else "<p>No certificate details.</p>"


def _dkim_key_length_html(ctx: ScanContext) -> str:
    dkim = ctx.dns_data.get("dkim_selectors", [])
    if not dkim:
        return "<p>No DKIM selectors.</p>"
    rows = []
    for sel in dkim:
        name = _escape(sel.get("selector", ""))
        bits = sel.get("public_key_bits")
        weak = sel.get("weak_key", False)
        if bits is not None:
            row = f"<tr><td><code>{name}</code></td><td>~{bits} bits</td><td><span class=\"badge {'sev-medium' if weak else 'sev-none'}\">{'Weak' if weak else 'OK'}</span></td></tr>"
        else:
            row = f"<tr><td><code>{name}</code></td><td>—</td><td>—</td></tr>"
        rows.append(row)
    return "<table class=\"tbl\"><thead><tr><th>Selector</th><th>Public key (approx)</th><th>Status</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def _open_relay_advanced_html(ctx: ScanContext) -> str:
    adv = ctx.smtp_data.get("open_relay_advanced", {})
    backup = adv.get("backup_mx_relays", [])
    internal = adv.get("internal_domain_relay_likely", False)
    ip_hints = adv.get("ip_trust_hints", [])
    pipelining = adv.get("pipelining") or {}
    parts = []
    if backup:
        parts.append("<p><strong>Backup MX relay tests:</strong></p><table class=\"tbl\"><thead><tr><th>Host</th><th>Preference</th><th>Relay likely</th><th>MAIL FROM</th><th>RCPT TO</th></tr></thead><tbody>")
        for r in backup:
            parts.append("<tr><td><code>{0}</code></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>".format(
                _escape(r.get("host", "")),
                r.get("preference", "—"),
                "Yes" if r.get("relay_likely") else "No",
                _escape(str(r.get("mail_from_code", "—"))),
                _escape(str(r.get("rcpt_to_code", "—"))),
            ))
        parts.append("</tbody></table>")
    parts.append("<p><strong>Internal domain trust relay:</strong> " + ("Likely (MAIL FROM target + RCPT TO external accepted)" if internal else "Not detected") + "</p>")
    if ip_hints:
        parts.append("<p class=\"meta\"><strong>IP trust hints in banner/EHLO:</strong> " + _escape("; ".join(ip_hints[:5])) + "</p>")
    parts.append("<p><strong>Pipelining:</strong> RCPT TO code " + _escape(str(pipelining.get("rcpt_to_code", "—"))) + (" (accepted)" if pipelining.get("pipeline_accepted") else " (not accepted)") + "</p>")
    return "\n".join(parts) if parts else "<p>No advanced relay data.</p>"


def _mail_ecosystem_html(ctx: ScanContext) -> str:
    d = ctx.smtp_data.get("mail_service_discovery", {})
    ports = d.get("ports", {})
    if not ports:
        return "<p>No mail protocol discovery data.</p>"
    rows = []
    for name, v in ports.items():
        open_ = v.get("open", False)
        banner = (v.get("banner") or v.get("error") or "—")[:60]
        rows.append(f"<tr><td><code>{_escape(name)}</code></td><td>{'Open' if open_ else 'Closed'}</td><td><code>{_escape(str(banner))}</code></td></tr>")
    out = "<table class=\"tbl\"><thead><tr><th>Port / Service</th><th>Status</th><th>Banner / note</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"
    webmail = d.get("webmail")
    if webmail and webmail.get("detected"):
        out += "<p><strong>Webmail detected:</strong> " + ", ".join(_escape(x.get("product", "")) + (" " + (x.get("version") or "")) for x in webmail.get("detected", [])) + "</p>"
    return out


def _spf_bypass_html(ctx: ScanContext) -> str:
    bypass = ctx.dns_data.get("spf_bypass", {})
    if not bypass:
        return "<p>No SPF bypass analysis data.</p>"
    parts = ["<ul>"]
    if bypass.get("spf_plus_all"):
        parts.append("<li class=\"relay-warn\"><strong>+all:</strong> SPF policy allows any sender (CRITICAL).</li>")
    if bypass.get("spf_softfail"):
        parts.append("<li><strong>~all:</strong> SPF softfail (HIGH).</li>")
    if bypass.get("spf_neutral"):
        parts.append("<li><strong>?all:</strong> SPF neutral (MEDIUM).</li>")
    if bypass.get("spf_lookup_over_10"):
        parts.append("<li><strong>Lookup limit:</strong> SPF may exceed 10 DNS lookups (permerror risk).</li>")
    if bypass.get("dmarc_p_none"):
        parts.append("<li><strong>DMARC p=none:</strong> Monitoring only; no enforcement.</li>")
    if bypass.get("spf_only_no_dkim_dmarc"):
        parts.append("<li class=\"relay-warn\"><strong>From header spoofing:</strong> SPF only; no DKIM/DMARC.</li>")
    sub = bypass.get("subdomain_no_spf", [])
    if sub:
        parts.append("<li><strong>Subdomains without SPF:</strong> " + _escape(", ".join(sub[:5])) + "</li>")
    parts.append("</ul>")
    return "\n".join(parts)


def _rbl_section_html(ctx: ScanContext) -> str:
    """RBL/DNSBL blacklist check: SMTP IPs tested against global blacklists; per-IP, per-RBL results and reputation score."""
    rbl = ctx.smtp_data.get("rbl_check", {})
    if not rbl:
        return "<p>No RBL/DNSBL data (no SMTP IPs to test or check skipped).</p>"
    summary = rbl.get("summary", {})
    by_ip = rbl.get("by_ip", {})
    zones = rbl.get("rbl_zones", [])
    total_ips = summary.get("total_ips", 0)
    ips_listed = summary.get("ips_listed_count", 0)
    any_listed = summary.get("any_listed", False)

    parts = []
    parts.append(f"<p><strong>Summary:</strong> {total_ips} SMTP IP(s) tested against {len(zones)} RBL zone(s). "
                 f"IPs listed on at least one blacklist: <strong>{ips_listed}</strong>.</p>")
    if any_listed:
        parts.append('<p class="relay-warn"><strong>Info security:</strong> Listed IPs indicate reputation abuse or compromised relay risk; '
                     'outbound mail may be rejected or marked as spam; correlation with DMARC/SPF delivery failure possible.</p>')

    for ip, data in by_ip.items():
        host = data.get("host", ip)
        source = data.get("source", "mx")
        score = data.get("reputation_score", 0.0)
        listed_count = data.get("listed_count", 0)
        total_checked = data.get("total_checked", 0)
        score_pct = int(round(score * 100))
        score_cls = "relay-warn" if score >= 0.25 else "relay-ok"
        parts.append(f'<h3>IP {_escape(ip)} — {_escape(host)} (source: {source})</h3>')
        parts.append(f'<p class="{score_cls}"><strong>Reputation score:</strong> {score:.2f} ({score_pct}%) — '
                     f'listed on {listed_count} of {total_checked} RBL(s).</p>')
        results = data.get("results", {})
        if results:
            parts.append('<table class="tbl"><thead><tr><th>RBL zone</th><th>Status</th><th>Listed</th><th>Response / note</th></tr></thead><tbody>')
            for zone_name, res in results.items():
                status = res.get("status", "—")
                listed = "Yes" if res.get("listed") else "No"
                resp = res.get("response") or res.get("message") or "—"
                row_cls = ' class="relay-warn"' if res.get("listed") else ""
                parts.append(f'<tr{row_cls}><td><code>{_escape(zone_name)}</code></td><td>{_escape(status)}</td>'
                             f'<td>{listed}</td><td><code>{_escape(str(resp)[:80])}</code></td></tr>')
            parts.append("</tbody></table>")
    return "\n".join(parts)


def _gateway_detection_html(ctx: ScanContext) -> str:
    g = ctx.smtp_data.get("gateway_detection", {})
    detected = g.get("detected", [])
    if not detected:
        return "<p>No known SMTP gateway or spam protection signature detected in banner (banner did not match known products).</p>"
    parts = ["<p>The following product(s) may be in front of the mail server (detected from banner):</p><ul>"]
    for item in detected:
        product = _escape(item.get("product", item.get("signature", "")))
        parts.append(f"<li><strong>{product}</strong></li>")
    parts.append("</ul>")
    if g.get("banner_snippet"):
        parts.append("<p class=\"meta\">Banner snippet: <code>" + _escape(g["banner_snippet"][:150]) + "</code></p>")
    return "\n".join(parts)


def _findings_html(ctx: ScanContext) -> str:
    if not ctx.findings:
        return "<p>No findings.</p>"
    cards = []
    for f in ctx.findings:
        cvss = f.get("cvss") or {}
        sev = cvss.get("severity", "N/A")
        score = cvss.get("base_score", "N/A")
        title = _escape(f.get("title", "Finding"))
        desc = _escape(f.get("description", ""))
        evidence = _escape((f.get("evidence") or "")[:300])
        attack = _escape((f.get("attack_scenario") or "")[:300])
        impact = _escape((f.get("business_impact") or "")[:300])
        rec = _escape(f.get("recommendation") or "")
        exploitability = f.get("exploitability", False)
        proof = _escape((f.get("proof_of_execution") or "")[:400])
        sev_cls = _severity_class(sev)
        exploit_row = ""
        if exploitability or proof:
            exploit_row = f"    <dt>Exploitability</dt><dd>{'Yes (PoC executed)' if exploitability else 'No'}</dd>\n    <dt>Proof of execution</dt><dd><code>{proof or '—'}</code></dd>\n"
        affected = f.get("affected_service")
        vector = f.get("attack_vector")
        chained = f.get("chained_risk")
        auth_tag = f.get("authenticated", False)
        chain_role = f.get("attack_chain_role")
        adv_row = ""
        if affected or vector or chained or chain_role:
            adv_row = "    <dt>Affected service</dt><dd>" + _escape(affected or "—") + "</dd>\n"
            if vector:
                adv_row += "    <dt>Attack vector</dt><dd>" + _escape(vector) + "</dd>\n"
            if chained:
                adv_row += "    <dt>Chained risk</dt><dd>" + _escape((chained or "")[:400]) + "</dd>\n"
            if chain_role:
                adv_row += "    <dt>Attack chain role</dt><dd>" + _escape((chain_role or "")[:400]) + "</dd>\n"
        if auth_tag:
            adv_row += "    <dt>Authenticated test</dt><dd>Yes</dd>\n"
        cards.append(f"""
<div class="finding-card">
  <div class="finding-header">
    <span class="finding-title">{title}</span>
    <span class="badge {sev_cls}">CVSS {score} — {sev}</span>
  </div>
  <p class="finding-desc">{desc}</p>
  <dl class="finding-details">
    <dt>Evidence</dt><dd><code>{evidence or '—'}</code></dd>
    <dt>Attack scenario</dt><dd>{attack or '—'}</dd>
    <dt>Business impact</dt><dd>{impact or '—'}</dd>
{exploit_row}{adv_row}    <dt>Recommendation</dt><dd>{rec or '—'}</dd>
  </dl>
</div>""")
    return "\n".join(cards)


def _credential_tests_section_html(ctx: ScanContext) -> str:
    """Full Credential-aware tests section: test email, login status, reuse, TLS risk, spoof PoC."""
    if not getattr(ctx, "credential_aware", False):
        return ""
    email = _escape((ctx.test_email or "").strip())
    login_ok = _credential_login_success(ctx)
    login_status = "Succeeded" if login_ok else "Failed"
    login_class = "relay-ok" if login_ok else "relay-warn"
    reuse = ctx.smtp_data.get("credential_reuse", {})
    protocols = reuse.get("protocols_accepting_credential", [])
    tls_risk = ctx.smtp_data.get("credential_tls_risk", {})
    plain_ok = tls_risk.get("plain_auth_accepted", False)
    spoof = ctx.smtp_data.get("credential_auth_spoof", {})
    spoof_ok = spoof.get("exploit_success", False)

    rows = []
    for name, accepted in [
        ("SMTP AUTH (587)", reuse.get("smtp_auth_587", False)),
        ("SMTP AUTH (25+STARTTLS)", reuse.get("smtp_auth_25_starttls", False)),
        ("POP3 (110)", reuse.get("pop3_110", False)),
        ("POP3S (995)", reuse.get("pop3s_995", False)),
        ("IMAP (143)", reuse.get("imap_143", False)),
        ("IMAPS (993)", reuse.get("imaps_993", False)),
    ]:
        cell = "Yes" if accepted else "No"
        rows.append(f"<tr><td>{_escape(name)}</td><td>{cell}</td></tr>")
    table_reuse = "<table class=\"tbl\"><thead><tr><th>Protocol</th><th>Credential accepted</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>" if rows else "<p>No credential reuse data.</p>"

    return f"""
<h2>Credential-aware tests</h2>
<p><strong>Test mailbox:</strong> <code>{email}</code></p>
<p class="relay-summary {login_class}"><strong>Login status:</strong> {login_status}. {"At least one protocol accepted the credentials." if login_ok else "No protocol (SMTP AUTH, POP3, IMAP) accepted the provided --email and --password. Check credentials and server availability."}</p>
<h3>Credential reuse (same account on multiple protocols)</h3>
{table_reuse}
<h3>TLS / plain auth risk</h3>
<p><strong>Plain authentication accepted (no STARTTLS):</strong> {"Yes — credentials could be sent in cleartext." if plain_ok else "No"}</p>
<h3>Authenticated From / Display name PoC</h3>
<p><strong>Result:</strong> {"Success — server accepted mail with From/display name manipulation (PoC sent only to test account)." if spoof_ok else "Failed or not attempted (e.g. login failed)."}</p>
"""

def _exploit_result_status(result: str) -> str:
    """Map audit result to success/failure only for Detail column."""
    if result in ("success", "pipelining_accepted"):
        return "Success"
    return "Failed"


def _exploit_audit_html(ctx: ScanContext) -> str:
    if not getattr(ctx, "attack_mode", False) or not ctx.exploit_audit_log:
        return "<p>No exploit phase was run (SAFE MODE) or no audit entries.</p>"
    rows = []
    for e in ctx.exploit_audit_log[-30:]:
        result = e.get("result", "")
        detail_status = _exploit_result_status(result)
        rows.append("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td><code>{3}</code></td></tr>".format(
            _escape(e.get("module", "")),
            _escape(e.get("action", "")),
            _escape(result),
            _escape(detail_status),
        ))
    return "<table class=\"tbl\"><thead><tr><th>Module</th><th>Action</th><th>Result</th><th>Detail</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def _risk_matrix_html(ctx: ScanContext) -> str:
    by_sev = {}
    for f in ctx.findings:
        sev = (f.get("cvss") or {}).get("severity", "Unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    rows = []
    for label in ["Critical", "High", "Medium", "Low", "None", "Unknown"]:
        count = by_sev.get(label, 0)
        if count > 0:
            rows.append(f"<tr><td><span class=\"badge {_severity_class(label)}\">{label}</span></td><td>{count}</td></tr>")
    if not rows:
        return "<p>No findings.</p>"
    return "<table class=\"tbl\"><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def _mitre_html(ctx: ScanContext) -> str:
    if not ctx.findings:
        return "<p>No findings.</p>"
    rows = []
    for f in ctx.findings:
        title = _escape((f.get("title") or "—")[:40])
        mitre = f.get("mitre") or []
        if not mitre:
            rows.append(f"<tr><td>{title}</td><td>—</td><td>—</td><td>—</td></tr>")
        else:
            for m in mitre:
                rows.append(f"<tr><td>{title}</td><td>{_escape(m.get('tactic', ''))}</td><td>{_escape(m.get('technique_id', ''))}</td><td>{_escape(m.get('technique', ''))}</td></tr>")
    return "<table class=\"tbl\"><thead><tr><th>Finding</th><th>Tactic</th><th>Technique ID</th><th>Technique</th></tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"


def generate(ctx: ScanContext) -> str:
    """Generate HTML report; return path to saved file. Uses ctx.output_dir if set. Filename includes UTC timestamp."""
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
    out_path = os.path.join(out_dir, f"mailt_report_{safe_domain}_{timestamp}.html")

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MailT — Email Security Report: {_escape(ctx.target_domain)}</title>
<style>
:root {{
  --bg: #0f172a;
  --card: #1e293b;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --green: #22c55e;
  --amber: #f59e0b;
  --red: #ef4444;
  --critical: #dc2626;
}}
* {{ box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--text); line-height: 1.6; min-height: 100vh; }}
.container {{ max-width: 920px; margin: 0 auto; padding: 1.5rem; }}
header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 2rem; border-radius: 12px; margin-bottom: 2rem; border: 1px solid #334155; }}
header h1 {{ margin: 0 0 0.5rem; font-size: 1.75rem; color: #fff; }}
header .meta {{ color: var(--muted); font-size: 0.95rem; }}
header code {{ background: rgba(56,189,248,0.2); color: var(--accent); padding: 0.2rem 0.5rem; border-radius: 4px; }}
h2 {{ font-size: 1.2rem; color: var(--accent); margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #334155; }}
.tbl {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card); border-radius: 8px; overflow: hidden; }}
.tbl th, .tbl td {{ border: 1px solid #334155; padding: 0.65rem 1rem; text-align: left; }}
.tbl th {{ background: #334155; color: #fff; font-weight: 600; }}
.tbl code {{ background: rgba(0,0,0,0.3); padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.9em; }}
.badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 6px; font-size: 0.85rem; font-weight: 600; }}
.sev-critical {{ background: #7f1d1d; color: #fecaca; }}
.sev-high {{ background: #7c2d12; color: #fed7aa; }}
.sev-medium {{ background: #713f12; color: #fde68a; }}
.sev-low {{ background: #374151; color: #d1d5db; }}
.sev-none {{ background: #334155; color: #94a3b8; }}
.finding-card {{ background: var(--card); border: 1px solid #334155; border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem; }}
.finding-header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem; }}
.finding-title {{ font-weight: 600; font-size: 1.05rem; }}
.finding-desc {{ margin: 0 0 1rem; color: var(--muted); }}
.finding-details {{ margin: 0; }}
.finding-details dt {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.5rem; }}
.finding-details dd {{ margin: 0.25rem 0 0; }}
.relay-summary {{ padding: 0.75rem 1rem; border-radius: 8px; margin: 1rem 0; }}
.relay-ok {{ background: rgba(34,197,94,0.15); border: 1px solid var(--green); color: #86efac; }}
.relay-warn {{ background: rgba(239,68,68,0.2); border: 1px solid var(--red); color: #fca5a5; }}
.tls-alert {{ background: rgba(239,68,68,0.15); border: 1px solid var(--red); border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
.tls-alert ul {{ margin: 0.5rem 0; padding-left: 1.5rem; }}
.tls-ok {{ background: rgba(34,197,94,0.1); border: 1px solid var(--green); border-radius: 8px; padding: 1rem; color: #86efac; }}
.meta {{ color: var(--muted); font-size: 0.9rem; }}
footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #334155; color: var(--muted); font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>MailT — Email Security Report</h1>
  <p class="meta">Target: <code>{_escape(ctx.target_domain)}</code> &nbsp;|&nbsp; Scan date: {_escape(scan_date)} &nbsp;|&nbsp; Findings: <strong>{len(ctx.findings)}</strong> &nbsp;|&nbsp; Mode: <strong>{'ATTACK (exploit PoC)' if getattr(ctx, 'attack_mode', False) else 'SAFE'}</strong></p>
</header>

<h2>Executive Summary</h2>
<p>This report summarizes the email security posture of the target domain based on anonymous DNS and SMTP checks. {_executive_summary_mode_text(ctx)}</p>

<h2>Scope</h2>
<p>Single mail domain. Methodology: passive DNS enumeration and anonymous SMTP/TLS checks.{_scope_credential_text(ctx)}</p>

<h2>Scan Results</h2>
<p>Data collected during the scan:</p>
<table class="tbl">
{_scan_results_html(ctx)}
</table>

<h2>DNS PTR / Reverse DNS</h2>
{_ptr_results_html(ctx)}

<h2>DKIM Selectors (full list)</h2>
{_dkim_selectors_html(ctx)}

<h2>DKIM Public Key Length</h2>
{_dkim_key_length_html(ctx)}

<h2>SMTP Port Discovery (25, 465, 587)</h2>
{_smtp_ports_html(ctx)}

<h2>SMTP HELP Response</h2>
{_help_response_html(ctx)}

<h2>Open Relay Test — Summary</h2>
{_open_relay_summary_html(ctx)}

<h2>Null Sender Relay (MAIL FROM:&lt;&gt;)</h2>
{_null_sender_relay_html(ctx)}

<h2>Catch-All Domain Check</h2>
{_catch_all_html(ctx)}

<h2>Advanced Open Relay (Backup MX, Internal Trust, Pipelining)</h2>
{_open_relay_advanced_html(ctx)}

<h2>Mail Ecosystem (SMTP/POP3/IMAP/Webmail)</h2>
{_mail_ecosystem_html(ctx)}

<h2>RBL / DNSBL Blacklist Results</h2>
{_rbl_section_html(ctx)}

<h2>SPF Bypass &amp; Policy Analysis</h2>
{_spf_bypass_html(ctx)}

<h2>TLS Security</h2>
{_tls_security_html(ctx)}

<h2>TLS Certificate</h2>
{_certificate_html(ctx)}

<h2>SMTP Gateway / Spam Protection</h2>
{_gateway_detection_html(ctx)}

<h2>Exploit / PoC Audit (ATTACK MODE)</h2>
{_exploit_audit_html(ctx)}

{_credential_tests_section_html(ctx)}

<h2>Findings (detailed)</h2>
{_findings_html(ctx)}

<h2>Risk Matrix</h2>
{_risk_matrix_html(ctx)}

<h2>MITRE ATT&amp;CK Mapping</h2>
{_mitre_html(ctx)}

<h2>Action Plan</h2>
<ol>
<li>Address all Critical and High findings.</li>
<li>Implement DMARC p=reject and SPF -all where applicable.</li>
<li>Enforce STARTTLS and disable weak TLS/ciphers.</li>
<li>Monitor DMARC/SPF/DKIM and TLS configuration.</li>
</ol>

<h2>Conclusion</h2>
<p>Remediate high and critical findings first; then strengthen policy and TLS.</p>

<footer>
MailT — Email Security Analysis Framework. Anonymous scan only.<br>
Developed by <a href="https://www.linkedin.com/in/cuma-kurt-34414917/" target="_blank" rel="noopener">Cuma KURT</a> — <a href="mailto:cumakurt@gmail.com">cumakurt@gmail.com</a> | <a href="https://github.com/cumakurt/mailt" target="_blank" rel="noopener">GitHub</a>
</footer>
</div>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return out_path
