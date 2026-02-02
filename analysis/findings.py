"""
Normalize raw DNS/SMTP data into structured findings for CVSS and MITRE.
"""
import logging
from core.context import ScanContext

logger = logging.getLogger("mailt.analysis")

# Statuses that mean "query succeeded, result is definitive"
DNS_DEFINITIVE_STATUS = ("ok", "empty")

FINDING_IDS = {
    "DNS_NO_MX": "dns_no_mx",
    "DNS_MX_INCONCLUSIVE": "dns_mx_inconclusive",
    "DNS_NO_SPF": "dns_no_spf",
    "DNS_SPF_INCONCLUSIVE": "dns_spf_inconclusive",
    "SPF_SOFTFAIL": "spf_softfail",
    "SPF_PLUS_ALL": "spf_plus_all",
    "SPF_NEUTRAL": "spf_neutral",
    "SPF_LOOKUP_LIMIT": "spf_lookup_limit",
    "DNS_NO_DMARC": "dns_no_dmarc",
    "DNS_DMARC_INCONCLUSIVE": "dns_dmarc_inconclusive",
    "DMARC_POLICY_NONE": "dmarc_policy_none",
    "DMARC_POLICY_QUARANTINE": "dmarc_policy_quarantine",
    "DNS_NO_DKIM": "dns_no_dkim",
    "DKIM_WEAK_KEY": "dkim_weak_key",
    "DNS_NO_BIMI": "dns_no_bimi",
    "SPF_BYPASS_HEADER_SPOOFING": "spf_bypass_header_spoofing",
    "SPF_BYPASS_SUBDOMAIN_NO_SPF": "spf_bypass_subdomain_no_spf",
    "SMTP_BANNER_DISCLOSURE": "smtp_banner_disclosure",
    "SMTP_NO_STARTTLS": "smtp_no_starttls",
    "SMTP_VRFY_ENABLED": "smtp_vrfy_enabled",
    "SMTP_EXPN_ENABLED": "smtp_expn_enabled",
    "SMTP_OPEN_RELAY": "smtp_open_relay",
    "SMTP_NULL_SENDER_RELAY": "smtp_null_sender_relay",
    "SMTP_BACKUP_MX_RELAY": "smtp_backup_mx_relay",
    "SMTP_INTERNAL_DOMAIN_RELAY": "smtp_internal_domain_relay",
    "SMTP_IP_TRUST_MISCONFIG": "smtp_ip_trust_misconfig",
    "SMTP_PIPELINING_ACCEPTED": "smtp_pipelining_accepted",
    "SMTP_CATCH_ALL": "smtp_catch_all",
    "SMTP_AUTH_WITHOUT_STARTTLS": "smtp_auth_without_starttls",
    "TLS_WEAK_PROTOCOL": "tls_weak_protocol",
    "TLS_WEAK_CIPHER": "tls_weak_cipher",
    "POP3_PLAIN_ACTIVE": "pop3_plain_active",
    "POP3_NO_RATE_LIMIT": "pop3_no_rate_limit",
    "IMAP_PLAIN_ACTIVE": "imap_plain_active",
    "IMAP_NO_RATE_LIMIT": "imap_no_rate_limit",
    "CROSS_PROTOCOL_CREDENTIAL_REUSE": "cross_protocol_credential_reuse",
    "WEBMAIL_VERSION_DISCLOSED": "webmail_version_disclosed",
    "WEBMAIL_INSECURE_COOKIES": "webmail_insecure_cookies",
    "MAIL_ACCOUNT_TAKEOVER_CHAIN": "mail_account_takeover_chain",
    "CREDENTIAL_REUSE_MULTI_PROTOCOL": "credential_reuse_multi_protocol",
    "CREDENTIAL_PLAIN_AUTH_ACCEPTED": "credential_plain_auth_accepted",
    "CREDENTIAL_AUTHENTICATED_SPOOF": "credential_authenticated_spoof",
    "RBL_IP_LISTED": "rbl_ip_listed",
    "RBL_REPUTATION_RISK": "rbl_reputation_risk",
}


def _finding(
    finding_id: str,
    title: str,
    category: str,
    severity_hint: str,
    description: str,
    attack_scenario: str,
    business_impact: str,
    evidence: str = "",
    recommendation: str = "",
    exploitability: bool = False,
    proof_of_execution: str | None = None,
    affected_service: str | None = None,
    attack_vector: str | None = None,
    chained_risk: str | None = None,
    authenticated: bool = False,
    attack_chain_role: str | None = None,
) -> dict:
    return {
        "id": finding_id,
        "title": title,
        "category": category,
        "severity_hint": severity_hint,
        "description": description,
        "attack_scenario": attack_scenario,
        "business_impact": business_impact,
        "evidence": evidence,
        "recommendation": recommendation,
        "exploitability": exploitability,
        "proof_of_execution": proof_of_execution,
        "affected_service": affected_service,
        "attack_vector": attack_vector,
        "chained_risk": chained_risk,
        "authenticated": authenticated,
        "attack_chain_role": attack_chain_role,
        "cvss": None,
        "mitre": [],
    }


def _dns_findings(ctx: ScanContext) -> list[dict]:
    findings = []
    d = ctx.dns_data
    domain = ctx.target_domain

    mx_status = d.get("mx_status", "ok")
    mx_list = d.get("mx", [])
    if mx_status in DNS_DEFINITIVE_STATUS and not mx_list:
        findings.append(_finding(
            FINDING_IDS["DNS_NO_MX"],
            "No MX records",
            "DNS",
            "high",
            f"Domain {domain} has no MX records; mail delivery may fail or be unpredictable.",
            "Attacker can target other vectors or spoof domain if SPF/DMARC are also weak.",
            "Mail delivery failure; spoofing risk.",
            evidence="MX query returned no records.",
            recommendation="Publish MX records pointing to mail servers.",
        ))
    elif mx_status in ("timeout", "error"):
        findings.append(_finding(
            FINDING_IDS["DNS_MX_INCONCLUSIVE"],
            "MX check inconclusive",
            "DNS",
            "info",
            f"MX lookup failed ({mx_status}); result may be unreliable. Message: {d.get('mx_message', '')}.",
            "N/A — re-run or check network/DNS.",
            "Inconclusive; manual verification recommended.",
            evidence=f"Status: {mx_status}",
            recommendation="Re-run scan or use alternate DNS; verify MX manually.",
        ))

    spf_status = d.get("spf_status", "ok")
    if spf_status in DNS_DEFINITIVE_STATUS and not d.get("spf_record"):
        findings.append(_finding(
            FINDING_IDS["DNS_NO_SPF"],
            "No SPF record",
            "DNS",
            "medium",
            f"Domain {domain} has no SPF record; any server can claim to send as @{domain}.",
            "Email spoofing (T1566.001); phishing from @{domain}.",
            "Brand abuse; phishing; spam.",
            evidence="No TXT record starting with v=spf1.",
            recommendation="Publish SPF (v=spf1 ... -all or ~all).",
        ))
    elif spf_status in ("timeout", "error") and not d.get("spf_record"):
        findings.append(_finding(
            FINDING_IDS["DNS_SPF_INCONCLUSIVE"],
            "SPF check inconclusive",
            "DNS",
            "info",
            f"SPF lookup failed ({spf_status}); result may be unreliable.",
            "N/A — re-run or check DNS.",
            "Inconclusive; manual verification recommended.",
            evidence=f"Status: {spf_status}",
            recommendation="Re-run scan or verify SPF manually.",
        ))
    else:
        if d.get("spf_all_qualifier") == "+":
            findings.append(_finding(
                FINDING_IDS["SPF_PLUS_ALL"],
                "SPF policy allows any sender (+all)",
                "DNS",
                "critical",
                "SPF uses +all (pass); any server can claim to send as this domain. Exploitable for phishing and spoofing.",
                f"Email spoofing (T1566.001); phishing from @{domain}; no SPF enforcement.",
                "Brand abuse; phishing; spam; infrastructure abuse.",
                evidence="SPF record contains +all or default pass all.",
                recommendation="Replace with -all (hardfail); authorize only known mail servers.",
            ))
        elif d.get("spf_all_qualifier") == "~":
            findings.append(_finding(
                FINDING_IDS["SPF_SOFTFAIL"],
                "SPF softfail (~all)",
                "DNS",
                "high",
                "SPF uses ~all (softfail); failing servers may still be accepted by receivers.",
                "Spoofed mail may be accepted by lenient receivers.",
                "Increased spoofing success rate.",
                evidence="SPF record contains ~all.",
                recommendation="Use -all (hardfail) for strict policy.",
            ))
        elif d.get("spf_all_qualifier") == "?":
            findings.append(_finding(
                FINDING_IDS["SPF_NEUTRAL"],
                "SPF neutral (?all)",
                "DNS",
                "medium",
                "SPF uses ?all (neutral); receivers treat failures as unknown; no clear reject.",
                "Spoofed mail may be accepted; policy is ambiguous.",
                "Weak enforcement; spoofing risk.",
                evidence="SPF record contains ?all.",
                recommendation="Use -all (hardfail) or ~all (softfail) for clear policy.",
            ))
        lookup_count = d.get("spf_lookup_count", 0)
        if lookup_count > 10:
            findings.append(_finding(
                FINDING_IDS["SPF_LOOKUP_LIMIT"],
                "SPF lookup limit risk",
                "DNS",
                "low",
                f"SPF has many DNS lookups (~{lookup_count}); may exceed receiver limit (10) and cause fail-open.",
                "Receivers may treat SPF as pass due to limit; spoofing.",
                "SPF may not enforce as intended.",
                evidence=f"Estimated lookups: {lookup_count}.",
                recommendation="Reduce includes/mechanisms to stay under 10 lookups.",
            ))

    dmarc = d.get("dmarc_record")
    dmarc_status = d.get("dmarc_status", "ok")
    if dmarc_status in DNS_DEFINITIVE_STATUS and not dmarc:
        findings.append(_finding(
            FINDING_IDS["DNS_NO_DMARC"],
            "No DMARC record",
            "DNS",
            "medium",
            f"No DMARC at _dmarc.{domain}; receivers have no policy for failed SPF/DKIM.",
            "Spoofing and phishing without policy enforcement.",
            "No alignment enforcement; spoofing risk.",
            evidence="No v=DMARC1 TXT at _dmarc.",
            recommendation="Publish DMARC (p=quarantine or p=reject).",
        ))
    elif dmarc_status in ("timeout", "error") and not dmarc:
        findings.append(_finding(
            FINDING_IDS["DNS_DMARC_INCONCLUSIVE"],
            "DMARC check inconclusive",
            "DNS",
            "info",
            f"DMARC lookup failed ({dmarc_status}); result may be unreliable.",
            "N/A — re-run or check DNS.",
            "Inconclusive; manual verification recommended.",
            evidence=f"Status: {dmarc_status}",
            recommendation="Re-run scan or verify DMARC manually.",
        ))
    if dmarc:
        policy = (d.get("dmarc_parsed") or {}).get("policy", "none")
        if policy == "none":
            findings.append(_finding(
                FINDING_IDS["DMARC_POLICY_NONE"],
                "DMARC policy none",
                "DNS",
                "medium",
                "DMARC p=none; no action is taken on failing messages.",
                "Spoofing continues to reach inbox.",
                "No enforcement.",
                evidence="p=none in DMARC.",
                recommendation="Use p=quarantine or p=reject.",
            ))
        elif policy == "quarantine":
            findings.append(_finding(
                FINDING_IDS["DMARC_POLICY_QUARANTINE"],
                "DMARC policy quarantine",
                "DNS",
                "low",
                "DMARC p=quarantine; failing messages may go to spam.",
                "Some spoofing may still reach users.",
                "Improved but not strict.",
                evidence="p=quarantine in DMARC.",
                recommendation="Consider p=reject for strictest protection.",
            ))

    if not d.get("dkim_selectors"):
        findings.append(_finding(
            FINDING_IDS["DNS_NO_DKIM"],
            "No DKIM selectors found",
            "DNS",
            "low",
            "No common DKIM selectors discovered; signing may not be advertised.",
            "Receivers cannot verify signatures; DMARC may fail.",
            "Weaker authentication.",
            evidence="No TXT at selector._domainkey.",
            recommendation="Publish DKIM and use common or documented selector.",
        ))
    for sel in d.get("dkim_selectors") or []:
        if sel.get("weak_key") and sel.get("public_key_bits"):
            findings.append(_finding(
                FINDING_IDS["DKIM_WEAK_KEY"],
                "DKIM weak public key",
                "DNS",
                "medium",
                f"DKIM selector '{sel.get('selector', '?')}' uses a short public key (~{sel.get('public_key_bits')} bits); recommend 2048+ bits.",
                "Easier to forge if key is weak; key recovery.",
                "Reduced signature assurance.",
                evidence=f"Selector {sel.get('selector')}: ~{sel.get('public_key_bits')} bits.",
                recommendation="Rotate to 2048-bit or 4096-bit RSA (or Ed25519).",
            ))
            break

    if not d.get("bimi_record"):
        findings.append(_finding(
            FINDING_IDS["DNS_NO_BIMI"],
            "No BIMI record",
            "DNS",
            "info",
            "No BIMI at default._bimi; no brand logo in supported clients.",
            "N/A (branding only).",
            "No logo in supported mail clients.",
            evidence="No v=BIMI1 TXT at default._bimi.",
            recommendation="Optional: add BIMI for verified brand logo.",
        ))

    # SPF bypass / policy analysis (from spf_bypass module)
    bypass = d.get("spf_bypass", {})
    if bypass.get("spf_only_no_dkim_dmarc"):
        findings.append(_finding(
            FINDING_IDS["SPF_BYPASS_HEADER_SPOOFING"],
            "From header spoofing possible (SPF only)",
            "DNS",
            "high",
            "SPF protects only envelope sender; without DKIM/DMARC, From header can be spoofed. Misconfigured controls allow abuse.",
            "Phishing and spoofing using forged From header; receivers may not reject.",
            "Domain impersonation; phishing; abuse.",
            evidence="SPF present; no DKIM selectors; no DMARC.",
            recommendation="Publish DKIM and DMARC (p=quarantine or p=reject); SPF alone does not protect From header.",
        ))
    subdomain_no_spf = bypass.get("subdomain_no_spf", [])
    if subdomain_no_spf:
        findings.append(_finding(
            FINDING_IDS["SPF_BYPASS_SUBDOMAIN_NO_SPF"],
            "Subdomains without SPF record",
            "DNS",
            "medium",
            f"Subdomain(s) {', '.join(subdomain_no_spf[:5])} have no SPF record; subdomain spoofing is exploitable.",
            "Attacker can send as user@subdomain; SPF will not fail for these subdomains.",
            "Subdomain impersonation; phishing.",
            evidence="No v=spf1 at: " + ", ".join(subdomain_no_spf[:5]),
            recommendation="Publish SPF for critical subdomains (mail, hr, smtp) or inherit via include.",
        ))

    return findings


def _smtp_findings(ctx: ScanContext) -> list[dict]:
    findings = []
    if not ctx.run_smtp:
        return findings
    e = ctx.smtp_data.get("smtp_enum", {})
    st = ctx.smtp_data.get("starttls", {})
    tls = ctx.smtp_data.get("tls_analysis", {})
    relay = ctx.smtp_data.get("open_relay", {})
    # Only add SMTP findings when we actually connected (no connection_failed)
    smtp_connected = not e.get("error")

    if smtp_connected and e.get("banner"):
        findings.append(_finding(
            FINDING_IDS["SMTP_BANNER_DISCLOSURE"],
            "SMTP banner disclosure",
            "SMTP",
            "low",
            "SMTP banner reveals server/version; helps attackers fingerprint.",
            "Reconnaissance (T1595); version-specific exploits.",
            "Information disclosure.",
            evidence=e.get("banner", ""),
            recommendation="Use generic banner or restrict access.",
        ))

    if smtp_connected and not st.get("supported") and st.get("error") != "connection_failed":
        findings.append(_finding(
            FINDING_IDS["SMTP_NO_STARTTLS"],
            "STARTTLS not supported or failed",
            "SMTP",
            "high",
            "SMTP does not support STARTTLS or TLS upgrade failed; traffic may be cleartext.",
            "Eavesdropping (T1040); credential theft.",
            "Cleartext credentials and content.",
            evidence=st.get("error") or "STARTTLS not advertised or failed.",
            recommendation="Enable and enforce STARTTLS.",
        ))

    if smtp_connected and e.get("vrfy_supported"):
        findings.append(_finding(
            FINDING_IDS["SMTP_VRFY_ENABLED"],
            "VRFY command enabled",
            "SMTP",
            "medium",
            "VRFY allows enumeration of valid mailboxes.",
            "Reconnaissance (T1589); user enumeration.",
            "User enumeration; easier phishing.",
            evidence="EHLO response indicates VRFY.",
            recommendation="Disable VRFY.",
        ))

    if smtp_connected and e.get("expn_supported"):
        findings.append(_finding(
            FINDING_IDS["SMTP_EXPN_ENABLED"],
            "EXPN command enabled",
            "SMTP",
            "medium",
            "EXPN allows expansion of aliases/lists; information disclosure.",
            "Reconnaissance; list enumeration.",
            "Disclosure of internal addresses.",
            evidence="EHLO response indicates EXPN.",
            recommendation="Disable EXPN.",
        ))

    if smtp_connected and relay.get("relay_likely"):
        findings.append(_finding(
            FINDING_IDS["SMTP_OPEN_RELAY"],
            "Open relay likely",
            "SMTP",
            "critical",
            "Server accepted RCPT TO external domain without AUTH; possible open relay.",
            "Abuse for spam/phishing (T1566); blacklisting.",
            "Abuse; blacklisting; legal risk.",
            evidence=f"RCPT TO accepted (code {relay.get('rcpt_to_code')}).",
            recommendation="Require authentication for external recipients; restrict relay.",
        ))

    if smtp_connected and relay.get("null_sender_relay_likely"):
        findings.append(_finding(
            FINDING_IDS["SMTP_NULL_SENDER_RELAY"],
            "Null sender open relay likely",
            "SMTP",
            "critical",
            "Server accepted MAIL FROM:<> and RCPT TO external; null sender relay.",
            "Bounce abuse; spam; blacklisting.",
            "Abuse; blacklisting; legal risk.",
            evidence=f"MAIL FROM:<> and RCPT TO accepted (code {relay.get('null_sender_rcpt_to_code')}).",
            recommendation="Reject null sender for external relay or require AUTH.",
        ))

    adv = ctx.smtp_data.get("open_relay_advanced", {})
    for r in adv.get("backup_mx_relays", []):
        if r.get("relay_likely") and not r.get("error"):
            findings.append(_finding(
                FINDING_IDS["SMTP_BACKUP_MX_RELAY"],
                "Open relay via backup MX",
                "SMTP",
                "critical",
                f"Backup MX {r.get('host', '?')} accepted RCPT TO external without AUTH; open relay exploitable.",
                "Abuse for spam/phishing via backup path; blacklisting.",
                "Abuse; blacklisting; legal risk.",
                evidence=f"Backup MX {r.get('host')}: RCPT TO accepted (code {r.get('rcpt_to_code')}).",
                recommendation="Require authentication on all MX hosts; restrict relay on backup MX.",
            ))
            break
    if smtp_connected and adv.get("internal_domain_relay_likely") and not adv.get("internal_domain_codes", {}).get("error"):
        findings.append(_finding(
            FINDING_IDS["SMTP_INTERNAL_DOMAIN_RELAY"],
            "Internal domain spoof-based relay possible",
            "SMTP",
            "high",
            "Server accepted MAIL FROM (target domain) and RCPT TO external without AUTH; unauthenticated internal-domain-based relay detectable.",
            "Phishing and spoofing from target domain; abuse exploitable.",
            "Infrastructure abuse; phishing; spoofing.",
            evidence=f"MAIL FROM target domain, RCPT TO external accepted (code {adv.get('internal_domain_codes', {}).get('rcpt_to_code')}).",
            recommendation="Require authentication for external recipients; do not trust MAIL FROM domain alone.",
        ))
    if smtp_connected and adv.get("ip_trust_hints") and (relay.get("relay_likely") or adv.get("internal_domain_relay_likely")):
        findings.append(_finding(
            FINDING_IDS["SMTP_IP_TRUST_MISCONFIG"],
            "IP-based trust misconfiguration hint",
            "SMTP",
            "low",
            "Banner or EHLO response contains trust-related phrases; relay from external IP may be exploitable.",
            "Server may rely on IP allowlist; external relay possible if misconfigured.",
            "Information disclosure; relay abuse if policy is weak.",
            evidence="Phrases: " + "; ".join(adv.get("ip_trust_hints", [])[:3]),
            recommendation="Audit relay policy; do not rely on IP alone; require AUTH for external.",
        ))
    pipelining = adv.get("pipelining") or {}
    if smtp_connected and pipelining.get("pipeline_accepted") and not pipelining.get("error"):
        findings.append(_finding(
            FINDING_IDS["SMTP_PIPELINING_ACCEPTED"],
            "SMTP pipelining accepted",
            "SMTP",
            "low",
            "Server accepted pipelined MAIL FROM + RCPT TO; frontend/backend parsing difference possible.",
            "SMTP smuggling or parsing edge cases may be exploitable in some deployments.",
            "Information disclosure; potential bypass in layered setups.",
            evidence=f"RCPT TO accepted after pipelined MAIL FROM (code {pipelining.get('rcpt_to_code')}).",
            recommendation="Ensure consistent parsing; consider disabling pipelining if frontend/backend differ.",
        ))

    catch_all = ctx.smtp_data.get("catch_all_check", {})
    if smtp_connected and catch_all.get("catch_all_likely") and not catch_all.get("error"):
        findings.append(_finding(
            FINDING_IDS["SMTP_CATCH_ALL"],
            "Catch-all domain likely",
            "SMTP",
            "low",
            "Server accepted RCPT TO for a non-existent local part; domain may be catch-all.",
            "User enumeration less reliable; all addresses appear valid.",
            "Information disclosure; spam targeting.",
            evidence=f"RCPT TO accepted (code {catch_all.get('rcpt_code')}).",
            recommendation="Consider disabling catch-all or document for abuse handling.",
        ))

    auth_check = ctx.smtp_data.get("auth_check", {})
    if smtp_connected and auth_check.get("auth_accepts_without_starttls") and not auth_check.get("error"):
        findings.append(_finding(
            FINDING_IDS["SMTP_AUTH_WITHOUT_STARTTLS"],
            "AUTH accepted without STARTTLS",
            "SMTP",
            "high",
            "Server accepts AUTH on plain connection; credentials may be sent in cleartext.",
            "Eavesdropping (T1040); credential theft.",
            "Cleartext credentials.",
            evidence=f"AUTH response code {auth_check.get('auth_response_code')} on unencrypted session.",
            recommendation="Enforce STARTTLS before AUTH; reject AUTH on plain connection.",
        ))

    if smtp_connected and tls.get("weak_protocol"):
        findings.append(_finding(
            FINDING_IDS["TLS_WEAK_PROTOCOL"],
            "Weak TLS protocol",
            "TLS",
            "high",
            f"Server uses weak protocol: {tls.get('protocol')}.",
            "Downgrade attacks; decryption.",
            "Compromised confidentiality.",
            evidence=str(tls.get("protocol")),
            recommendation="Disable SSLv3, TLS 1.0/1.1; use TLS 1.2+.",
        ))

    if smtp_connected and tls.get("weak_cipher_hint"):
        findings.append(_finding(
            FINDING_IDS["TLS_WEAK_CIPHER"],
            "Weak cipher suite",
            "TLS",
            "medium",
            "Server may negotiate weak ciphers (NULL/EXP/DES/RC4).",
            "Decryption; MITM.",
            "Reduced confidentiality.",
            evidence=str(tls.get("cipher")),
            recommendation="Disable weak ciphers; use strong AEAD ciphers.",
        ))

    return findings


def _rbl_findings(ctx: ScanContext) -> list[dict]:
    """Findings from RBL/DNSBL check: IP listed on blacklist, reputation risk (info security perspective)."""
    findings = []
    rbl = ctx.smtp_data.get("rbl_check", {})
    if not rbl:
        return findings
    summary = rbl.get("summary", {})
    by_ip = rbl.get("by_ip", {})
    total_ips = summary.get("total_ips", 0)
    if total_ips == 0:
        return findings

    # Any IP listed on one or more RBLs: reputation abuse, compromised relay risk
    if summary.get("any_listed") and by_ip:
        for ip, data in by_ip.items():
            listed_count = data.get("listed_count", 0)
            if listed_count == 0:
                continue
            host = data.get("host", ip)
            source = data.get("source", "mx")
            zones_listed = [
                zone for zone, res in data.get("results", {}).items()
                if res.get("listed") and res.get("status") == "ok"
            ]
            severity = "critical" if listed_count >= 3 else "high" if listed_count >= 2 else "medium"
            findings.append(_finding(
                FINDING_IDS["RBL_IP_LISTED"],
                "SMTP IP listed on DNS blacklist (RBL/DNSBL)",
                "RBL",
                severity,
                f"IP {ip} ({host}, source: {source}) is listed on {listed_count} blacklist(s): {', '.join(zones_listed[:5])}. "
                "Reputation abuse or compromised relay risk; outbound mail may be rejected or marked as spam.",
                "Receiving servers may reject or quarantine mail from this IP; DMARC/SPF pass but delivery fails; abuse correlation.",
                "Mail delivery failure; brand reputation; possible compromised relay or shared hostile environment.",
                evidence=f"IP {ip} listed on: {', '.join(zones_listed)}",
                recommendation="Request delisting from each RBL after resolving cause (compromised host, open relay, or shared IP reputation). Check for abuse and secure SMTP; use dedicated IP if possible.",
                affected_service="SMTP",
                attack_vector="reputation",
            ))

    # High reputation score: multiple RBLs list the IP
    for ip, data in by_ip.items():
        score = data.get("reputation_score", 0.0)
        total_checked = data.get("total_checked", 0)
        if total_checked >= 3 and score >= 0.25:
            if any(f.get("id") == "rbl_ip_listed" and ip in (f.get("evidence") or "") for f in findings):
                continue
            host = data.get("host", ip)
            findings.append(_finding(
                FINDING_IDS["RBL_REPUTATION_RISK"],
                "SMTP IP reputation score elevated",
                "RBL",
                "medium" if score >= 0.5 else "low",
                f"IP {ip} ({host}) has RBL reputation score {score:.2f} ({data.get('listed_count', 0)}/{total_checked} lists). "
                "Correlates with delivery risk and possible DMARC/SPF failure at receivers.",
                "Receivers may treat mail from this IP as suspicious; correlation with blacklist and policy failures.",
                "Delivery degradation; possible false positives if list overlap.",
                evidence=f"Reputation score: {score:.2f}, listed on {data.get('listed_count', 0)} of {total_checked} RBLs",
                recommendation="Monitor RBL status; consider dedicated outbound IP and request delisting where appropriate.",
                affected_service="SMTP",
                attack_vector="reputation",
            ))
            break

    return findings


def _mail_ecosystem_findings(ctx: ScanContext) -> list[dict]:
    """Findings from POP3, IMAP, webmail, cross-protocol, account takeover chain."""
    findings = []
    s = ctx.smtp_data
    pop3 = s.get("pop3_security", {})
    imap = s.get("imap_security", {})
    cross = s.get("cross_protocol_attack", {})
    wfp = s.get("webmail_fingerprint", {})
    wsec = s.get("webmail_security", {})
    chain = s.get("mail_account_takeover_chain", {})

    if pop3.get("pop3_110", {}).get("open"):
        findings.append(_finding(
            FINDING_IDS["POP3_PLAIN_ACTIVE"],
            "Plain-text POP3 (110) active",
            "POP3",
            "high",
            "POP3 on port 110 is open; credentials and mail may be sent in cleartext.",
            "Eavesdropping (T1040); credential theft.",
            "Cleartext credentials; compliance risk.",
            evidence="Port 110 open; banner: " + (pop3.get("pop3_110", {}).get("banner") or "")[:60],
            recommendation="Use POP3S (995) or enforce STARTTLS.",
            affected_service="POP3",
            attack_vector="network",
        ))
    if pop3.get("attack_probe") and not pop3.get("attack_probe", {}).get("rate_limit_detected") and pop3.get("attack_probe", {}).get("attempts", 0) >= 3:
        findings.append(_finding(
            FINDING_IDS["POP3_NO_RATE_LIMIT"],
            "POP3 AUTH no rate limit",
            "POP3",
            "high",
            "POP3 accepted multiple AUTH attempts without rate limit or lockout.",
            "Brute-force possible; account takeover.",
            "Credential stuffing; account compromise.",
            evidence=f"Attempts: {pop3.get('attack_probe', {}).get('attempts')}; no rate limit detected.",
            recommendation="Implement rate limiting and lockout for POP3 AUTH.",
            affected_service="POP3",
            attack_vector="authentication",
        ))

    if imap.get("imap_143", {}).get("open"):
        findings.append(_finding(
            FINDING_IDS["IMAP_PLAIN_ACTIVE"],
            "Plain-text IMAP (143) active",
            "IMAP",
            "high",
            "IMAP on port 143 is open; credentials and mail may be sent in cleartext.",
            "Eavesdropping (T1040); credential theft.",
            "Cleartext credentials; compliance risk.",
            evidence="Port 143 open; banner: " + (imap.get("imap_143", {}).get("banner") or "")[:60],
            recommendation="Use IMAPS (993) or enforce STARTTLS.",
            affected_service="IMAP",
            attack_vector="network",
        ))
    if imap.get("attack_probe") and not imap.get("attack_probe", {}).get("rate_limit_detected") and imap.get("attack_probe", {}).get("attempts", 0) >= 3:
        findings.append(_finding(
            FINDING_IDS["IMAP_NO_RATE_LIMIT"],
            "IMAP LOGIN no rate limit",
            "IMAP",
            "high",
            "IMAP accepted multiple LOGIN attempts without rate limit.",
            "Brute-force possible; mailbox takeover.",
            "Credential stuffing; account compromise.",
            evidence=f"Attempts: {imap.get('attack_probe', {}).get('attempts')}; no rate limit detected.",
            recommendation="Implement rate limiting and lockout for IMAP LOGIN.",
            affected_service="IMAP",
            attack_vector="authentication",
        ))

    if cross.get("credential_reuse_risk") or cross.get("lockout_inconsistent"):
        findings.append(_finding(
            FINDING_IDS["CROSS_PROTOCOL_CREDENTIAL_REUSE"],
            "Credential reuse possible across mail protocols",
            "Mail",
            "critical",
            "SMTP AUTH, POP3, and IMAP share the same credential surface; lockout may be inconsistent across protocols.",
            "Attacker can try same credentials on SMTP/POP3/IMAP; one protocol may not lock.",
            "Full mailbox takeover; credential theft; internal phishing.",
            evidence="Cross-protocol probe: lockout_inconsistent=" + str(cross.get("lockout_inconsistent")),
            recommendation="Unify auth policy; enforce rate limit and lockout on all protocols; consider MFA.",
            affected_service="SMTP/POP3/IMAP",
            attack_vector="authentication",
            chained_risk="Weak IMAP/POP3 auth combined with webmail rate-limit bypass allow full mailbox takeover.",
        ))

    if wfp.get("version_disclosed"):
        findings.append(_finding(
            FINDING_IDS["WEBMAIL_VERSION_DISCLOSED"],
            "Webmail version disclosed",
            "Webmail",
            "low",
            "Webmail product/version visible in response: " + ", ".join(wfp.get("version_disclosed", [])),
            "Reconnaissance; version-specific exploits.",
            "Information disclosure.",
            evidence=", ".join(wfp.get("version_disclosed", [])),
            recommendation="Remove version from HTML/headers.",
            affected_service="Webmail",
            attack_vector="reconnaissance",
        ))

    safe = wsec.get("safe_checks") or {}
    if safe.get("status") and (not safe.get("secure_cookie") or not safe.get("httponly_cookie")):
        findings.append(_finding(
            FINDING_IDS["WEBMAIL_INSECURE_COOKIES"],
            "Webmail insecure or missing cookie flags",
            "Webmail",
            "medium",
            "Set-Cookie may lack Secure or HttpOnly; session hijack or XSS risk.",
            "Session theft; cookie exposure.",
            "Session hijack; compliance.",
            evidence="Secure: " + str(safe.get("secure_cookie")) + " HttpOnly: " + str(safe.get("httponly_cookie")),
            recommendation="Set Secure and HttpOnly on session cookies.",
            affected_service="Webmail",
            attack_vector="session",
        ))

    if chain.get("chained_risk"):
        findings.append(_finding(
            FINDING_IDS["MAIL_ACCOUNT_TAKEOVER_CHAIN"],
            "Mail account takeover risk (chained)",
            "Mail",
            "critical",
            "Weak IMAP/POP3 authentication controls combined with webmail rate-limit weakness allow full mailbox takeover, leading to credential theft and internal phishing.",
            "Brute-force or credential stuffing across SMTP/POP3/IMAP/Webmail; no MFA.",
            "Account takeover; credential theft; internal phishing; data breach.",
            evidence="Chained: pop3_weak=" + str(chain.get("pop3_weak")) + " imap_weak=" + str(chain.get("imap_weak")) + " webmail_weak_rate=" + str(chain.get("webmail_weak_rate")),
            recommendation="Enforce rate limit and lockout on all mail access; enable MFA; unify auth policy.",
            affected_service="SMTP/POP3/IMAP/Webmail",
            attack_vector="authentication",
            chained_risk="Weak IMAP authentication controls combined with webmail rate-limit bypass allow a full mailbox takeover, leading to credential theft and internal phishing.",
        ))

    return findings


def _credential_findings(ctx: ScanContext) -> list[dict]:
    """Findings from credential-aware tests (--email + --password)."""
    if not getattr(ctx, "credential_aware", False):
        return []
    findings = []
    s = ctx.smtp_data
    domain = ctx.target_domain

    reuse = s.get("credential_reuse", {})
    protocols = reuse.get("protocols_accepting_credential", [])
    if len(protocols) >= 2:
        findings.append(_finding(
            FINDING_IDS["CREDENTIAL_REUSE_MULTI_PROTOCOL"],
            "Same credential accepted on multiple mail protocols",
            "Credential",
            "critical",
            f"Test mailbox credential was accepted on: {', '.join(protocols)}. "
            "Single credential exposes multiple attack surfaces (SMTP AUTH, POP3, IMAP).",
            "Attacker with one stolen credential can send mail, read mail, or pivot via different protocols.",
            "Mail account takeover; lateral movement; increased blast radius.",
            evidence=f"Protocols accepting credential: {protocols}",
            recommendation="Enforce MFA per protocol where possible; consider disabling legacy plain protocols; monitor cross-protocol logins.",
            exploitability=True,
            proof_of_execution=f"Verified with PoC: {protocols}",
            affected_service="SMTP / POP3 / IMAP",
            attack_chain_role="Credential reuse enables multi-vector abuse",
            authenticated=True,
        ))

    tls_risk = s.get("credential_tls_risk", {})
    if tls_risk.get("plain_auth_accepted"):
        findings.append(_finding(
            FINDING_IDS["CREDENTIAL_PLAIN_AUTH_ACCEPTED"],
            "SMTP AUTH accepted on plain connection (no STARTTLS)",
            "Credential",
            "critical",
            "Server accepted AUTH PLAIN on unencrypted connection. Credentials could be sent in cleartext.",
            "On-path attacker can capture credentials if client uses plain connection.",
            "Credential theft; account compromise.",
            evidence=tls_risk.get("response_preview") or "AUTH PLAIN 235 on port 25 without STARTTLS",
            recommendation="Require STARTTLS before AUTH; disable AUTH on plain connection.",
            exploitability=True,
            proof_of_execution=tls_risk.get("response_preview") or "235 Authentication successful",
            affected_service="SMTP",
            attack_chain_role="Credential exposure on wire",
            authenticated=True,
        ))

    spoof = s.get("credential_auth_spoof", {})
    if spoof.get("exploit_success") and spoof.get("from_manipulation_accepted"):
        findings.append(_finding(
            FINDING_IDS["CREDENTIAL_AUTHENTICATED_SPOOF"],
            "Authenticated user can send mail with manipulated From/Display name",
            "Credential",
            "high",
            "After SMTP AUTH, server accepted mail with internal From/display name manipulation. "
            "Exploitable for internal phishing or BEC-style abuse.",
            "Authenticated attacker can impersonate internal users; no content/links in PoC.",
            "Internal phishing; BEC risk; trust abuse.",
            evidence=spoof.get("proof_of_execution") or "DATA 250 after From header manipulation",
            recommendation="Enforce strict From alignment (e.g. Sender/From match); consider DMARC for internal; user awareness.",
            exploitability=True,
            proof_of_execution=spoof.get("proof_of_execution") or "PoC verified",
            affected_service="SMTP (Submission)",
            attack_chain_role="Authenticated impersonation",
            authenticated=True,
        ))

    return findings


def _enrich_findings_with_exploit(ctx: ScanContext) -> None:
    """Set exploitability and proof_of_execution on findings from attack-mode exploit results."""
    if not getattr(ctx, "attack_mode", False):
        return
    s = ctx.smtp_data
    for f in ctx.findings:
        fid = f.get("id", "")
        if fid == "smtp_open_relay":
            expl = s.get("open_relay_exploit", {})
            if expl.get("exploit_success"):
                f["exploitability"] = True
                f["proof_of_execution"] = expl.get("proof_of_execution") or ("DATA 250: " + str(expl.get("data_code")))
        elif fid in ("spf_bypass_header_spoofing", "dmarc_policy_none", "dns_no_dmarc") or "spoof" in fid:
            expl = s.get("spoof_exploit", {})
            if expl.get("exploit_success"):
                f["exploitability"] = True
                f["proof_of_execution"] = expl.get("proof_of_execution")
        elif fid == "smtp_internal_domain_relay":
            expl = s.get("internal_trust_exploit", {})
            if expl.get("exploit_success"):
                f["exploitability"] = True
                f["proof_of_execution"] = expl.get("proof_of_execution")
        elif fid == "smtp_pipelining_accepted":
            expl = s.get("smtp_smuggling_poc", {})
            if expl.get("frontend_reject_backend_accept"):
                f["exploitability"] = True
                f["proof_of_execution"] = expl.get("proof_of_execution")
        elif fid == "smtp_auth_without_starttls":
            sim = s.get("auth_attack_simulation", {})
            if sim.get("exploit_attempted") and not sim.get("rate_limit_detected") and not sim.get("lockout_detected"):
                f["exploitability"] = True
                f["proof_of_execution"] = f"No rate limit after {sim.get('attempts', 0)} AUTH attempts; responses: {sim.get('responses', [])}"


def collect_findings_from_context(ctx: ScanContext) -> None:
    """Populate ctx.findings from DNS and SMTP data."""
    ctx.findings.clear()
    if ctx.run_dns:
        for f in _dns_findings(ctx):
            ctx.add_finding(f)
    if ctx.run_smtp:
        for f in _smtp_findings(ctx):
            ctx.add_finding(f)
        for f in _mail_ecosystem_findings(ctx):
            ctx.add_finding(f)
        for f in _rbl_findings(ctx):
            ctx.add_finding(f)
    if getattr(ctx, "credential_aware", False):
        for f in _credential_findings(ctx):
            ctx.add_finding(f)
    _enrich_findings_with_exploit(ctx)
