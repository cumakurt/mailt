"""
MITRE ATT&CK mapping for findings.
Maps finding IDs to tactics and techniques.
"""
import json
import logging
import os
from typing import Any

logger = logging.getLogger("mailt.analysis")

# Default mapping when JSON not found
_DEFAULT_MAP: dict[str, list[dict[str, str]]] = {
    "dns_no_mx": [{"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}, {"tactic": "Reconnaissance", "technique_id": "T1592", "technique": "Gather Victim Host Information"}],
    "dns_mx_inconclusive": [],
    "dns_no_spf": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing: Spearphishing Attachment"}],
    "dns_spf_inconclusive": [],
    "spf_softfail": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}],
    "spf_plus_all": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}],
    "spf_neutral": [{"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}],
    "spf_lookup_limit": [{"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}],
    "spf_bypass_header_spoofing": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}],
    "spf_bypass_subdomain_no_spf": [{"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}],
    "dns_no_dmarc": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}],
    "dns_dmarc_inconclusive": [],
    "dmarc_policy_none": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}],
    "dmarc_policy_quarantine": [{"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}],
    "dns_no_dkim": [{"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}],
    "dkim_weak_key": [{"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}],
    "dns_no_bimi": [],
    "smtp_banner_disclosure": [{"tactic": "Reconnaissance", "technique_id": "T1595", "technique": "Active Scanning"}],
    "smtp_no_starttls": [{"tactic": "Collection", "technique_id": "T1040", "technique": "Network Sniffing"}],
    "smtp_vrfy_enabled": [{"tactic": "Reconnaissance", "technique_id": "T1589", "technique": "Gather Victim Identity Information"}],
    "smtp_expn_enabled": [{"tactic": "Reconnaissance", "technique_id": "T1589", "technique": "Gather Victim Identity Information"}],
    "smtp_open_relay": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}, {"tactic": "Abuse", "technique_id": "T1071.003", "technique": "Application Layer Protocol: Mail Protocols"}],
    "smtp_null_sender_relay": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}, {"tactic": "Abuse", "technique_id": "T1071.003", "technique": "Application Layer Protocol: Mail Protocols"}],
    "smtp_backup_mx_relay": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}, {"tactic": "Abuse", "technique_id": "T1071.003", "technique": "Application Layer Protocol: Mail Protocols"}],
    "smtp_internal_domain_relay": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing"}],
    "smtp_ip_trust_misconfig": [{"tactic": "Reconnaissance", "technique_id": "T1595", "technique": "Active Scanning"}],
    "smtp_pipelining_accepted": [{"tactic": "Defense Evasion", "technique_id": "T1027", "technique": "Obfuscated Files or Information"}],
    "smtp_catch_all": [{"tactic": "Reconnaissance", "technique_id": "T1589", "technique": "Gather Victim Identity Information"}],
    "smtp_auth_without_starttls": [{"tactic": "Credential Access", "technique_id": "T1040", "technique": "Network Sniffing"}],
    "tls_weak_protocol": [{"tactic": "Credential Access", "technique_id": "T1040", "technique": "Network Sniffing"}],
    "tls_weak_cipher": [{"tactic": "Credential Access", "technique_id": "T1040", "technique": "Network Sniffing"}],
    "pop3_plain_active": [{"tactic": "Credential Access", "technique_id": "T1040", "technique": "Network Sniffing"}],
    "pop3_no_rate_limit": [{"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}],
    "imap_plain_active": [{"tactic": "Credential Access", "technique_id": "T1040", "technique": "Network Sniffing"}],
    "imap_no_rate_limit": [{"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}],
    "cross_protocol_credential_reuse": [{"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}],
    "webmail_version_disclosed": [{"tactic": "Reconnaissance", "technique_id": "T1592", "technique": "Gather Victim Host Information"}],
    "webmail_insecure_cookies": [{"tactic": "Credential Access", "technique_id": "T1539", "technique": "Steal Web Session Cookie"}],
    "mail_account_takeover_chain": [{"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}, {"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"}],
    "credential_reuse_multi_protocol": [{"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}, {"tactic": "Lateral Movement", "technique_id": "T1078", "technique": "Valid Accounts"}],
    "credential_plain_auth_accepted": [{"tactic": "Credential Access", "technique_id": "T1040", "technique": "Network Sniffing"}],
    "credential_authenticated_spoof": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Phishing: Spearphishing Attachment"}, {"tactic": "Impair Defenses", "technique_id": "T1566", "technique": "Phishing"}],
}


def _load_mitre_data() -> dict | None:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, "data", "mitre_attack.json")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.debug("Could not load mitre_attack.json: %s", e)
    return None


def _get_mitre_for_finding(finding_id: str) -> list[dict[str, str]]:
    data = _load_mitre_data()
    if data and "mappings" in data and finding_id in data["mappings"]:
        return data["mappings"][finding_id]
    return _DEFAULT_MAP.get(finding_id, [])


def apply_mitre_to_findings(findings: list[dict[str, Any]]) -> None:
    """Set mitre list on each finding in place."""
    for f in findings:
        fid = f.get("id", "")
        f["mitre"] = _get_mitre_for_finding(fid)
