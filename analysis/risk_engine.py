"""
CVSS v3.1 scoring for findings.
AV, AC, PR, UI, S, C, I, A -> base score and severity label.
"""
import math
import logging
from typing import Any

logger = logging.getLogger("mailt.analysis")

# Severity bands (CVSS 3.1)
SEVERITY_BANDS = [
    (0.0, 0.0, "None"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
]


def _round_up(value: float) -> float:
    """Round up to 1 decimal (CVSS style)."""
    return math.ceil(value * 10) / 10


def _impact_subscore(confidentiality: str, integrity: str, availability: str) -> float:
    """IS = 1 - (1-C)(1-I)(1-A). Values: N=0, L=0.22, H=0.56."""
    map_ = {"N": 0.0, "L": 0.22, "H": 0.56}
    c = map_.get(confidentiality, 0)
    i = map_.get(integrity, 0)
    a = map_.get(availability, 0)
    return 1.0 - (1 - c) * (1 - i) * (1 - a)


def _exploitability(av: str, ac: str, pr: str, ui: str) -> float:
    """E = 8.22 * AV * AC * PR * UI."""
    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    ui_map = {"N": 0.85, "R": 0.62}
    return 8.22 * av_map.get(av, 0.85) * ac_map.get(ac, 0.77) * pr_map.get(pr, 0.85) * ui_map.get(ui, 0.85)


def _base_score(impact_isc: float, exploitability: float) -> float:
    """Impact = 6.42 * ISC (scope unchanged); Base = min(10, Impact + E). All findings use scope unchanged."""
    if impact_isc <= 0:
        return 0.0
    impact = 6.42 * impact_isc
    raw = impact + exploitability
    return _round_up(min(10.0, raw))


def _score_to_severity(score: float) -> str:
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return label
    return "None"


# Mapping: finding id -> (C, I, A, AV, AC, PR, UI). Scope = Unchanged.
_FINDING_METRICS: dict[str, tuple[str, str, str, str, str, str, str]] = {
    "dns_no_mx": ("N", "L", "H", "N", "L", "N", "N"),
    "dns_mx_inconclusive": ("N", "N", "N", "N", "L", "N", "N"),
    "dns_no_spf": ("L", "L", "N", "N", "L", "N", "N"),
    "dns_spf_inconclusive": ("N", "N", "N", "N", "L", "N", "N"),
    "spf_softfail": ("L", "N", "N", "N", "L", "N", "N"),
    "spf_plus_all": ("H", "H", "N", "N", "L", "N", "N"),
    "spf_neutral": ("L", "L", "N", "N", "L", "N", "N"),
    "spf_lookup_limit": ("L", "N", "N", "N", "L", "N", "N"),
    "spf_bypass_header_spoofing": ("L", "L", "N", "N", "L", "N", "N"),
    "spf_bypass_subdomain_no_spf": ("L", "L", "N", "N", "L", "N", "N"),
    "dns_no_dmarc": ("L", "L", "N", "N", "L", "N", "N"),
    "dns_dmarc_inconclusive": ("N", "N", "N", "N", "L", "N", "N"),
    "dmarc_policy_none": ("L", "L", "N", "N", "L", "N", "N"),
    "dmarc_policy_quarantine": ("L", "N", "N", "N", "L", "N", "N"),
    "dns_no_dkim": ("L", "N", "N", "N", "L", "N", "N"),
    "dkim_weak_key": ("L", "L", "N", "N", "L", "N", "N"),
    "dns_no_bimi": ("N", "N", "N", "N", "L", "N", "N"),
    "smtp_banner_disclosure": ("L", "N", "N", "N", "L", "N", "N"),
    "smtp_no_starttls": ("H", "N", "N", "N", "L", "N", "N"),
    "smtp_vrfy_enabled": ("L", "N", "N", "N", "L", "N", "N"),
    "smtp_expn_enabled": ("L", "N", "N", "N", "L", "N", "N"),
    "smtp_open_relay": ("H", "H", "H", "N", "L", "N", "N"),
    "smtp_null_sender_relay": ("H", "H", "H", "N", "L", "N", "N"),
    "smtp_backup_mx_relay": ("H", "H", "H", "N", "L", "N", "N"),
    "smtp_internal_domain_relay": ("H", "L", "N", "N", "L", "N", "N"),
    "smtp_ip_trust_misconfig": ("L", "N", "N", "N", "L", "N", "N"),
    "smtp_pipelining_accepted": ("L", "N", "N", "N", "L", "N", "N"),
    "smtp_catch_all": ("L", "N", "N", "N", "L", "N", "N"),
    "smtp_auth_without_starttls": ("H", "N", "N", "N", "L", "N", "N"),
    "tls_weak_protocol": ("H", "N", "N", "N", "L", "N", "N"),
    "tls_weak_cipher": ("H", "N", "N", "N", "L", "N", "N"),
    "pop3_plain_active": ("H", "N", "N", "N", "L", "N", "N"),
    "pop3_no_rate_limit": ("H", "N", "N", "N", "L", "N", "N"),
    "imap_plain_active": ("H", "N", "N", "N", "L", "N", "N"),
    "imap_no_rate_limit": ("H", "N", "N", "N", "L", "N", "N"),
    "cross_protocol_credential_reuse": ("H", "H", "N", "N", "L", "N", "N"),
    "webmail_version_disclosed": ("L", "N", "N", "N", "L", "N", "N"),
    "webmail_insecure_cookies": ("L", "L", "N", "N", "L", "N", "N"),
    "mail_account_takeover_chain": ("H", "H", "N", "N", "L", "N", "N"),
}


def _metrics_for_finding(finding: dict[str, Any]) -> tuple[str, str, str, str, str, str, str]:
    fid = finding.get("id", "")
    hint = finding.get("severity_hint", "low").lower()
    default = ("L", "L", "N", "N", "L", "N", "N")
    row = _FINDING_METRICS.get(fid, default)
    # row: C, I, A, AV, AC, PR, UI (S implied U)
    if len(row) == 7:
        return row
    return default[:7]


def compute_cvss(finding: dict[str, Any]) -> dict[str, Any]:
    """Compute CVSS v3.1 base score for a finding. Modifies finding with cvss key."""
    C, I, A, AV, AC, PR, UI = _metrics_for_finding(finding)
    S = "U"  # Scope Unchanged for our findings
    impact_isc = _impact_subscore(C, I, A)
    exploitability = _exploitability(AV, AC, PR, UI)
    score = _base_score(impact_isc, exploitability)
    severity = _score_to_severity(score)
    finding["cvss"] = {
        "version": "3.1",
        "AV": AV,
        "AC": AC,
        "PR": PR,
        "UI": UI,
        "S": S,
        "C": C,
        "I": I,
        "A": A,
        "base_score": score,
        "severity": severity,
    }
    return finding


def apply_cvss_to_findings(findings: list[dict[str, Any]]) -> None:
    """Apply CVSS to each finding in place."""
    for f in findings:
        compute_cvss(f)
