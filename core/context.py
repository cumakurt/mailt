"""
Target and scan state management.
Holds domain, options, and collected data for the scan session.
add_dns_data / add_smtp_data use documented key sets; unknown keys are allowed but logged at debug.
"""
from dataclasses import dataclass, field
import logging
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.progress import ProgressReporter

logger = logging.getLogger("mailt.context")

# Documented keys populated by scanner modules (allowlist for validation; unknown keys still accepted)
KNOWN_DNS_KEYS = frozenset({
    "mx", "mx_status", "mx_message", "a", "a_status", "a_message",
    "aaaa", "aaaa_status", "aaaa_message", "txt_raw", "txt_status", "txt_message",
    "ns", "ns_status", "ns_message", "spf_record", "spf_status", "spf_message",
    "spf_mechanisms", "spf_lookup_count", "spf_all_qualifier", "dkim_selectors",
    "dmarc_record", "dmarc_status", "dmarc_parsed", "bimi_record", "spf_bypass",
    "ptr_results",
})
KNOWN_SMTP_KEYS = frozenset({
    "smtp_enum", "starttls", "tls_analysis", "open_relay", "open_relay_advanced",
    "catch_all_check", "auth_check", "mail_service_discovery", "pop3_security",
    "imap_security", "webmail_fingerprint", "webmail_security",
    "mail_account_takeover_chain", "mail_dos_analysis", "gateway_detection",
    "open_relay_exploit", "spoof_exploit", "display_name_exploit",
    "auth_attack_simulation", "internal_trust_exploit", "smtp_smuggling_poc",
    "cross_protocol_attack",
    "credential_reuse", "credential_tls_risk", "credential_auth_spoof",
    "rbl_check",
})


@dataclass
class ScanContext:
    """Holds target domain and scan configuration."""

    target_domain: str
    verbose: bool = False
    run_dns: bool = True
    run_smtp: bool = True
    # Attack mode: exploit/PoC only when BOTH --attack-mode and --i-understand-the-risks are set
    attack_mode: bool = False
    # Manual server hostnames/IPs (override MX-based discovery when set)
    manual_smtp_host: Optional[str] = None
    manual_pop3_host: Optional[str] = None
    manual_imap_host: Optional[str] = None

    # User-based credential-aware tests (--email + --password)
    test_email: Optional[str] = None
    test_password: Optional[str] = None
    credential_aware: bool = False

    # Progress reporter (set by scanner)
    progress: Optional["ProgressReporter"] = None

    # Collected raw data (populated by scanner)
    dns_data: dict[str, Any] = field(default_factory=dict)
    smtp_data: dict[str, Any] = field(default_factory=dict)

    # Normalized findings (populated by analysis)
    findings: list[dict[str, Any]] = field(default_factory=list)

    # Audit trail for attack-mode actions (module, action, result, timestamp)
    exploit_audit_log: list[dict[str, Any]] = field(default_factory=list)

    # Step errors (step name -> error message) when a step fails; scan continues
    step_errors: list[dict[str, str]] = field(default_factory=list)

    # Output: directory for reports, format (html | json | markdown | all)
    output_dir: Optional[str] = None
    output_format: str = "html"

    # Quiet: minimal progress output; log_file: optional path for log output
    quiet: bool = False
    log_file: Optional[str] = None

    # Timeouts (seconds): scan total, DNS, SMTP (None = use defaults)
    scan_timeout_seconds: Optional[float] = None
    dns_timeout: Optional[float] = None
    smtp_timeout: Optional[float] = None

    def add_step_error(self, step: str, error: str) -> None:
        """Record a step failure; scan continues."""
        self.step_errors.append({"step": step, "error": error})

    def add_dns_data(self, key: str, value: Any) -> None:
        """Store DNS-related data. Prefer keys from KNOWN_DNS_KEYS for consistency."""
        if key not in KNOWN_DNS_KEYS:
            logger.debug("add_dns_data unknown key: %s", key)
        self.dns_data[key] = value

    def add_smtp_data(self, key: str, value: Any) -> None:
        """Store SMTP-related data. Prefer keys from KNOWN_SMTP_KEYS for consistency."""
        if key not in KNOWN_SMTP_KEYS:
            logger.debug("add_smtp_data unknown key: %s", key)
        self.smtp_data[key] = value

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Append a normalized finding."""
        self.findings.append(finding)

    def get_all_findings(self) -> list[dict[str, Any]]:
        """Return all findings (for reporting)."""
        return self.findings

    def log_exploit_audit(self, module: str, action: str, result: str, detail: Optional[dict] = None) -> None:
        """Append to exploit audit trail (attack mode only)."""
        import time
        self.exploit_audit_log.append({
            "module": module,
            "action": action,
            "result": result,
            "detail": detail or {},
            "timestamp": time.time(),
        })
