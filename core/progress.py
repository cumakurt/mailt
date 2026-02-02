"""
Progress reporting: step list, current step, elapsed time, percentage, remaining.
"""
import sys
import time
from typing import Callable, Optional


class ProgressReporter:
    """Reports current step, total steps, elapsed time, percentage, and remaining."""

    def __init__(self, total_steps: int, verbose: bool = False, quiet: bool = False):
        self.total_steps = total_steps
        self.current_step = 0
        self.start_time: Optional[float] = None
        self.step_start_time: Optional[float] = None
        self.verbose = verbose
        self.quiet = quiet
        self._step_names: list[str] = []

    def set_step_names(self, names: list[str]) -> None:
        """Set human-readable names for each step (optional)."""
        self._step_names = names

    def start(self, step_names: Optional[list[str]] = None) -> None:
        """Call at scan start. step_names: optional list to show full step plan."""
        self.start_time = time.perf_counter()
        self.current_step = 0
        self._print_header(step_names)

    def _print_header(self, step_names: Optional[list[str]] = None) -> None:
        if self.quiet:
            return
        print(f"\n  Steps: {self.total_steps} total")
        if step_names:
            pad = max(2, len(str(len(step_names))))
            for i, name in enumerate(step_names, 1):
                print(f"    {i:0{pad}d}. {name}")
        print("  " + "-" * 60)

    def advance(self, step_name: str, detail: Optional[str] = None) -> None:
        """
        Call at the start of each step.
        step_name: e.g. "DNS: MX records"
        detail: optional one-line detail to show after (e.g. "Found 2 records")
        """
        self.current_step += 1
        self.step_start_time = time.perf_counter()
        elapsed = (self.step_start_time - self.start_time) if self.start_time else 0
        pct = (self.current_step / self.total_steps * 100) if self.total_steps else 0
        remaining = self.total_steps - self.current_step

        if self.quiet:
            return
        # [03/14] DNS: SPF record... (1.2s) — 21% complete, 11 steps left
        pad = max(2, len(str(self.total_steps)))
        line = f"  [{self.current_step:0{pad}d}/{self.total_steps:0{pad}d}] {step_name}"
        if elapsed > 0:
            line += f"  ({elapsed:.1f}s)"
        line += f"  — {pct:.0f}% complete"
        if remaining > 0:
            line += f", {remaining} step{'s' if remaining != 1 else ''} left"
        print(line, flush=True)
        if detail:
            print(f"       → {detail}", flush=True)

    def step_done(self, detail: Optional[str] = None) -> None:
        """Call at end of step to optionally print step duration / result."""
        if self.quiet or not detail or not self.verbose:
            return
        elapsed = (time.perf_counter() - self.step_start_time) if self.step_start_time else 0
        print(f"       ✓ {detail} ({elapsed:.2f}s)", flush=True)

    def done(self) -> None:
        """Call when scan is complete."""
        if self.start_time is None:
            return
        total_elapsed = time.perf_counter() - self.start_time
        if self.quiet:
            print(f"MailT: Completed {self.total_steps} steps in {total_elapsed:.1f}s", flush=True)
            return
        print("  " + "-" * 60)
        print(f"  Completed: {self.total_steps} steps in {total_elapsed:.1f}s")
        print(flush=True)


def build_step_list(
    run_dns: bool,
    run_smtp: bool,
    attack_mode: bool = False,
    credential_aware: bool = False,
    output_format: str = "html",
) -> list[str]:
    """Build ordered list of step names for progress."""
    steps = []
    if run_dns:
        steps += [
            "DNS: Resolve MX, A, AAAA, TXT, NS",
            "DNS: SPF record lookup",
            "DNS: DKIM selector discovery",
            "DNS: DMARC policy lookup",
            "DNS: BIMI check",
            "DNS: SPF bypass / policy analysis",
            "DNS: RBL/DNSBL blacklist check",
        ]
    if run_smtp:
        steps += [
            "SMTP: Connect and EHLO (banner)",
            "SMTP: STARTTLS upgrade",
            "SMTP: TLS version and cipher",
            "SMTP: Open relay probe",
            "SMTP: Advanced open relay (backup MX, internal trust, pipelining)",
            "SMTP: Catch-all check",
            "SMTP: AUTH without STARTTLS check",
            "Mail: Protocol surface discovery (SMTP/POP3/IMAP/Webmail)",
            "Mail: POP3/POP3S security",
            "Mail: IMAP/IMAPS security",
            "Mail: Webmail fingerprint",
            "Mail: Webmail security (HTTPS, cookies, CSP)",
            "Mail: Account takeover chain analysis",
            "Mail: DoS/resource analysis",
        ]
    if credential_aware and run_smtp:
        steps += [
            "Credential: Reuse (SMTP AUTH, POP3, IMAP)",
            "Credential: TLS/plain auth risk",
            "Credential: Authenticated From/Display name PoC",
        ]
    if attack_mode and run_smtp:
        steps += [
            "EXPLOIT: Open relay PoC",
            "EXPLOIT: SPF/DMARC spoof PoC",
            "EXPLOIT: Display name spoof PoC",
            "EXPLOIT: AUTH brute simulation",
            "EXPLOIT: Internal trust PoC",
            "EXPLOIT: SMTP smuggling PoC",
            "EXPLOIT: Cross-protocol credential reuse",
        ]
    steps += ["Analysis: Normalize findings, CVSS, MITRE"]
    fmt = (output_format or "html").lower()
    if fmt in ("html", "all"):
        steps.append("Reporting: Generate HTML report")
    if fmt in ("json", "all"):
        steps.append("Reporting: Generate JSON report")
    if fmt in ("markdown", "all"):
        steps.append("Reporting: Generate Markdown report")
    # Fallback: if output_format was unknown or no report step was added, ensure at least HTML report
    if not steps or steps[-1] == "Analysis: Normalize findings, CVSS, MITRE":
        steps.append("Reporting: Generate HTML report")
    return steps
