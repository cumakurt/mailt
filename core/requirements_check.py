"""
Pre-flight check: ensure required packages are available.
If anything is missing, print warnings and exit with non-zero.
"""
import sys


def check_dnspython() -> tuple[bool, str]:
    """Return (ok, message)."""
    try:
        import dns.resolver  # noqa: F401
        return True, "dnspython"
    except ImportError:
        return False, "dnspython (pip install dnspython)"


def check_requirements() -> None:
    """Check all required dependencies. Print missing items and exit with 1 if any missing."""
    missing = []
    ok, msg = check_dnspython()
    if not ok:
        missing.append(("DNS resolution", msg))

    if not missing:
        return

    print("MailT — Missing required package. Please install before running.\n", file=sys.stderr)
    for name, msg in missing:
        print(f"  [X] {name}: {msg}", file=sys.stderr)
    print("\nAfter installing, run MailT again.", file=sys.stderr)
    sys.exit(1)
