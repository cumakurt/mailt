"""
Detect SMTP gateway or spam/security appliance in front of mail server from banner.
Anonymous: banner-only heuristics; no probing.
Uses comprehensive list of industry products and multiple banner variations per product.
"""
import logging
from core.context import ScanContext

logger = logging.getLogger("mailt.smtp")

# (banner_substring, product_display_name) — substring is case-insensitive
# Order: more specific first (e.g. FortiMail before Fortinet) to prefer precise product name
GATEWAY_SIGNATURES = [
    # Fortinet (FortiMail: email security gateway)
    ("FortiMail", "Fortinet FortiMail"),
    ("Forti-Mail", "Fortinet FortiMail"),
    ("fortimail", "Fortinet FortiMail"),
    ("Fortinet", "Fortinet FortiMail"),
    # Barracuda
    ("Barracuda", "Barracuda Email Security Gateway"),
    ("barracuda", "Barracuda Email Security Gateway"),
    # Proofpoint
    ("Proofpoint", "Proofpoint Email Protection"),
    ("proofpoint", "Proofpoint Email Protection"),
    ("PPES", "Proofpoint Email Security"),
    # Mimecast
    ("Mimecast", "Mimecast Secure Email Gateway"),
    ("mimecast", "Mimecast Secure Email Gateway"),
    # Cisco
    ("IronPort", "Cisco IronPort / ESA"),
    ("ironport", "Cisco IronPort / ESA"),
    ("Cisco ESA", "Cisco Email Security Appliance"),
    ("Cisco CES", "Cisco Email Security"),
    ("cisco esa", "Cisco Email Security Appliance"),
    # Symantec / Broadcom
    ("Symantec", "Symantec Messaging Gateway"),
    ("symantec", "Symantec Messaging Gateway"),
    ("Broadcom", "Broadcom Email Security"),
    # Microsoft
    ("Microsoft EOP", "Microsoft Exchange Online Protection"),
    ("EOP", "Microsoft Exchange Online Protection"),
    ("Exchange Online", "Microsoft Exchange Online Protection"),
    # Sophos
    ("Sophos", "Sophos Email Appliance"),
    ("sophos", "Sophos Email Appliance"),
    ("Sophos Email", "Sophos Email Security"),
    # Trend Micro
    ("Trend Micro", "Trend Micro IMSVA / Email Security"),
    ("TrendMicro", "Trend Micro Email Security"),
    ("IMSVA", "Trend Micro IMSVA"),
    # McAfee / Trellix
    ("McAfee", "McAfee Email Gateway"),
    ("Trellix", "Trellix Email Security"),
    ("Trellix Email", "Trellix Email Security"),
    # Forcepoint
    ("Forcepoint", "Forcepoint Email Security"),
    ("forcepoint", "Forcepoint Email Security"),
    # F5
    ("F5", "F5 BIG-IP / Mail Safe"),
    ("BIG-IP", "F5 BIG-IP"),
    # Other gateways / appliances
    ("MailFoundry", "MailFoundry"),
    ("SpamTitan", "SpamTitan"),
    ("Spam Titan", "SpamTitan"),
    ("GFI MailEssentials", "GFI MailEssentials"),
    ("GFI", "GFI MailEssentials"),
    ("Alt-N", "Alt-N SecurityGateway"),
    ("SecurityGateway", "Alt-N SecurityGateway"),
    ("MailScanner", "MailScanner"),
    ("Amavis", "Amavis"),
    ("ClamAV", "ClamAV (antivirus)"),
    ("SpamAssassin", "SpamAssassin"),
    # Kaspersky
    ("Kaspersky", "Kaspersky Security for Mail Server"),
    ("kaspersky", "Kaspersky Security for Mail Server"),
    # ESET
    ("ESET", "ESET Mail Security"),
    ("eset", "ESET Mail Security"),
    # Bitdefender
    ("Bitdefender", "Bitdefender Email Security"),
    ("bitdefender", "Bitdefender Email Security"),
    # Hornetsecurity
    ("Hornetsecurity", "Hornetsecurity Email Security"),
    ("Hornet", "Hornetsecurity"),
    # Tessian
    ("Tessian", "Tessian Email Security"),
    # Abnormal Security
    ("Abnormal", "Abnormal Security"),
    # Avanan
    ("Avanan", "Avanan Email Security"),
    # Perception Point
    ("Perception Point", "Perception Point"),
    ("PerceptionPoint", "Perception Point"),
    # Vade
    ("Vade", "Vade Retro"),
    ("Vade Retro", "Vade Retro"),
    # Egress
    ("Egress", "Egress Email Security"),
    # Material Security
    ("Material Security", "Material Security"),
    # Area 1 / Cloudflare
    ("Area 1", "Cloudflare Area 1 Email Security"),
    ("Area1", "Cloudflare Area 1 Email Security"),
    # Graphus
    ("Graphus", "Graphus"),
    # Heimdal
    ("Heimdal", "Heimdal Email Security"),
    # Vircom
    ("Vircom", "Vircom modusGate"),
    ("modusGate", "Vircom modusGate"),
    # Reflexion
    ("Reflexion", "Reflexion Networks"),
    # Clearswift
    ("Clearswift", "Clearswift SECURE Email Gateway"),
    ("clearswift", "Clearswift SECURE Email Gateway"),
    # SolarWinds
    ("SolarWinds", "SolarWinds Mail Assure"),
    ("Mail Assure", "SolarWinds Mail Assure"),
    # TitanHQ
    ("TitanHQ", "TitanHQ SpamTitan"),
    # LuxSci
    ("LuxSci", "LuxSci Email Security"),
    # Retruster
    ("Retruster", "Retruster"),
    # Cofense
    ("Cofense", "Cofense PhishMe"),
    # Mimecast (duplicate patterns for robustness)
    ("Mimecast Gateway", "Mimecast Secure Email Gateway"),
    # Zix
    ("Zix", "Zix Email Security"),
    # AppRiver
    ("AppRiver", "AppRiver SecureTide"),
    ("SecureTide", "AppRiver SecureTide"),
    # DuoCircle
    ("DuoCircle", "DuoCircle"),
    # MailChannels
    ("MailChannels", "MailChannels"),
    # Valimail
    ("Valimail", "Valimail"),
    # Agari
    ("Agari", "Agari Phishing Defense"),
    # Ironscales
    ("Ironscales", "Ironscales"),
    # INKY
    ("INKY", "INKY Phishing Protection"),
    # CipherMail
    ("CipherMail", "CipherMail Gateway"),
    # Halon
    ("Halon", "Halon SMTP"),
    # Stalwart
    ("Stalwart", "Stalwart Mail Server"),
]


def _detect_from_banner(banner: str) -> list[tuple[str, str]]:
    """Return list of (signature_matched, product_name) for banner. Deduplicates by product name."""
    if not banner:
        return []
    banner_lower = banner.lower()
    seen_products = set()
    detected = []
    for sig, name in GATEWAY_SIGNATURES:
        if name in seen_products:
            continue
        if sig.lower() in banner_lower:
            detected.append((sig, name))
            seen_products.add(name)
    return detected


def run(ctx: ScanContext) -> None:
    """Run gateway/spam detection from SMTP banner; store in ctx.smtp_data['gateway_detection']."""
    e = ctx.smtp_data.get("smtp_enum", {})
    banner = e.get("banner") or ""
    # Also check EHLO lines (some products identify in 250 extensions)
    ehlo_lines = e.get("ehlo_lines", [])
    combined = banner + " " + " ".join(ehlo_lines)
    detected = _detect_from_banner(combined)
    result = {
        "detected": [{"signature": s, "product": p} for s, p in detected],
        "banner_snippet": (banner[:250] + "..." if len(banner) > 250 else banner) if banner else None,
        "raw_banner": banner,
    }
    ctx.add_smtp_data("gateway_detection", result)
    if ctx.verbose and detected:
        logger.debug("Gateway/spam detection: %s", [p for _, p in detected])
