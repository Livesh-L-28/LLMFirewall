"""SSRF protection and safe URL validation utilities.

Security Invariant:
Validates URL syntax and target destinations deterministically WITHOUT performing network egress requests.
Does not claim immunity against DNS rebinding (which requires network-level egress pinning/proxying).
"""

import ipaddress
import re
from typing import Optional, Set
from urllib.parse import urlparse

from llmfirewall.core.models import Finding, Severity, ThreatType

# Common cloud metadata endpoints and loopbacks
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack instance metadata
    "fd00:ec2::254",       # AWS IPv6 IMDSv2
    "100.100.100.200",     # Alibaba Cloud metadata
    "169.254.170.2",       # AWS ECS task metadata
}

BLOCKED_SCHEMES: Set[str] = {
    "file",
    "gopher",
    "ftp",
    "tftp",
    "dict",
    "ldap",
    "ldaps",
    "netdoc",
    "jar",
}

SAFE_SCHEMES: Set[str] = {"http", "https"}


def is_private_or_restricted_ip(ip_str: str) -> bool:
    """Check if an IP string corresponds to a private, loopback, link-local, or cloud metadata address."""
    clean_ip = ip_str.strip().strip("[]")

    # Direct match against known cloud metadata IPs
    if clean_ip in CLOUD_METADATA_IPS:
        return True

    try:
        ip = ipaddress.ip_address(clean_ip)
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def validate_url_safety(
    url: str,
    allow_private_network: bool = False,
    allowed_schemes: Optional[Set[str]] = None,
) -> Optional[Finding]:
    """Inspect a URL string for SSRF, forbidden schemes, or private network traversal.
    
    Args:
        url: The candidate URL string to inspect.
        allow_private_network: If True, bypass private/localhost checks (defaults to False).
        allowed_schemes: Set of allowed URL schemes (defaults to {'http', 'https'}).
        
    Returns:
        Optional[Finding]: Emitted Finding if malicious/dangerous URL detected, else None.
    """
    if not url or not isinstance(url, str):
        return None

    stripped = url.strip()
    schemes = allowed_schemes or SAFE_SCHEMES

    try:
        parsed = urlparse(stripped)
    except Exception as exc:
        return Finding(
            detector_name="url_security",
            threat_type=ThreatType.MALICIOUS_URL,
            description=f"Malformed URL syntax: {exc}",
            severity=Severity.HIGH,
            confidence=1.0,
            metadata={"url": stripped[:128], "error": "malformed_url"},
        )

    # 1. Scheme Validation
    scheme = (parsed.scheme or "").lower()
    if not scheme:
        return Finding(
            detector_name="url_security",
            threat_type=ThreatType.MALICIOUS_URL,
            description="URL is missing scheme (expected http or https).",
            severity=Severity.MEDIUM,
            confidence=0.9,
            metadata={"url": stripped[:128], "violation": "missing_scheme"},
        )

    if scheme in BLOCKED_SCHEMES or scheme not in schemes:
        return Finding(
            detector_name="url_security",
            threat_type=ThreatType.MALICIOUS_URL,
            description=f"Dangerous or unsupported URL scheme '{scheme}'.",
            severity=Severity.CRITICAL,
            confidence=1.0,
            metadata={"url": stripped[:128], "scheme": scheme, "violation": "blocked_scheme"},
        )

    # 2. Host and Port Validation
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return Finding(
            detector_name="url_security",
            threat_type=ThreatType.MALICIOUS_URL,
            description="URL is missing valid hostname.",
            severity=Severity.HIGH,
            confidence=1.0,
            metadata={"url": stripped[:128], "violation": "missing_hostname"},
        )

    # Check for embedded credentials (e.g. http://user:pass@host)
    if parsed.username or parsed.password:
        return Finding(
            detector_name="url_security",
            threat_type=ThreatType.MALICIOUS_URL,
            description="URL contains embedded basic authentication credentials.",
            severity=Severity.HIGH,
            confidence=0.95,
            metadata={"hostname": hostname, "violation": "embedded_credentials"},
        )

    # 3. SSRF / Localhost / Cloud Metadata Inspection
    if not allow_private_network:
        # Check standard localhost aliases
        localhost_patterns = {
            "localhost",
            "localhost.localdomain",
            "ip6-localhost",
            "ip6-loopback",
        }
        if hostname in localhost_patterns or hostname.endswith(".localhost"):
            return Finding(
                detector_name="url_security",
                threat_type=ThreatType.MALICIOUS_URL,
                description=f"SSRF attempt: Localhost address '{hostname}' is forbidden.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={"hostname": hostname, "violation": "ssrf_localhost"},
            )

        # Check decimal, hex, or octal IP representations
        # E.g. 2130706433 is 127.0.0.1 in decimal, 0x7f000001 in hex
        numeric_ip_match = re.match(r"^(0x[0-9a-fA-F]+|\d+)$", hostname)
        if numeric_ip_match:
            try:
                num_val = int(hostname, 0)
                ip_obj = ipaddress.ip_address(num_val)
                if ip_obj.is_loopback or ip_obj.is_private:
                    return Finding(
                        detector_name="url_security",
                        threat_type=ThreatType.MALICIOUS_URL,
                        description=f"SSRF attempt: Encoded IP address '{hostname}' ({ip_obj}) is private/loopback.",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        metadata={"hostname": hostname, "resolved_ip": str(ip_obj), "violation": "ssrf_encoded_ip"},
                    )
            except ValueError:
                pass

        # Check standard IP literal
        if is_private_or_restricted_ip(hostname):
            return Finding(
                detector_name="url_security",
                threat_type=ThreatType.MALICIOUS_URL,
                description=f"SSRF attempt: Private or restricted IP '{hostname}' is forbidden.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={"hostname": hostname, "violation": "ssrf_restricted_ip"},
            )

    return None
