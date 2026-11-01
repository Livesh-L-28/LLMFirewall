"""SSRF protection and safe URL validation utilities.

Security Invariant:
Validates URL syntax and target destinations deterministically WITHOUT performing network egress requests
unless DNS validation is explicitly enabled.
Defends against IPv4 and IPv6 private/link-local SSRF, encoded IP formats, and cloud metadata access.
"""

import ipaddress
import re
import socket
from typing import Optional, Set
from urllib.parse import urlparse

from llmfirewall.core.models import Finding, Severity, ThreatType

# Common cloud metadata endpoints, aliases, and wire proxies
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",           # AWS, GCP, Azure, OpenStack instance metadata
    "fd00:ec2::254",             # AWS IPv6 IMDSv2
    "100.100.100.200",           # Alibaba Cloud metadata
    "169.254.170.2",             # AWS ECS task metadata
    "169.254.169.250",           # Azure IMDS wire proxy
    "metadata.google.internal",  # GCP metadata hostname
    "metadata.internal",
    "instance-data",             # AWS EC2 metadata DNS alias
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


def _parse_legacy_ipv4(host_str: str) -> Optional[ipaddress.IPv4Address]:
    """Parse legacy or alternative IPv4 representations (octal, hex, dword, dotted-pair, dotted-tri).

    Supports POSIX inet_aton formats:
    - 4 parts: a.b.c.d (each byte 0..255)
    - 3 parts: a.b.c (a, b: 0..255; c: 0..65535)
    - 2 parts: a.b (a: 0..255; b: 0..16777215)
    - 1 part: a (0..4294967295)

    Each part can be hexadecimal (0x prefix), octal (0 prefix followed by octal digits),
    or decimal.
    """
    if not host_str or not isinstance(host_str, str):
        return None
    s = host_str.strip().strip("[]")
    if not s or ":" in s:
        return None
    parts = s.split(".")
    if not (1 <= len(parts) <= 4):
        return None

    parsed_parts = []
    for p in parts:
        p_clean = p.strip()
        if not p_clean:
            return None
        try:
            if p_clean.lower().startswith("0x"):
                val = int(p_clean, 16)
            elif p_clean.startswith("0") and len(p_clean) > 1:
                val = int(p_clean, 8)
            else:
                val = int(p_clean, 10)
        except ValueError:
            return None
        if val < 0:
            return None
        parsed_parts.append(val)

    num_parts = len(parsed_parts)
    try:
        if num_parts == 4:
            if any(p > 255 for p in parsed_parts):
                return None
            ip_int = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | (parsed_parts[2] << 8) | parsed_parts[3]
        elif num_parts == 3:
            if parsed_parts[0] > 255 or parsed_parts[1] > 255 or parsed_parts[2] > 0xFFFF:
                return None
            ip_int = (parsed_parts[0] << 24) | (parsed_parts[1] << 16) | parsed_parts[2]
        elif num_parts == 2:
            if parsed_parts[0] > 255 or parsed_parts[1] > 0xFFFFFF:
                return None
            ip_int = (parsed_parts[0] << 24) | parsed_parts[1]
        elif num_parts == 1:
            if parsed_parts[0] > 0xFFFFFFFF:
                return None
            ip_int = parsed_parts[0]
        else:
            return None
        return ipaddress.IPv4Address(ip_int)
    except Exception:
        return None


def is_private_or_restricted_ip(ip_str: str) -> bool:
    """Check if an IP string corresponds to a private, loopback, link-local, or cloud metadata address.

    Handles standard IPv4, IPv6, IPv4-mapped IPv6, and cloud metadata representations.
    """
    clean_ip = ip_str.strip().strip("[]").split("%")[0]

    # Direct match against known cloud metadata IPs and hostnames
    if clean_ip in CLOUD_METADATA_IPS:
        return True

    try:
        ip = ipaddress.ip_address(clean_ip)
        # Check IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1, ::ffff:169.254.169.254)
        if ip.version == 6 and ip.ipv4_mapped is not None:
            return is_private_or_restricted_ip(str(ip.ipv4_mapped))

        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        pass

    # Fall back to alternative / legacy IPv4 representations (octal, hex, dword, dotted-pair)
    legacy_ip = _parse_legacy_ipv4(clean_ip)
    if legacy_ip is not None:
        return (
            legacy_ip.is_loopback
            or legacy_ip.is_private
            or legacy_ip.is_link_local
            or legacy_ip.is_multicast
            or legacy_ip.is_reserved
            or legacy_ip.is_unspecified
        )

    return False


def validate_dns_resolution(hostname: str, timeout: float = 1.0) -> Optional[Finding]:
    """Validate that a target domain does not resolve to private, loopback, or cloud metadata IP addresses.

    Prevents DNS rebinding and private IP pivoting without issuing HTTP requests.
    """
    if not hostname:
        return None

    clean_host = hostname.strip().strip("[]").lower()
    if clean_host in CLOUD_METADATA_IPS or clean_host.endswith(".localhost"):
        return Finding(
            detector_name="url_security",
            threat_type=ThreatType.MALICIOUS_URL,
            description=f"SSRF attempt: Hostname '{clean_host}' is a forbidden metadata/localhost alias.",
            severity=Severity.CRITICAL,
            confidence=1.0,
            metadata={"hostname": clean_host, "violation": "ssrf_metadata_alias"},
        )

    # If it's already an IP literal or legacy IP representation, skip DNS resolution
    try:
        ipaddress.ip_address(clean_host)
        return None
    except ValueError:
        pass

    if _parse_legacy_ipv4(clean_host) is not None:
        return None

    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in addr_info:
            resolved_ip = sockaddr[0]
            if is_private_or_restricted_ip(resolved_ip):
                return Finding(
                    detector_name="url_security",
                    threat_type=ThreatType.MALICIOUS_URL,
                    description=f"SSRF attempt: Domain '{clean_host}' resolves to restricted IP '{resolved_ip}'.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={
                        "hostname": clean_host,
                        "resolved_ip": resolved_ip,
                        "violation": "ssrf_dns_rebinding",
                    },
                )
    except (socket.gaierror, socket.timeout, OSError):
        # Unresolvable domains handled by application network layer
        pass
    finally:
        socket.setdefaulttimeout(orig_timeout)

    return None


def validate_redirect_safety(
    target_url: str,
    original_url: Optional[str] = None,
    allow_cross_domain: bool = False,
    allowed_domains: Optional[Set[str]] = None,
) -> Optional[Finding]:
    """Validate redirection target to prevent open redirects, protocol downgrades, and internal pivoting."""
    target_finding = validate_url_safety(target_url)
    if target_finding:
        return target_finding

    parsed_target = urlparse(target_url.strip())
    target_scheme = (parsed_target.scheme or "").lower()
    target_host = (parsed_target.hostname or "").lower()

    if original_url:
        parsed_orig = urlparse(original_url.strip())
        orig_scheme = (parsed_orig.scheme or "").lower()
        orig_host = (parsed_orig.hostname or "").lower()

        # Prevent protocol downgrade (e.g. https -> http or https -> file)
        if orig_scheme == "https" and target_scheme != "https":
            return Finding(
                detector_name="url_security",
                threat_type=ThreatType.MALICIOUS_URL,
                description=f"Insecure redirect protocol downgrade from '{orig_scheme}' to '{target_scheme}'.",
                severity=Severity.HIGH,
                confidence=1.0,
                metadata={"original_url": original_url[:64], "target_url": target_url[:64], "violation": "protocol_downgrade"},
            )

        # Cross-domain validation
        if not allow_cross_domain and orig_host and target_host != orig_host:
            if not allowed_domains or target_host not in {d.lower() for d in allowed_domains}:
                return Finding(
                    detector_name="url_security",
                    threat_type=ThreatType.MALICIOUS_URL,
                    description=f"Unauthorized cross-domain redirect from '{orig_host}' to '{target_host}'.",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    metadata={"original_host": orig_host, "target_host": target_host, "violation": "unauthorized_cross_domain_redirect"},
                )

    return None


def validate_url_safety(
    url: str,
    allow_private_network: bool = False,
    allowed_schemes: Optional[Set[str]] = None,
    validate_dns: bool = False,
) -> Optional[Finding]:
    """Inspect a URL string for SSRF, forbidden schemes, or private network traversal.

    Args:
        url: The candidate URL string to inspect.
        allow_private_network: If True, bypass private/localhost checks (defaults to False).
        allowed_schemes: Set of allowed URL schemes (defaults to {'http', 'https'}).
        validate_dns: If True, perform DNS lookup to prevent DNS rebinding to private IPs.

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
        # Check standard cloud metadata aliases and hostnames
        if hostname in CLOUD_METADATA_IPS:
            return Finding(
                detector_name="url_security",
                threat_type=ThreatType.MALICIOUS_URL,
                description=f"SSRF attempt: Cloud metadata destination '{hostname}' is forbidden.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={"hostname": hostname, "violation": "ssrf_cloud_metadata"},
            )

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

        # Check standard IP literal (IPv4 or IPv6)
        try:
            standard_ip = ipaddress.ip_address(hostname)
            if (
                standard_ip.is_loopback
                or standard_ip.is_private
                or standard_ip.is_link_local
                or standard_ip.is_multicast
                or standard_ip.is_reserved
                or standard_ip.is_unspecified
                or str(standard_ip) in CLOUD_METADATA_IPS
            ):
                return Finding(
                    detector_name="url_security",
                    threat_type=ThreatType.MALICIOUS_URL,
                    description=f"SSRF attempt: Private or restricted IP '{hostname}' is forbidden.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"hostname": hostname, "violation": "ssrf_restricted_ip"},
                )
        except ValueError:
            pass

        # Check alternative / legacy IPv4 representations (octal, hex, dword, dotted-pair, dotted-tri)
        legacy_ip = _parse_legacy_ipv4(hostname)
        if legacy_ip is not None:
            if (
                legacy_ip.is_loopback
                or legacy_ip.is_private
                or legacy_ip.is_link_local
                or legacy_ip.is_multicast
                or legacy_ip.is_reserved
                or legacy_ip.is_unspecified
                or str(legacy_ip) in CLOUD_METADATA_IPS
            ):
                return Finding(
                    detector_name="url_security",
                    threat_type=ThreatType.MALICIOUS_URL,
                    description=f"SSRF attempt: Encoded or alternative IP address '{hostname}' ({legacy_ip}) is private/loopback.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"hostname": hostname, "resolved_ip": str(legacy_ip), "violation": "ssrf_encoded_ip"},
                )

        # 4. Optional DNS resolution validation
        if validate_dns:
            dns_finding = validate_dns_resolution(hostname)
            if dns_finding:
                return dns_finding

    return None
