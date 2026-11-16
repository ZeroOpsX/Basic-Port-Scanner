"""
Target and Network Input Validation Module for NetPulse.
Uses Python's standard `ipaddress` module for robust IP address verification
and `socket.gethostbyname()` for domain resolution with comprehensive error handling.
"""

import ipaddress
import re
import socket
from typing import List, Optional, Tuple


def is_valid_ipv4(target: str) -> bool:
    """
    Validates whether the provided target string is a valid IPv4 address.

    Args:
        target: IP address string to validate (e.g., '192.168.1.1', '127.0.0.1').

    Returns:
        True if target is a valid IPv4 address, False otherwise.

    Examples:
        >>> is_valid_ipv4("192.168.1.1")
        True
        >>> is_valid_ipv4("999.999.999.999")
        False
        >>> is_valid_ipv4("google.com")
        False
    """
    if not target or not isinstance(target, str):
        return False

    cleaned_target = target.strip()

    try:
        ipaddress.IPv4Address(cleaned_target)
        return True
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return False


def validate_ipv4(target: str) -> str:
    """
    Validates and normalizes an IPv4 address string.

    Args:
        target: IP address string.

    Returns:
        Canonical string representation of the IPv4 address.

    Raises:
        ValueError: If target is not a valid IPv4 address.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string.")

    cleaned = target.strip()
    try:
        ip = ipaddress.IPv4Address(cleaned)
        return str(ip)
    except (ipaddress.AddressValueError, ValueError) as err:
        raise ValueError(f"Invalid IPv4 address '{target}': {err}")


def is_valid_cidr(target: str) -> bool:
    """
    Validates whether the provided string is a valid IPv4 CIDR network specification.

    Args:
        target: Target string to validate (e.g., '192.168.1.0/24', '10.0.0.0/16').

    Returns:
        True if target is a valid IPv4 CIDR string, False otherwise.
    """
    if not target or not isinstance(target, str):
        return False

    cleaned = target.strip()
    if "/" not in cleaned:
        return False

    try:
        network = ipaddress.ip_network(cleaned, strict=False)
        return isinstance(network, ipaddress.IPv4Network)
    except (ValueError, TypeError):
        return False


def parse_cidr(cidr_str: str) -> List[str]:
    """
    Parses an IPv4 CIDR network string into a list of host IPv4 address strings using ipaddress.ip_network.

    For subnets with prefix <= 30, returns usable host addresses (omitting network and broadcast).
    For /31 (RFC 3021 point-to-point) and /32 (host route), returns all assigned addresses.

    Args:
        cidr_str: CIDR notation string (e.g., '192.168.1.0/24', '10.0.0.1/30').

    Returns:
        List of string IPv4 addresses in the network range.

    Raises:
        ValueError: If CIDR string is malformed, not IPv4, or has an unreasonably broad prefix (< /8).
    """
    if not cidr_str or not isinstance(cidr_str, str):
        raise ValueError("CIDR input must be a non-empty string.")

    cleaned = cidr_str.strip()
    if "/" not in cleaned:
        raise ValueError(f"Target '{cidr_str}' is not in CIDR notation (expected format: 'IP/prefix', e.g. 192.168.1.0/24).")

    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as err:
        raise ValueError(f"Invalid CIDR network format '{cidr_str}': {err}") from err

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError(f"Only IPv4 CIDR networks are supported (received: '{cidr_str}').")

    if network.prefixlen < 8:
        raise ValueError(f"CIDR prefix /{network.prefixlen} is too broad. Minimum allowed prefix is /8.")

    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        # Fallback for /32 host route
        hosts = [str(ip) for ip in network]

    return hosts


def resolve_domain(domain: str) -> Optional[str]:
    """
    Resolves a domain name (e.g., 'example.com') to an IPv4 address using socket.gethostbyname().
    Gracefully handles non-existent domains, socket errors, and malformed inputs.

    Args:
        domain: Domain name or hostname to resolve.

    Returns:
        Resolved IPv4 address string (e.g., '93.184.216.34') if successful, or None if domain doesn't exist.

    Examples:
        >>> resolve_domain("localhost")
        '127.0.0.1'
        >>> resolve_domain("nonexistent-domain-xyz123456.invalid")
        None
    """
    if not domain or not isinstance(domain, str):
        return None

    # Strip accidental protocol prefixes (http://, https://) or trailing paths/ports
    clean_domain = domain.strip().lower()
    clean_domain = re.sub(r"^https?://", "", clean_domain).split("/")[0].split(":")[0]

    if not clean_domain:
        return None

    try:
        return socket.gethostbyname(clean_domain)
    except (socket.gaierror, socket.herror, socket.error):
        # Domain not found (Errno 11001/EAI_NONAME) or network lookup failure
        return None


def resolve_domain_to_ipv4(domain: str) -> str:
    """
    Resolves a domain name to an IPv4 address using socket.gethostbyname().
    Raises a descriptive ValueError if the domain does not exist or resolution fails.

    Args:
        domain: Domain name or hostname to resolve (e.g., 'example.com').

    Returns:
        The resolved IPv4 address as a string.

    Raises:
        ValueError: If the domain input is empty or the domain does not exist in DNS.
    """
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain must be a non-empty string.")

    clean_domain = domain.strip().lower()
    clean_domain = re.sub(r"^https?://", "", clean_domain).split("/")[0].split(":")[0]

    if not clean_domain:
        raise ValueError("Domain name cannot be empty.")

    try:
        return socket.gethostbyname(clean_domain)
    except socket.gaierror as err:
        raise ValueError(
            f"Failed to resolve domain '{clean_domain}': Domain does not exist or DNS lookup failed."
        ) from err
    except socket.herror as err:
        raise ValueError(f"Host error encountered while resolving '{clean_domain}': {err}") from err
    except socket.error as err:
        raise ValueError(f"Socket error while resolving '{clean_domain}': {err}") from err


def is_valid_hostname(hostname: str) -> bool:
    """Validates if a target string adheres to RFC 1123 DNS hostname rules."""
    if not hostname or not isinstance(hostname, str):
        return False

    cleaned = hostname.strip().rstrip(".")
    if len(cleaned) < 1 or len(cleaned) > 253:
        return False

    allowed = re.compile(r"^(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in cleaned.split("."))


def resolve_target(target: str) -> Tuple[str, str]:
    """
    Validates and resolves the target into (canonical_name, ipv4_address).

    Args:
        target: IPv4 address, CIDR range, or domain name.

    Returns:
        Tuple of (target_name, resolved_ipv4_address).

    Raises:
        ValueError: If the target is neither a valid IPv4/CIDR nor a resolvable hostname.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target cannot be empty.")

    cleaned = target.strip()

    # 1. Direct IPv4 validation
    if is_valid_ipv4(cleaned):
        return cleaned, cleaned

    # 2. CIDR Range fallback for single target resolver
    if is_valid_cidr(cleaned):
        hosts = parse_cidr(cleaned)
        if hosts:
            return cleaned, hosts[0]

    # 3. Domain / Hostname resolution
    resolved_ip = resolve_domain(cleaned)
    if resolved_ip:
        return cleaned, resolved_ip

    raise ValueError(
        f"Unable to resolve target '{cleaned}': Target is not a valid IPv4 address/CIDR range and domain does not exist."
    )


def resolve_targets(target: str) -> List[Tuple[str, str]]:
    """
    Validates and resolves a target specification, which may be a CIDR range
    (e.g., '192.168.1.0/24'), a single IPv4 address, or a resolvable domain name.

    Args:
        target: Target specification string.

    Returns:
        List of (canonical_name, resolved_ipv4_address) tuples for all hosts to be scanned.

    Raises:
        ValueError: If target is empty, malformed, or unresolvable.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target cannot be empty.")

    cleaned = target.strip()

    # 1. CIDR Network range
    if is_valid_cidr(cleaned):
        hosts = parse_cidr(cleaned)
        if not hosts:
            raise ValueError(f"No usable hosts found in CIDR range '{cleaned}'.")
        return [(ip, ip) for ip in hosts]

    # 2. Single IPv4 address or domain name
    return [resolve_target(cleaned)]

