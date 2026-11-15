"""
Target and Network Input Validation Module for NetPulse.
Uses Python's standard `ipaddress` module for robust IP address verification.
"""

import ipaddress
import re
import socket
from typing import Optional, Tuple


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
        ip = ipaddress.IPv4Address(cleaned_target)
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


def is_valid_hostname(hostname: str) -> bool:
    """
    Validates if a target string adheres to RFC 1123 DNS hostname rules.
    """
    if not hostname or not isinstance(hostname, str):
        return False

    cleaned = hostname.strip().rstrip(".")
    if len(cleaned) < 1 or len(cleaned) > 253:
        return False

    # Regex for standard domain names and hostnames (including localhost)
    allowed = re.compile(r"^(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in cleaned.split("."))


def resolve_target(target: str) -> Tuple[str, str]:
    """
    Validates and resolves the target into (canonical_name, ipv4_address).

    Args:
        target: IPv4 address or domain name.

    Returns:
        Tuple of (target_name, resolved_ipv4_address).

    Raises:
        ValueError: If the target is neither a valid IPv4 address nor a resolvable hostname.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target cannot be empty.")

    cleaned = target.strip()

    # 1. Direct IPv4 validation
    if is_valid_ipv4(cleaned):
        return cleaned, cleaned

    # 2. Hostname resolution fallback
    if is_valid_hostname(cleaned):
        try:
            resolved_ip = socket.gethostbyname(cleaned)
            return cleaned, resolved_ip
        except socket.gaierror as err:
            raise ValueError(f"Unable to resolve domain/hostname '{cleaned}': {err}")

    raise ValueError(f"Invalid target '{cleaned}': Must be a valid IPv4 address or resolvable hostname.")


if __name__ == "__main__":
    test_ips = ["127.0.0.1", "192.168.1.1", "256.0.0.1", "google.com", "::1", "", "10.0.0.255"]
    for ip in test_ips:
        print(f"Target: {ip:<15} -> Valid IPv4: {is_valid_ipv4(ip)}")
