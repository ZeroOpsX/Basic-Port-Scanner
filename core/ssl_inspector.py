"""
NetPulse SSL/TLS Inspector Module.
Uses Python's standard `ssl` module to inspect open ports for SSL/TLS encryption
and extracts certificate metadata including Common Name (CN), Issuer, and Expiration Date.
"""

from datetime import datetime, timezone
import ipaddress
import os
import socket
import ssl
import tempfile
from typing import Any, Dict, List, Optional, Tuple

try:
    from .constants import DEFAULT_TIMEOUT
except ImportError:
    try:
        from utils.config import DEFAULT_TIMEOUT
    except ImportError:
        DEFAULT_TIMEOUT = 1.5


def _is_ip_address(addr: str) -> bool:
    """Checks if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(addr.strip())
        return True
    except (ValueError, TypeError):
        return False


def _get_rdn_attribute(rdn_seq: Any, target_attr: str) -> str:
    """
    Extracts an attribute value (e.g. 'commonName', 'organizationName')
    from an RDN sequence tuple returned by ssl.getpeercert().
    """
    if not rdn_seq or not isinstance(rdn_seq, (tuple, list)):
        return ""

    for rdn in rdn_seq:
        if isinstance(rdn, (tuple, list)):
            for item in rdn:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    if item[0] == target_attr:
                        return str(item[1])
    return ""


def _format_rdn_sequence(rdn_seq: Any) -> str:
    """
    Formats an RDN tuple into a standardized human-readable string
    (e.g., 'CN=example.com, O=Example Inc, C=US').
    """
    if not rdn_seq or not isinstance(rdn_seq, (tuple, list)):
        return ""

    abbr_map = {
        "commonName": "CN",
        "organizationName": "O",
        "organizationalUnitName": "OU",
        "countryName": "C",
        "stateOrProvinceName": "ST",
        "localityName": "L",
    }

    parts = []
    for rdn in rdn_seq:
        if isinstance(rdn, (tuple, list)):
            for item in rdn:
                if isinstance(item, (tuple, list)) and len(item) >= 2:
                    key = abbr_map.get(item[0], item[0])
                    parts.append(f"{key}={item[1]}")

    return ", ".join(parts)


def parse_certificate_dict(cert_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses a decoded SSL certificate dictionary (from getpeercert or _test_decode_cert)
    into a structured summary containing Common Name (CN), Issuer, and Expiration Date.

    Args:
        cert_dict: Raw certificate dictionary.

    Returns:
        Structured dictionary with normalized certificate metadata.
    """
    if not cert_dict or not isinstance(cert_dict, dict):
        return {
            "common_name": "",
            "issuer": "",
            "issuer_full": "",
            "expiration_date": "",
            "is_expired": False,
            "days_left": None,
        }

    subject = cert_dict.get("subject", ())
    issuer_seq = cert_dict.get("issuer", ())

    # Extract Common Name (CN)
    common_name = _get_rdn_attribute(subject, "commonName")

    # Extract Issuer (prefer CN, fallback to Organization or full RDN string)
    issuer_cn = _get_rdn_attribute(issuer_seq, "commonName")
    issuer_org = _get_rdn_attribute(issuer_seq, "organizationName")
    issuer = issuer_cn or issuer_org or _format_rdn_sequence(issuer_seq)
    issuer_full = _format_rdn_sequence(issuer_seq)

    # Expiration Date (notAfter)
    expiration_date = cert_dict.get("notAfter", "")

    # Calculate days left and expiration status
    is_expired = False
    days_left = None
    if expiration_date:
        try:
            exp_epoch = ssl.cert_time_to_seconds(expiration_date)
            now_epoch = datetime.now(timezone.utc).timestamp()
            days_left = int((exp_epoch - now_epoch) / 86400)
            is_expired = days_left < 0
        except Exception:
            pass

    # Extract SANs (Subject Alternative Names)
    sans: List[str] = []
    for entry in cert_dict.get("subjectAltName", ()):
        if isinstance(entry, (tuple, list)) and len(entry) == 2 and entry[0] == "DNS":
            sans.append(entry[1])

    return {
        "common_name": common_name,
        "issuer": issuer,
        "issuer_full": issuer_full,
        "expiration_date": expiration_date,
        "not_before": cert_dict.get("notBefore", ""),
        "serial_number": cert_dict.get("serialNumber", ""),
        "subject_alt_names": sans,
        "is_expired": is_expired,
        "days_left": days_left,
    }


def inspect_ssl(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    server_hostname: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Connects to an open port and performs an SSL/TLS handshake to extract
    the Common Name (CN), Issuer, and Expiration Date from the certificate.

    Handles valid, self-signed, and expired certificates gracefully without
    rejecting untrusted certificates.

    Args:
        ip: Target host IP address or hostname.
        port: Open port number (e.g. 443, 8443).
        timeout: Socket connection and handshake timeout in seconds.
        server_hostname: Optional SNI hostname (defaults to hostname if not IP).

    Returns:
        Dictionary containing 'common_name', 'issuer', 'expiration_date', and SSL details,
        or None if the port does not use SSL/TLS or connection fails.
    """
    sock = None
    try:
        # Create unverified SSL context to inspect self-signed or unverified certs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        # Set SNI hostname if not a raw IP address
        sni_host = server_hostname if server_hostname else (None if _is_ip_address(ip) else ip)
        sock = ctx.wrap_socket(raw_sock, server_hostname=sni_host)

        # Retrieve connection parameters
        tls_version = sock.version()
        cipher_info = sock.cipher()

        # Retrieve DER certificate bytes
        der_bytes = sock.getpeercert(binary_form=True)
        if not der_bytes:
            return None

        # Convert DER bytes to PEM format
        pem_cert = ssl.DER_cert_to_PEM_cert(der_bytes)

        # Decode PEM certificate using OpenSSL's internal decoder
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as tmp:
            tmp.write(pem_cert)
            tmp_path = tmp.name

        try:
            cert_dict = ssl._ssl._test_decode_cert(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        # Parse extracted certificate attributes
        parsed = parse_certificate_dict(cert_dict)
        parsed["has_ssl"] = True
        parsed["tls_version"] = tls_version
        parsed["cipher"] = cipher_info[0] if cipher_info else None

        return parsed

    except (ssl.SSLError, socket.error, OSError, KeyboardInterrupt):
        # Port does not use SSL/TLS or connection failed
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def get_ssl_certificate(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    server_hostname: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    """
    Simplified helper that returns the core certificate fields:
    Common Name (CN), Issuer, and Expiration Date.

    Args:
        ip: Target host IP or hostname.
        port: Open port number.
        timeout: Timeout in seconds.
        server_hostname: Optional SNI hostname.

    Returns:
        Dict with keys {'common_name', 'issuer', 'expiration_date'}, or None.
    """
    res = inspect_ssl(ip, port, timeout=timeout, server_hostname=server_hostname)
    if not res:
        return None

    return {
        "common_name": res.get("common_name", ""),
        "issuer": res.get("issuer", ""),
        "expiration_date": res.get("expiration_date", ""),
    }


def is_ssl_port(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """
    Determines whether an open port is serving an SSL/TLS encrypted service.

    Args:
        ip: Target host IP or hostname.
        port: TCP port number.
        timeout: Socket timeout in seconds.

    Returns:
        True if an SSL/TLS handshake completes successfully, False otherwise.
    """
    res = inspect_ssl(ip, port, timeout=timeout)
    return res is not None and res.get("has_ssl", False)


class SSLInspector:
    """
    SSL/TLS Certificate Inspector Class.
    Extracts certificate metadata (CN, Issuer, Expiration Date) from open ports.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def inspect(
        self,
        ip: str,
        port: int,
        server_hostname: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Inspects an open port and extracts full SSL certificate metadata."""
        return inspect_ssl(ip, port, timeout=self.timeout, server_hostname=server_hostname)

    def get_certificate(
        self,
        ip: str,
        port: int,
        server_hostname: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Extracts Common Name (CN), Issuer, and Expiration Date."""
        return get_ssl_certificate(ip, port, timeout=self.timeout, server_hostname=server_hostname)

    def is_ssl(self, ip: str, port: int) -> bool:
        """Checks if a port speaks SSL/TLS."""
        return is_ssl_port(ip, port, timeout=self.timeout)
