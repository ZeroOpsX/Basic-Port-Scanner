"""
NetPulse Service Detector Module.
Maps open TCP/UDP ports to their standard IANA service names using socket.getservbyport()
with fallback to common cybersecurity port registries and caching.
"""

from functools import lru_cache
import socket
import ssl
from typing import Dict, Iterable, Optional

try:
    from .constants import COMMON_PORTS, DEFAULT_TIMEOUT
except ImportError:
    try:
        from utils.config import COMMON_PORTS, DEFAULT_TIMEOUT
    except ImportError:
        COMMON_PORTS = {}
        DEFAULT_TIMEOUT = 1.5


@lru_cache(maxsize=1024)
def get_iana_service_name(port: int, protocol: str = "tcp") -> Optional[str]:
    """
    Maps an open port to its standard IANA service name using socket.getservbyport().

    Args:
        port: Integer port number (1-65535).
        protocol: Protocol string, typically 'tcp' or 'udp' (default: 'tcp').

    Returns:
        Standard IANA service name (e.g., 'http', 'ssh', 'domain', 'ftp') if registered,
        or None if no IANA mapping exists in the system services database.

    Examples:
        >>> get_iana_service_name(80)
        'http'
        >>> get_iana_service_name(22)
        'ssh'
        >>> get_iana_service_name(443)
        'https'
        >>> get_iana_service_name(54321)
        None
    """
    if not isinstance(port, int) or port < 1 or port > 65535:
        return None

    try:
        return socket.getservbyport(port, protocol)
    except (OSError, OverflowError, ValueError, TypeError):
        return None


def get_service_name(
    port: int,
    protocol: str = "tcp",
    default: str = "unknown",
    fallback_to_common: bool = True,
) -> str:
    """
    Resolves a port to its service name. First queries socket.getservbyport() for
    standard IANA mappings (e.g. 80 -> http, 22 -> ssh). If not found in IANA,
    optionally falls back to known common cybersecurity ports (e.g. MySQL, Redis).

    Args:
        port: TCP/UDP port number (1-65535).
        protocol: Protocol name, 'tcp' or 'udp' (default: 'tcp').
        default: Fallback string if service is unrecognized (default: 'unknown').
        fallback_to_common: Whether to check COMMON_PORTS if IANA returns None.

    Returns:
        Resolved service name string.
    """
    iana = get_iana_service_name(port, protocol)
    if iana:
        return iana

    if fallback_to_common and port in COMMON_PORTS:
        return str(COMMON_PORTS[port]).lower()

    return default


def detect_service(port: int, protocol: str = "tcp") -> str:
    """
    Convenience wrapper to map an open port to its standard IANA service name.

    Args:
        port: TCP port number.
        protocol: Protocol ('tcp' or 'udp').

    Returns:
        Standard IANA service name (e.g., 80 -> 'http', 22 -> 'ssh').
    """
    return get_service_name(port, protocol=protocol)


def map_ports_to_services(
    ports: Iterable[int],
    protocol: str = "tcp",
) -> Dict[int, str]:
    """
    Maps an iterable of ports to their detected service names.

    Args:
        ports: Iterable of integer port numbers.
        protocol: Protocol ('tcp' or 'udp').

    Returns:
        Dictionary mapping port -> service name (e.g. {80: 'http', 22: 'ssh'}).
    """
    return {port: get_service_name(port, protocol) for port in ports}


HTTP_PORTS = {80, 443, 8080}


def extract_http_headers(raw_response: str) -> Dict[str, str]:
    """
    Parses a raw HTTP response string and extracts header key-value pairs,
    specifically focusing on 'Server' and 'X-Powered-By'.

    Args:
        raw_response: Raw decoded HTTP response string from the server.

    Returns:
        Dictionary mapping header names to their extracted values.
    """
    headers: Dict[str, str] = {}
    if not raw_response or not isinstance(raw_response, str):
        return headers

    lines = raw_response.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            name, _, value = line.partition(":")
            clean_name = name.strip()
            clean_val = value.strip()
            headers[clean_name.lower()] = clean_val
            if clean_name.lower() == "server":
                headers["Server"] = clean_val
            elif clean_name.lower() == "x-powered-by":
                headers["X-Powered-By"] = clean_val

    return headers


def grab_http_headers(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, str]:
    """
    Connects to an open HTTP/HTTPS port, sends an HTTP HEAD request,
    and extracts the 'Server' and 'X-Powered-By' response headers.

    Args:
        ip: Target host IP address or hostname.
        port: HTTP port number (e.g., 80, 443, 8080).
        timeout: Socket connection and read timeout in seconds.

    Returns:
        Dictionary containing extracted headers (e.g. {'Server': 'nginx', 'X-Powered-By': 'PHP/8.1'}).
        Empty dict if connection fails or headers are not present.
    """
    sock = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        # Wrap in TLS/SSL context if connecting to port 443
        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                sock = context.wrap_socket(raw_sock, server_hostname=ip)
            except Exception:
                sock = raw_sock
        else:
            sock = raw_sock

        head_request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: NetPulse/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(head_request.encode("utf-8"))

        data = sock.recv(2048)
        if not data:
            return {}

        raw_response = data.decode("utf-8", errors="ignore")
        all_headers = extract_http_headers(raw_response)

        extracted: Dict[str, str] = {}
        if "Server" in all_headers:
            extracted["Server"] = all_headers["Server"]
        if "X-Powered-By" in all_headers:
            extracted["X-Powered-By"] = all_headers["X-Powered-By"]

        return extracted
    except (socket.timeout, socket.error, OSError, ssl.SSLError, KeyboardInterrupt):
        return {}
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def grab_banner(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    probe: bytes = b"\r\n",
) -> str:
    """
    Connects to an open TCP port and retrieves the service response banner.
    If the port is an HTTP/HTTPS port (80, 443, 8080), sends an HTTP HEAD request
    and extracts the 'Server' and 'X-Powered-By' headers.
    Otherwise, sends a dummy byte/newline probe and reads up to 1024 bytes.

    Args:
        ip: Target host IP address or hostname.
        port: TCP port number (1-65535).
        timeout: Socket timeout in seconds (default: 1.5s).
        probe: Payload byte/newline to send to elicit banner response (default: b"\\r\\n").

    Returns:
        Decoded response banner string (up to 1024 bytes), or an empty string on error/timeout.
    """
    # If port is an HTTP/HTTPS port (80, 443, 8080), send an HTTP HEAD request
    if port in HTTP_PORTS:
        http_headers = grab_http_headers(ip, port, timeout=timeout)
        if http_headers:
            parts = []
            if "Server" in http_headers:
                parts.append(f"Server: {http_headers['Server']}")
            if "X-Powered-By" in http_headers:
                parts.append(f"X-Powered-By: {http_headers['X-Powered-By']}")
            if parts:
                return " | ".join(parts)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send a dummy byte/newline to elicit response banner
        try:
            sock.sendall(probe)
        except (socket.error, OSError):
            pass

        data = sock.recv(1024)
        if not data:
            return ""

        return data.decode("utf-8", errors="ignore").strip()
    except (socket.timeout, socket.error, OSError, KeyboardInterrupt):
        return ""
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


class ServiceDetector:
    """
    Service Detection Engine.
    Leverages socket.getservbyport() to identify network services running on open ports.
    """

    def __init__(self, protocol: str = "tcp", fallback_to_common: bool = True):
        self.protocol = protocol
        self.fallback_to_common = fallback_to_common
        self._cache: Dict[int, str] = {}

    def get_service(self, port: int) -> str:
        """
        Resolves a single port to its IANA service name.
        Caches results for high performance during large scans.
        """
        if port not in self._cache:
            self._cache[port] = get_service_name(
                port,
                protocol=self.protocol,
                fallback_to_common=self.fallback_to_common,
            )
        return self._cache[port]

    def get_iana_service(self, port: int) -> Optional[str]:
        """
        Queries socket.getservbyport() directly for official IANA registration.
        """
        return get_iana_service_name(port, protocol=self.protocol)

    def map_ports(self, ports: Iterable[int]) -> Dict[int, str]:
        """
        Maps a collection of ports to their service names.
        """
        return {port: self.get_service(port) for port in ports}

    def grab_banner(self, ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
        """
        Connects to open port and retrieves response banner.
        """
        return grab_banner(ip, port, timeout=timeout)

    def grab_http_headers(self, ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, str]:
        """
        Sends HTTP HEAD request and extracts Server and X-Powered-By headers.
        """
        return grab_http_headers(ip, port, timeout=timeout)
