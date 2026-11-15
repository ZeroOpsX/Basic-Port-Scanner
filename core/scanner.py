"""
PortScanner engine implementation using socket connect_ex and ThreadPoolExecutor.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import Callable, Dict, List, Optional

from .constants import COMMON_PORTS, DEFAULT_TIMEOUT, DEFAULT_THREADS


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """
    Checks if a single TCP port is open on a target IP address.

    Uses socket.AF_INET for IPv4 and socket.SOCK_STREAM for TCP.
    Calls connect_ex(), which returns 0 if the connection succeeded (port open),
    or an errno error code if closed / filtered.

    Args:
        ip: Target IPv4 address or hostname string.
        port: TCP port number (1-65535).
        timeout: Socket connection timeout in seconds (default: 1.5s).

    Returns:
        True if the port is open (connect_ex returns 0), False otherwise.

    Examples:
        >>> scan_port("127.0.0.1", 80, timeout=1.0)
        False
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        status = sock.connect_ex((ip, port))
        return status == 0
    except (socket.timeout, socket.error, OSError):
        return False
    finally:
        sock.close()


class PortScanner:
    """Multi-threaded TCP Port Scanner Engine."""

    def __init__(
        self,
        target: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_THREADS,
    ):
        self.raw_target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.target_ip = self._resolve_target(target)

    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IPv4 address."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as err:
            raise ValueError(f"Unable to resolve host '{target}': {err}") from err

    def scan_port(
        self,
        port: int,
        grab_banner: bool = False,
        timeout: Optional[float] = None,
    ) -> Optional[Dict]:
        """
        Scans an individual TCP port on the scanner target.

        Args:
            port: Port number to scan.
            grab_banner: Whether to attempt banner grabbing.
            timeout: Optional per-call timeout override; defaults to self.timeout.

        Returns:
            Dictionary with port info if open, or None if closed.
        """
        active_timeout = timeout if timeout is not None else self.timeout
        is_open = scan_port(self.target_ip, port, timeout=active_timeout)
        if not is_open:
            return None

        service = COMMON_PORTS.get(port, "Unknown")
        banner = ""
        if grab_banner:
            banner = self._grab_banner(port, timeout=active_timeout)

        return {
            "port": port,
            "state": "OPEN",
            "service": service,
            "banner": banner,
        }

    def _grab_banner(self, port: int, timeout: Optional[float] = None) -> str:
        """Attempt to grab a service banner from an open port."""
        active_timeout = timeout if timeout is not None else self.timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(active_timeout)
        try:
            if sock.connect_ex((self.target_ip, port)) == 0:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner.splitlines()[0] if banner else ""
            return ""
        except (socket.timeout, socket.error, OSError):
            return ""
        finally:
            sock.close()

    def scan_ports(
        self,
        ports: List[int],
        grab_banner: bool = False,
        timeout: Optional[float] = None,
        on_port_scanned: Optional[Callable[[Dict], None]] = None,
    ) -> List[Dict]:
        """
        Scans a list of ports concurrently using ThreadPoolExecutor.

        Args:
            ports: List of port integers to scan.
            grab_banner: Flag to attempt service banner grabbing.
            timeout: Optional dynamic timeout override for each port scan.
            on_port_scanned: Optional callback function triggered when an open port is discovered.

        Returns:
            Sorted list of open port detail dictionaries.
        """
        active_timeout = timeout if timeout is not None else self.timeout
        open_ports: List[Dict] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port, grab_banner, active_timeout): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                res = future.result()
                if res:
                    open_ports.append(res)
                    if on_port_scanned:
                        on_port_scanned(res)

        # Sort results numerically by port number
        open_ports.sort(key=lambda x: x["port"])
        return open_ports
