"""
PortScanner engine implementation using ThreadPoolExecutor for multi-threaded scanning.
Classifies port states into OPEN, CLOSED (RST/refusal), and FILTERED (timeout).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
import logging
import socket
import threading
from typing import Callable, Dict, List, Optional

from .constants import COMMON_PORTS, DEFAULT_THREADS, DEFAULT_TIMEOUT

try:
    from utils.logger import logger
except ImportError:
    logger = logging.getLogger("NetPulse")


class PortStatus(str):
    """
    Port state classification representation.
    Inherits from str so equality checks like `state == 'OPEN'` evaluate normally,
    while `bool(PortStatus.OPEN)` is True and `bool(PortStatus.CLOSED)` is False.
    """
    def __bool__(self) -> bool:
        return self == "OPEN"


PortStatus.OPEN = PortStatus("OPEN")
PortStatus.CLOSED = PortStatus("CLOSED")
PortStatus.FILTERED = PortStatus("FILTERED")

PORT_OPEN = PortStatus.OPEN
PORT_CLOSED = PortStatus.CLOSED
PORT_FILTERED = PortStatus.FILTERED

# Errno definitions for active connection refusal (RST packet / immediate refusal)
CLOSED_ERRNOS = {
    errno.ECONNREFUSED,  # 111 on Linux
}
if hasattr(errno, "ECONNRESET"):
    CLOSED_ERRNOS.add(errno.ECONNRESET)
# Windows Winsock error codes (WSAECONNREFUSED=10061, WSAECONNRESET=10054)
CLOSED_ERRNOS.update({10061, 10054})

# Errno definitions for dropped packets and connection timeouts (Filtered)
FILTERED_ERRNOS = set()
if hasattr(errno, "ETIMEDOUT"):
    FILTERED_ERRNOS.add(errno.ETIMEDOUT)
if hasattr(errno, "EHOSTUNREACH"):
    FILTERED_ERRNOS.add(errno.EHOSTUNREACH)
if hasattr(errno, "ENETUNREACH"):
    FILTERED_ERRNOS.add(errno.ENETUNREACH)
# Windows Winsock error codes (WSAETIMEDOUT=10060, WSAEHOSTUNREACH=10065, WSAENETUNREACH=10051)
FILTERED_ERRNOS.update({10060, 10065, 10051})


def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> PortStatus:
    """
    Checks and classifies a single TCP port on a target IP address.

    Port State Classifications:
      - 'OPEN': Handshake completed successfully (connect_ex returns 0).
      - 'CLOSED': Target responded with an active TCP RST or connection refusal (ECONNREFUSED).
      - 'FILTERED': Probe timed out or dropped by firewall (ETIMEDOUT / socket.timeout).

    Args:
        ip: Target IPv4 address or hostname string.
        port: TCP port number (1-65535).
        timeout: Socket connection timeout in seconds (default: 1.5s).

    Returns:
        PortStatus enum-like string: 'OPEN', 'CLOSED', or 'FILTERED'.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        status = sock.connect_ex((ip, port))

        if status == 0:
            return PortStatus.OPEN
        elif status in CLOSED_ERRNOS:
            return PortStatus.CLOSED
        elif status in FILTERED_ERRNOS:
            return PortStatus.FILTERED
        else:
            return PortStatus.CLOSED if status in (111, 10061) else PortStatus.FILTERED

    except socket.timeout:
        # No response received before timeout: packet dropped or filtered
        return PortStatus.FILTERED
    except socket.gaierror as err:
        logger.error(f"Address resolution failure for target '{ip}': {err}")
        return PortStatus.FILTERED
    except socket.error as err:
        err_code = getattr(err, "errno", None)
        if err_code in CLOSED_ERRNOS or "refus" in str(err).lower():
            return PortStatus.CLOSED
        return PortStatus.FILTERED
    except KeyboardInterrupt:
        return PortStatus.FILTERED
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def grab_banner(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """
    Attempts to retrieve a service banner from an open TCP port.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner.splitlines()[0] if banner else ""
        return ""
    except (socket.timeout, socket.gaierror, socket.error, OSError, KeyboardInterrupt):
        return ""
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_ports_concurrent(
    ip: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_THREADS,
    grab_banners: bool = False,
    include_closed: bool = False,
    on_port_scanned: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Multi-threaded port scanning loop using concurrent.futures.ThreadPoolExecutor.

    Distributes port checks across a worker pool, yielding real-time callback
    events and returning a sorted list of discovered open ports.

    Args:
        ip: Target IPv4 address or hostname.
        ports: List of port integers to scan.
        timeout: Socket timeout per port in seconds.
        max_workers: Concurrency thread pool size (default: 100).
        grab_banners: Whether to attempt service banner grabbing on open ports.
        include_closed: If True, includes CLOSED and FILTERED ports in results.
        on_port_scanned: Optional callback function invoked when a port probe completes.

    Returns:
        Sorted list of discovered port dictionaries.
    """
    if not ports:
        return []

    workers = max(1, min(max_workers, len(ports)))
    results: List[Dict] = []
    results_lock = threading.Lock()

    def _worker(port: int) -> None:
        state = scan_port(ip, port, timeout=timeout)
        if not include_closed and state != PortStatus.OPEN:
            return

        service = COMMON_PORTS.get(port, "Unknown")
        banner = ""
        if state == PortStatus.OPEN and grab_banners:
            banner = grab_banner(ip, port, timeout=timeout)

        record = {
            "port": port,
            "state": str(state),
            "service": service,
            "banner": banner,
        }

        # Thread-safe synchronization: acquire lock before appending to shared list
        with results_lock:
            results.append(record)
            if on_port_scanned:
                on_port_scanned(record)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {executor.submit(_worker, port): port for port in ports}

        for future in as_completed(future_to_port):
            try:
                future.result()
            except Exception as err:
                logger.error(f"Error scanning port {future_to_port[future]}: {err}")

    # Sort results numerically by port number
    results.sort(key=lambda x: x["port"])
    return results


class PortScanner:
    """Multi-threaded TCP Port Scanner Engine leveraging ThreadPoolExecutor."""

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
        self.lock = threading.Lock()

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
        include_closed: bool = False,
    ) -> Optional[Dict]:
        """
        Scans an individual TCP port on the scanner target.
        """
        active_timeout = timeout if timeout is not None else self.timeout
        state = scan_port(self.target_ip, port, timeout=active_timeout)

        if not include_closed and state != PortStatus.OPEN:
            return None

        service = COMMON_PORTS.get(port, "Unknown")
        banner = ""
        if state == PortStatus.OPEN and grab_banner:
            banner = grab_banner(self.target_ip, port, timeout=active_timeout)

        return {
            "port": port,
            "state": str(state),
            "service": service,
            "banner": banner,
        }

    def scan_ports(
        self,
        ports: List[int],
        grab_banner: bool = False,
        timeout: Optional[float] = None,
        on_port_scanned: Optional[Callable[[Dict], None]] = None,
        include_closed: bool = False,
    ) -> List[Dict]:
        """
        Multi-threaded scanning loop using ThreadPoolExecutor.
        """
        active_timeout = timeout if timeout is not None else self.timeout
        return scan_ports_concurrent(
            ip=self.target_ip,
            ports=ports,
            timeout=active_timeout,
            max_workers=self.max_workers,
            grab_banners=grab_banner,
            include_closed=include_closed,
            on_port_scanned=on_port_scanned,
        )
