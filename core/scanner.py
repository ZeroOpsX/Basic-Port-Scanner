"""
PortScanner engine implementation using socket connect_ex and ThreadPoolExecutor.
Classifies port states into OPEN, CLOSED (RST/refusal), and FILTERED (timeout).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
import logging
import socket
from typing import Callable, Dict, List, Optional

from .constants import COMMON_PORTS, DEFAULT_TIMEOUT, DEFAULT_THREADS

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

    Examples:
        >>> scan_port("127.0.0.1", 80, timeout=1.0)
        'CLOSED'
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
            return PortStatus.CLOSED if status == 111 or status == 10061 else PortStatus.FILTERED

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
        include_closed: bool = False,
    ) -> Optional[Dict]:
        """
        Scans an individual TCP port on the scanner target and classifies its state.

        Args:
            port: Port number to scan.
            grab_banner: Whether to attempt banner grabbing on open ports.
            timeout: Optional per-call timeout override; defaults to self.timeout.
            include_closed: If True, returns result even if port is CLOSED or FILTERED.

        Returns:
            Dictionary with port info and classified state ("OPEN", "CLOSED", or "FILTERED").
        """
        active_timeout = timeout if timeout is not None else self.timeout
        state = scan_port(self.target_ip, port, timeout=active_timeout)

        if not include_closed and state != PortStatus.OPEN:
            return None

        service = COMMON_PORTS.get(port, "Unknown")
        banner = ""
        if state == PortStatus.OPEN and grab_banner:
            banner = self._grab_banner(port, timeout=active_timeout)

        return {
            "port": port,
            "state": str(state),
            "service": service,
            "banner": banner,
        }

    def _grab_banner(self, port: int, timeout: Optional[float] = None) -> str:
        """Attempt to grab a service banner from an open port."""
        active_timeout = timeout if timeout is not None else self.timeout
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(active_timeout)
            if sock.connect_ex((self.target_ip, port)) == 0:
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
