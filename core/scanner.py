"""PortScanner engine implementation using ThreadPoolExecutor."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import Callable, Dict, List, Optional

from .constants import COMMON_PORTS, DEFAULT_TIMEOUT, DEFAULT_THREADS


class PortScanner:
    """Multi-threaded TCP Port Scanner."""

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
        except socket.gaierror as e:
            raise ValueError(f"Unable to resolve host '{target}': {e}")

    def scan_port(self, port: int, grab_banner: bool = False) -> Optional[Dict]:
        """Scan an individual TCP port. Returns dict if open, None if closed."""
        result = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            status = sock.connect_ex((self.target_ip, port))
            if status == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = ""
                if grab_banner:
                    banner = self._grab_banner(sock)
                result = {
                    "port": port,
                    "state": "OPEN",
                    "service": service,
                    "banner": banner,
                }
        except socket.error:
            pass
        finally:
            sock.close()

        return result

    def _grab_banner(self, sock: socket.socket) -> str:
        """Attempt to grab a service banner from an open socket."""
        try:
            # Send standard probe byte if needed or just listen
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            # Return first line or truncated banner
            return banner.splitlines()[0] if banner else ""
        except (socket.timeout, socket.error):
            return ""

    def scan_ports(
        self,
        ports: List[int],
        grab_banner: bool = False,
        on_port_scanned: Optional[Callable[[Dict], None]] = None,
    ) -> List[Dict]:
        """Scan a list of ports concurrently using thread pool."""
        open_ports: List[Dict] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port, grab_banner): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                res = future.result()
                if res:
                    open_ports.append(res)
                    if on_port_scanned:
                        on_port_scanned(res)

        # Sort results by port number
        open_ports.sort(key=lambda x: x["port"])
        return open_ports
