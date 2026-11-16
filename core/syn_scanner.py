"""
NetPulse Raw TCP SYN (Stealth / Half-Open) Port Scanner Module.
Uses Scapy to craft and transmit raw IP/TCP SYN packets, inspects SYN-ACK and RST
responses, and tears down connections with RST packets without completing the
standard TCP 3-way handshake.

Requires administrative (Windows) or root (Linux/Unix/macOS) privileges to create
raw socket frames.
"""

import ctypes
import logging
import os
import platform
import queue
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

try:
    from .constants import COMMON_PORTS, DEFAULT_TIMEOUT
except ImportError:
    try:
        from utils.config import COMMON_PORTS, DEFAULT_TIMEOUT
    except ImportError:
        DEFAULT_TIMEOUT = 1.5
        COMMON_PORTS = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS"}

try:
    from utils.logger import logger
except ImportError:
    logger = logging.getLogger("NetPulse")

# Flag indicating if Scapy is installed
try:
    from scapy.all import ICMP, IP, TCP, conf, send, sr1
    # Disable Scapy verbose runtime console outputs
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    IP = None
    TCP = None
    ICMP = None
    sr1 = None
    send = None
    SCAPY_AVAILABLE = False


def is_root_or_admin() -> bool:
    """
    Verifies if the current execution context has administrative or superuser privileges.

    Returns:
        True if running with Administrator (Windows) or root (UID 0 on Linux/macOS).
    """
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def check_admin_privileges() -> None:
    """
    Enforces root or administrator privileges, raising PermissionError if lacking.
    """
    if not is_root_or_admin():
        elevate_msg = (
            "Run as Administrator in an elevated PowerShell/Command Prompt."
            if platform.system() == "Windows"
            else "Run with sudo or as root user: 'sudo python main.py -sS ...'"
        )
        raise PermissionError(
            f"TCP SYN scan (-sS) requires administrative/root privileges to craft raw packets.\n{elevate_msg}"
        )


def syn_scan_port(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    src_port: Optional[int] = None,
    enforce_admin: bool = True,
) -> Dict[str, Any]:
    """
    Scans a single TCP port using a raw TCP SYN packet (Half-Open Stealth Scan).

    Packet Flow:
      1. Send TCP SYN (flags="S") with randomized sequence and source port.
      2. If target responds with SYN-ACK (flags=0x12 or 'SA'):
         -> Port is OPEN.
         -> Immediately transmit raw RST (flags="R") to tear down connection
            without completing the 3-way handshake.
      3. If target responds with RST or RST-ACK (flags=0x14, 0x04, or 'R'):
         -> Port is CLOSED.
      4. If target does not respond within timeout or ICMP unreachable returned:
         -> Port is FILTERED.

    Args:
        ip: Target IP address or hostname.
        port: TCP port number (1-65535).
        timeout: Packet wait timeout in seconds.
        src_port: Optional custom source port (default: random high port 1024-65535).
        enforce_admin: Whether to assert root/admin privileges before sending.

    Returns:
        Dictionary containing scan results:
          - 'port': int
          - 'protocol': 'tcp'
          - 'state': str ('OPEN', 'CLOSED', 'FILTERED')
          - 'service': str
          - 'flags': str
    """
    if enforce_admin:
        check_admin_privileges()

    if not SCAPY_AVAILABLE:
        raise ImportError(
            "Scapy is required for raw TCP SYN scanning. Please install it using 'pip install scapy'."
        )

    service = COMMON_PORTS.get(port, "Unknown")
    s_port = src_port or random.randint(1024, 65535)
    seq_num = random.randint(1000, 999999)

    try:
        # Craft raw IP / TCP SYN packet
        syn_packet = IP(dst=ip) / TCP(sport=s_port, dport=port, flags="S", seq=seq_num)

        # Transmit packet and await single response
        resp = sr1(syn_packet, timeout=timeout, verbose=0)

        # 1. No response -> Packet dropped or filtered by firewall
        if resp is None:
            return {
                "port": port,
                "protocol": "tcp",
                "state": "FILTERED",
                "service": service,
                "flags": "None",
            }

        # 2. TCP Layer Response received
        if resp.haslayer(TCP):
            tcp_layer = resp.getlayer(TCP)
            tcp_flags = tcp_layer.flags

            # SYN-ACK Response: Port is OPEN
            # (flag integer 0x12, or Flag enum containing 'S' and 'A')
            is_syn_ack = False
            if isinstance(tcp_flags, int):
                is_syn_ack = (tcp_flags & 0x12) == 0x12
            else:
                flag_str = str(tcp_flags).upper()
                is_syn_ack = ("S" in flag_str and "A" in flag_str) or flag_str == "SA"

            if is_syn_ack:
                # Send RST to tear down connection cleanly without 3-way handshake completion
                try:
                    ack_num = getattr(tcp_layer, "ack", seq_num + 1)
                    rst_pkt = IP(dst=ip) / TCP(
                        sport=s_port,
                        dport=port,
                        flags="R",
                        seq=ack_num,
                    )
                    send(rst_pkt, verbose=0)
                except Exception as rst_err:
                    logger.debug(f"Failed to send RST packet to {ip}:{port}: {rst_err}")

                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "OPEN",
                    "service": service,
                    "flags": str(tcp_flags),
                }

            # RST / RST-ACK Response: Port is CLOSED
            is_rst = False
            if isinstance(tcp_flags, int):
                is_rst = bool(tcp_flags & 0x04)
            else:
                flag_str = str(tcp_flags).upper()
                is_rst = "R" in flag_str

            if is_rst:
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "CLOSED",
                    "service": service,
                    "flags": str(tcp_flags),
                }

            # Any other TCP flags
            return {
                "port": port,
                "protocol": "tcp",
                "state": "FILTERED",
                "service": service,
                "flags": str(tcp_flags),
            }

        # 3. ICMP unreachable received -> FILTERED
        if resp.haslayer(ICMP):
            icmp_layer = resp.getlayer(ICMP)
            return {
                "port": port,
                "protocol": "tcp",
                "state": "FILTERED",
                "service": service,
                "flags": f"ICMP Type {icmp_layer.type} Code {icmp_layer.code}",
            }

        return {
            "port": port,
            "protocol": "tcp",
            "state": "FILTERED",
            "service": service,
            "flags": "Unknown",
        }

    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as err:
        logger.debug(f"SYN scan error on {ip}:{port} -> {err}")
        return {
            "port": port,
            "protocol": "tcp",
            "state": "FILTERED",
            "service": service,
            "flags": f"Error: {err}",
        }


def syn_scan_ports(
    ip: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = 20,
    rate_limit_ms: float = 0.0,
    on_port_scanned: Optional[Callable[[Dict[str, Any]], None]] = None,
    enforce_admin: bool = True,
) -> List[Dict[str, Any]]:
    """
    Executes concurrent raw TCP SYN stealth port scan across target ports.

    Args:
        ip: Target host IP address.
        ports: List of TCP port integers.
        timeout: Probe timeout in seconds.
        max_workers: Thread concurrency count (default: 20).
        rate_limit_ms: Milliseconds delay between probes.
        on_port_scanned: Callback invoked when an OPEN port is discovered.
        enforce_admin: Enforces root/admin check.

    Returns:
        Sorted list of discovered open port result dictionaries.
    """
    if enforce_admin:
        check_admin_privileges()

    if not SCAPY_AVAILABLE:
        raise ImportError(
            "Scapy is required for raw TCP SYN scanning. Please install it using 'pip install scapy'."
        )

    if not ports:
        return []

    port_queue: queue.Queue = queue.Queue()
    for port in ports:
        port_queue.put(port)

    workers = max(1, min(max_workers, len(ports)))
    results: List[Dict[str, Any]] = []
    results_lock = threading.Lock()

    def _worker():
        while True:
            try:
                port = port_queue.get_nowait()
            except queue.Empty:
                break

            try:
                if rate_limit_ms > 0:
                    time.sleep(rate_limit_ms / 1000.0)

                res = syn_scan_port(
                    ip, port, timeout=timeout, enforce_admin=False
                )
                if res["state"] == "OPEN":
                    with results_lock:
                        results.append(res)
                        if on_port_scanned:
                            on_port_scanned(res)
            except Exception as err:
                logger.error(f"Error during SYN scan on port {port}: {err}")
            finally:
                port_queue.task_done()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_worker) for _ in range(workers)]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as err:
                logger.error(f"SYN scan worker error: {err}")

    results.sort(key=lambda x: x["port"])
    return results


class SYNScanner:
    """
    Raw TCP SYN Stealth Port Scanner.
    Crafts raw IP/TCP packets with SYN flags and intercepts SYN-ACK/RST responses.
    """

    def __init__(
        self,
        target: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = 20,
        rate_limit_ms: float = 0.0,
        enforce_admin: bool = True,
    ):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limit_ms = rate_limit_ms
        if enforce_admin:
            check_admin_privileges()

    def scan_port(self, port: int) -> Dict[str, Any]:
        """Audits a single port via TCP SYN packet."""
        return syn_scan_port(
            self.target,
            port,
            timeout=self.timeout,
            enforce_admin=False,
        )

    def scan_ports(
        self,
        ports: List[int],
        on_port_scanned: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> List[Dict[str, Any]]:
        """Audits target ports via concurrent TCP SYN packets."""
        return syn_scan_ports(
            self.target,
            ports,
            timeout=self.timeout,
            max_workers=self.max_workers,
            rate_limit_ms=self.rate_limit_ms,
            on_port_scanned=on_port_scanned,
            enforce_admin=False,
        )
