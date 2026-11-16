"""
NetPulse UDP Port Scanner Module.
Implements asynchronous and concurrent UDP port scanning using SOCK_DGRAM
with specialized application-layer protocol probes for common UDP services
including DNS (port 53), NTP (port 123), SNMP (port 161), TFTP (port 69),
and NetBIOS (port 137).
"""

import errno
import logging
import queue
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

try:
    from .constants import (
        COMMON_UDP_PORTS,
        COMMON_UDP_PORTS_LIST,
        DEFAULT_THREADS,
        DEFAULT_TIMEOUT,
    )
except ImportError:
    try:
        from utils.config import (
            COMMON_UDP_PORTS,
            COMMON_UDP_PORTS_LIST,
            DEFAULT_THREADS,
            DEFAULT_TIMEOUT,
        )
    except ImportError:
        DEFAULT_TIMEOUT = 1.5
        DEFAULT_THREADS = 100
        COMMON_UDP_PORTS = {
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            69: "TFTP",
            123: "NTP",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            161: "SNMP",
            162: "SNMP-Trap",
            500: "ISAKMP",
            514: "Syslog",
            520: "RIP",
            1900: "SSDP",
            5353: "mDNS",
        }
        COMMON_UDP_PORTS_LIST = sorted(list(COMMON_UDP_PORTS.keys()))

try:
    from utils.logger import logger
except ImportError:
    logger = logging.getLogger("NetPulse")

# Errno definitions for ICMP Port Unreachable (RST/unreachable feedback)
UDP_CLOSED_ERRNOS = {
    errno.ECONNREFUSED,  # 111 on Linux
}
if hasattr(errno, "ECONNRESET"):
    UDP_CLOSED_ERRNOS.add(errno.ECONNRESET)
# Windows Winsock error codes (WSAECONNRESET=10054, WSAECONNREFUSED=10061)
UDP_CLOSED_ERRNOS.update({10054, 10061})

# ==============================================================================
# Protocol-Specific UDP Probes
# ==============================================================================

# DNS (Port 53): Standard DNS Query for '.' (root) record (Type A, Class IN)
DNS_PROBE = (
    b"\x13\x37"  # Transaction ID
    b"\x01\x00"  # Flags: Standard query, Recursion desired
    b"\x00\x01"  # Questions: 1
    b"\x00\x00"  # Answer RRs: 0
    b"\x00\x00"  # Authority RRs: 0
    b"\x00\x00"  # Additional RRs: 0
    b"\x00"      # Root name (empty label)
    b"\x00\x01"  # Type: A (Host Address)
    b"\x00\x01"  # Class: IN (Internet)
)

# NTP (Port 123): NTP client mode 3 request (48 bytes: LI=0, VN=3, Mode=3)
NTP_PROBE = b"\x1b" + (47 * b"\x00")

# SNMP (Port 161): SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) community 'public'
SNMP_PROBE = (
    b"\x30\x26"                                  # SEQUENCE (38 bytes)
    b"\x02\x01\x00"                              # Version: 1 (0)
    b"\x04\x06public"                            # Community: 'public'
    b"\xa0\x19"                                  # GetRequest PDU (25 bytes)
    b"\x02\x01\x00"                              # Request ID: 0
    b"\x02\x01\x00"                              # Error status: 0
    b"\x02\x01\x00"                              # Error index: 0
    b"\x30\x0e"                                  # VarBindList (14 bytes)
    b"\x30\x0c"                                  # VarBind (12 bytes)
    b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
    b"\x05\x00"                                  # Value: NULL
)

# TFTP (Port 69): Read Request (RRQ) for file 'netpulse', mode 'octet'
TFTP_PROBE = b"\x00\x01netpulse\x00octet\x00"

# NetBIOS Name Service (Port 137): Node Status Query
NETBIOS_PROBE = (
    b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41"
    b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
)

# Generic fallback probe (4 null bytes)
GENERIC_UDP_PROBE = b"\x00\x00\x00\x00"

# Registry of port -> probe bytes
UDP_PROBES: Dict[int, bytes] = {
    53: DNS_PROBE,
    69: TFTP_PROBE,
    123: NTP_PROBE,
    137: NETBIOS_PROBE,
    161: SNMP_PROBE,
}


def parse_udp_response(port: int, data: bytes) -> str:
    """
    Parses application layer payload from a UDP response into a descriptive banner.

    Args:
        port: UDP port number.
        data: Raw received payload bytes.

    Returns:
        Human-readable summary or extracted banner string.
    """
    if not data:
        return ""

    if port == 53:
        if len(data) >= 12:
            rcode = data[3] & 0x0F
            status = "NoError" if rcode == 0 else f"RCode={rcode}"
            return f"DNS Response ({status}, {len(data)} bytes)"
        return f"DNS Response ({len(data)} bytes)"

    if port == 123:
        if len(data) >= 48:
            stratum = data[1]
            version = (data[0] >> 3) & 0x07
            mode = data[0] & 0x07
            return f"NTP Server Response (Stratum {stratum}, v{version}, Mode {mode})"
        return f"NTP Response ({len(data)} bytes)"

    if port == 161:
        if b"public" in data or len(data) > 10:
            # Attempt to extract printable strings (like sysDescr)
            printable = "".join(
                chr(b) if 32 <= b <= 126 else " " for b in data[16:]
            ).strip()
            if printable:
                words = [w for w in printable.split() if len(w) > 2]
                if words:
                    return f"SNMP Response ({' '.join(words[:6])})"
            return f"SNMP Response ({len(data)} bytes)"
        return f"SNMP Response ({len(data)} bytes)"

    if port == 69:
        if len(data) >= 4 and data[:2] == b"\x00\x05":
            # TFTP Error packet (Opcode 5)
            err_msg = data[4:].decode("ascii", errors="ignore").rstrip("\x00")
            return f"TFTP Error: {err_msg}" if err_msg else "TFTP Error Response"
        return f"TFTP Response ({len(data)} bytes)"

    if port == 137:
        return f"NetBIOS Name Service Response ({len(data)} bytes)"

    # Generic printable banner extraction
    printable = "".join(chr(b) if 32 <= b <= 126 else "" for b in data).strip()
    if len(printable) >= 4:
        return printable[:64]

    return f"UDP Response ({len(data)} bytes)"


def scan_udp_port(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    probe: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    Audits a single UDP port using SOCK_DGRAM and protocol-specific probes.

    Classification:
      - 'OPEN': A UDP response payload was received from the target host.
      - 'CLOSED': Received an active ICMP Port Unreachable packet (ECONNREFUSED / WSAECONNRESET).
      - 'OPEN|FILTERED': Socket timed out without receiving any packet or ICMP error.

    Args:
        ip: Target IPv4 address or hostname string.
        port: UDP port number (1-65535).
        timeout: Socket communication timeout in seconds.
        probe: Custom payload bytes to transmit (default: protocol-specific probe or null bytes).

    Returns:
        Dictionary containing scan results:
          - 'port': int
          - 'protocol': 'udp'
          - 'state': str ('OPEN', 'CLOSED', 'OPEN|FILTERED')
          - 'service': str
          - 'banner': str
          - 'raw_response': bytes
    """
    service = COMMON_UDP_PORTS.get(port, "Unknown")
    payload = probe if probe is not None else UDP_PROBES.get(port, GENERIC_UDP_PROBE)
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Calling connect on a UDP socket establishes a default destination address,
        # which permits the OS kernel to route ICMP port unreachable errors to recv().
        sock.connect((ip, port))
        sock.send(payload)

        data = sock.recv(1024)
        banner = parse_udp_response(port, data)
        return {
            "port": port,
            "protocol": "udp",
            "state": "OPEN",
            "service": service,
            "banner": banner,
            "raw_response": data,
        }

    except (ConnectionResetError, ConnectionRefusedError) as err:
        return {
            "port": port,
            "protocol": "udp",
            "state": "CLOSED",
            "service": service,
            "banner": "",
            "raw_response": b"",
        }

    except (socket.timeout, TimeoutError):
        return {
            "port": port,
            "protocol": "udp",
            "state": "OPEN|FILTERED",
            "service": service,
            "banner": "",
            "raw_response": b"",
        }

    except OSError as err:
        err_code = getattr(err, "errno", None)
        win_code = getattr(err, "winerror", None)

        if err_code in UDP_CLOSED_ERRNOS or win_code in UDP_CLOSED_ERRNOS:
            return {
                "port": port,
                "protocol": "udp",
                "state": "CLOSED",
                "service": service,
                "banner": "",
                "raw_response": b"",
            }
        return {
            "port": port,
            "protocol": "udp",
            "state": "OPEN|FILTERED",
            "service": service,
            "banner": "",
            "raw_response": b"",
        }

    except (KeyboardInterrupt, SystemExit):
        raise

    except Exception as err:
        logger.debug(f"Unexpected error probing UDP {ip}:{port} -> {err}")
        return {
            "port": port,
            "protocol": "udp",
            "state": "FILTERED",
            "service": service,
            "banner": "",
            "raw_response": b"",
        }

    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_udp_ports_concurrent(
    ip: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = 20,
    rate_limit_ms: float = 0.0,
    include_open_filtered: bool = False,
    on_port_scanned: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Executes multi-threaded UDP port scanning across target ports.

    Args:
        ip: Target host IP address or hostname.
        ports: List of UDP port numbers to scan.
        timeout: Socket communication timeout in seconds per port.
        max_workers: Concurrency worker thread count (default: 20).
        rate_limit_ms: Delay in milliseconds between queries per worker thread.
        include_open_filtered: If True, includes 'OPEN|FILTERED' ports in output.
        on_port_scanned: Callback invoked when an open (or open|filtered) port is found.

    Returns:
        Sorted list of discovered UDP port result dictionaries.
    """
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

                res = scan_udp_port(ip, port, timeout=timeout)
                is_open = res["state"] == "OPEN"
                is_open_filtered = include_open_filtered and res["state"] == "OPEN|FILTERED"

                if is_open or is_open_filtered:
                    with results_lock:
                        results.append(res)
                        if on_port_scanned:
                            on_port_scanned(res)

            except Exception as err:
                logger.error(f"Error scanning UDP port {port}: {err}")
            finally:
                port_queue.task_done()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_worker) for _ in range(workers)]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as err:
                logger.error(f"UDP worker thread error: {err}")

    results.sort(key=lambda x: x["port"])
    return results


class UDPScanner:
    """
    High-performance UDP Port Scanner Engine.
    Manages single and batch UDP port scanning with protocol-specific probing.
    """

    def __init__(
        self,
        target: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = 20,
        rate_limit_ms: float = 0.0,
    ):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limit_ms = rate_limit_ms

    def scan_port(self, port: int, probe: Optional[bytes] = None) -> Dict[str, Any]:
        """Audits a single UDP port."""
        return scan_udp_port(self.target, port, timeout=self.timeout, probe=probe)

    def scan_ports(
        self,
        ports: Optional[List[int]] = None,
        include_open_filtered: bool = False,
        on_port_scanned: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> List[Dict[str, Any]]:
        """Audits a list of UDP ports (defaults to COMMON_UDP_PORTS_LIST)."""
        scan_list = ports if ports is not None else list(COMMON_UDP_PORTS_LIST)
        return scan_udp_ports_concurrent(
            ip=self.target,
            ports=scan_list,
            timeout=self.timeout,
            max_workers=self.max_workers,
            rate_limit_ms=self.rate_limit_ms,
            include_open_filtered=include_open_filtered,
            on_port_scanned=on_port_scanned,
        )
