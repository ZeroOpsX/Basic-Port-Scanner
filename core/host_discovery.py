"""
Host discovery module for NetPulse.
Determines if a remote target is active before port scanning using
ICMP echo requests (system ping) with TCP ping fallback.
"""

import platform
import socket
import subprocess
from typing import List, Optional

try:
    from utils.logger import logger
except ImportError:
    import logging
    logger = logging.getLogger("NetPulse")


def icmp_ping(target: str, timeout: float = 2.0) -> bool:
    """
    Performs an ICMP Echo Request using the operating system's native ping utility.

    Args:
        target: Target IP address or domain name.
        timeout: Maximum duration in seconds to wait for a reply.

    Returns:
        True if the host responds to ICMP ping, False otherwise.
    """
    system_os = platform.system().lower()

    if system_os == "windows":
        # Windows ping: -n (count), -w (timeout in milliseconds)
        timeout_ms = max(500, int(timeout * 1000))
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), target]
    else:
        # Linux / macOS ping: -c (count), -W (timeout in seconds)
        timeout_sec = max(1, int(timeout))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), target]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1.0,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as err:
        logger.debug(f"ICMP ping failed on {target}: {err}")
        return False


def tcp_ping(target: str, port: int = 80, timeout: float = 2.0) -> bool:
    """
    Performs a TCP ping on a specific port to check if the host is reachable.
    Useful when ICMP packets are filtered or blocked by firewalls.

    Args:
        target: Target IP address or hostname.
        port: TCP port to probe (default: 80).
        timeout: Socket connection timeout in seconds.

    Returns:
        True if the TCP connection succeeds (or sends an active reset), False on timeout/unreachable.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # connect_ex returns 0 if connected, or error code
        status = sock.connect_ex((target, port))
        return status == 0
    except (socket.timeout, socket.gaierror, socket.error, OSError):
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def is_host_online(
    target: str,
    timeout: float = 2.0,
    fallback_ports: Optional[List[int]] = None,
) -> bool:
    """
    Checks if the target host is online before running a comprehensive port scan.

    Execution Flow:
      1. Attempts an ICMP ping.
      2. If ICMP fails (common due to firewall rules), falls back to a TCP ping
         on standard web/system ports (e.g., 80, 443).

    Args:
        target: Target IP address or hostname.
        timeout: Timeout per probe in seconds.
        fallback_ports: List of TCP ports to try if ICMP fails (default: [80, 443]).

    Returns:
        True if host is responsive via ICMP or TCP ping, False otherwise.
    """
    if fallback_ports is None:
        fallback_ports = [80, 443]

    # 1. Primary check: ICMP Ping
    if icmp_ping(target, timeout=timeout):
        logger.debug(f"Host '{target}' is online via ICMP Echo.")
        return True

    # 2. Secondary check: TCP Ping fallback
    for port in fallback_ports:
        if tcp_ping(target, port=port, timeout=timeout):
            logger.debug(f"Host '{target}' is online via TCP probe on port {port}.")
            return True

    return False


if __name__ == "__main__":
    test_targets = ["127.0.0.1", "google.com", "192.0.2.1"]
    for t in test_targets:
        online = is_host_online(t, timeout=1.0)
        status_text = "ONLINE" if online else "OFFLINE/UNREACHABLE"
        print(f"Target: {t:<20} Status: {status_text}")
