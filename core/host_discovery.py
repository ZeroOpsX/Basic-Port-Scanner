"""
Host discovery module for NetPulse.
Determines if a remote target is active before port scanning using
ICMP echo requests (system ping) with TCP ping fallback.
"""

import platform
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional

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


def extract_ttl_from_ping_output(output: str) -> Optional[int]:
    """
    Parses the Time To Live (TTL) integer value from ping command output.
    Supports Windows (TTL=128), Linux/Unix (ttl=64), and macOS formats.

    Args:
        output: Raw stdout string from system ping command.

    Returns:
        Extracted integer TTL value, or None if not found.
    """
    if not output or not isinstance(output, str):
        return None

    match = re.search(r"\bttl[=:]\s*(\d+)", output, re.IGNORECASE)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def guess_os_from_ttl(ttl: int) -> Dict[str, Any]:
    """
    Guesses the target operating system family based on observed Time To Live (TTL)
    from ICMP echo response packets.

    Standard Default Initial TTL Values:
      - Linux / FreeBSD / macOS / Android / modern Unix: Initial TTL ~64
      - Windows (XP/7/8/10/11, Windows Server): Initial TTL ~128
      - Solaris / AIX / Cisco Network Appliances: Initial TTL ~255

    Args:
        ttl: Observed integer TTL from ping response packet.

    Returns:
        Dictionary containing:
          - 'ttl': int (observed TTL)
          - 'initial_ttl': int (estimated initial TTL before router hops)
          - 'hops': int (estimated network router hops traversed)
          - 'os': str (human-readable OS guess)
          - 'os_family': str ('Linux', 'Windows', 'Solaris/Cisco', 'Unknown')
          - 'description': str
    """
    if ttl <= 0:
        return {
            "ttl": ttl,
            "initial_ttl": None,
            "hops": 0,
            "os": "Unknown",
            "os_family": "Unknown",
            "description": f"Invalid TTL value: {ttl}",
        }

    if ttl <= 64:
        initial = 64
        hops = initial - ttl
        os_name = "Linux / macOS"
        family = "Linux"
    elif ttl <= 128:
        initial = 128
        hops = initial - ttl
        os_name = "Windows"
        family = "Windows"
    elif ttl <= 255:
        initial = 255
        hops = initial - ttl
        os_name = "Solaris / Cisco Network Device"
        family = "Solaris/Cisco"
    else:
        return {
            "ttl": ttl,
            "initial_ttl": None,
            "hops": 0,
            "os": "Unknown",
            "os_family": "Unknown",
            "description": f"Unusual TTL value: {ttl}",
        }

    return {
        "ttl": ttl,
        "initial_ttl": initial,
        "hops": max(0, hops),
        "os": os_name,
        "os_family": family,
        "description": f"TTL {ttl} (initial ~{initial}, ~{hops} hop{'s' if hops != 1 else ''}) -> {os_name}",
    }


def ping_and_extract_ttl(target: str, timeout: float = 2.0) -> Optional[int]:
    """
    Executes a native system ICMP ping, captures stdout, and extracts the response TTL.

    Args:
        target: Target IP address or hostname.
        timeout: Ping timeout duration in seconds.

    Returns:
        Observed TTL integer, or None if ping failed or timed out.
    """
    system_os = platform.system().lower()

    if system_os == "windows":
        timeout_ms = max(500, int(timeout * 1000))
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), target]
    else:
        timeout_sec = max(1, int(timeout))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), target]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 1.0,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return extract_ttl_from_ping_output(result.stdout)
        return None
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as err:
        logger.debug(f"Ping TTL check failed on {target}: {err}")
        return None


def get_host_os_guess(target: str, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """
    Performs an ICMP ping to observe the TTL and guesses the target operating system.

    Args:
        target: Target IP address or hostname.
        timeout: Probe timeout in seconds.

    Returns:
        OS guess dictionary if responsive, None if host did not respond or TTL missing.
    """
    ttl = ping_and_extract_ttl(target, timeout=timeout)
    if ttl is not None:
        return guess_os_from_ttl(ttl)
    return None


if __name__ == "__main__":
    test_targets = ["127.0.0.1", "google.com", "192.0.2.1"]
    for t in test_targets:
        online = is_host_online(t, timeout=1.0)
        status_text = "ONLINE" if online else "OFFLINE/UNREACHABLE"
        print(f"Target: {t:<20} Status: {status_text}")
