"""
NetPulse Vulnerability and Misconfiguration Checker Module.
Audits open network ports for common security vulnerabilities and dangerous default configurations,
including unauthenticated anonymous FTP access (RFC 1635).
"""

import ftplib
import logging
import socket
from typing import Any, Dict, List, Optional

try:
    from .constants import DEFAULT_TIMEOUT
except ImportError:
    try:
        from utils.config import DEFAULT_TIMEOUT
    except ImportError:
        DEFAULT_TIMEOUT = 1.5

try:
    from utils.logger import logger
except ImportError:
    logger = logging.getLogger("NetPulse")


def check_ftp_anonymous(
    ip: str,
    port: int = 21,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """
    Checks if an open FTP service permits anonymous login (RFC 1635).

    Args:
        ip: Target host IP address or hostname.
        port: FTP port number (default: 21).
        timeout: Socket and FTP communication timeout in seconds (default: 1.5s).

    Returns:
        Dictionary containing vulnerability status and server response details:
          - 'vulnerable': bool (True if anonymous login succeeded)
          - 'allowed': bool (alias for vulnerable)
          - 'port': int
          - 'service': str ('FTP')
          - 'vuln_id': str ('FTP-ANON-LOGIN')
          - 'title': str ('FTP Anonymous Login Allowed')
          - 'severity': str ('HIGH')
          - 'banner': str (Server welcome banner)
          - 'response': str (Login response or error message)
          - 'flag': str (CLI warning badge string or None)
    """
    ftp = None
    banner = ""
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        try:
            banner = ftp.getwelcome().strip()
        except Exception:
            banner = ""

        # Attempt standard anonymous authentication
        resp = ftp.login("anonymous", "anonymous@")
        allowed = True
        response_msg = resp or "230 Anonymous user logged in."

        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass

        return {
            "vulnerable": True,
            "allowed": True,
            "port": port,
            "service": "FTP",
            "vuln_id": "FTP-ANON-LOGIN",
            "title": "FTP Anonymous Login Allowed",
            "severity": "HIGH",
            "description": "The FTP server allows anonymous login without valid credentials.",
            "banner": banner,
            "response": response_msg,
            "flag": "[!] VULN: FTP Anonymous Login Allowed",
        }

    except ftplib.error_perm as err:
        # 530 Login incorrect or User cannot log in
        return {
            "vulnerable": False,
            "allowed": False,
            "port": port,
            "service": "FTP",
            "vuln_id": "FTP-ANON-LOGIN",
            "title": "FTP Anonymous Login Allowed",
            "severity": "HIGH",
            "description": "The FTP server allows anonymous login without valid credentials.",
            "banner": banner,
            "response": str(err).strip(),
            "flag": None,
        }

    except (
        ftplib.error_reply,
        ftplib.error_temp,
        socket.timeout,
        socket.error,
        OSError,
        KeyboardInterrupt,
    ) as err:
        return {
            "vulnerable": False,
            "allowed": False,
            "port": port,
            "service": "FTP",
            "vuln_id": "FTP-ANON-LOGIN",
            "title": "FTP Anonymous Login Allowed",
            "severity": "HIGH",
            "description": "The FTP server allows anonymous login without valid credentials.",
            "banner": banner,
            "response": f"Connection/Protocol error: {err}",
            "flag": None,
        }

    finally:
        if ftp:
            try:
                ftp.close()
            except Exception:
                pass


def run_port_vulnerability_checks(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """
    Executes relevant vulnerability and misconfiguration checks based on the target port number.

    Args:
        ip: Target host IP address or hostname.
        port: Open TCP port number.
        timeout: Check execution timeout in seconds.

    Returns:
        List of discovered vulnerability finding dictionaries.
    """
    findings: List[Dict[str, Any]] = []

    # Port 21: FTP Anonymous Access
    if port == 21:
        ftp_res = check_ftp_anonymous(ip, port=port, timeout=timeout)
        if ftp_res.get("vulnerable"):
            findings.append(ftp_res)

    return findings


class VulnerabilityChecker:
    """
    Vulnerability and Misconfiguration Checker Engine.
    Executes automated vulnerability audits on open ports.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def check_ftp_anonymous(self, ip: str, port: int = 21) -> Dict[str, Any]:
        """Audits FTP service for unauthenticated anonymous access."""
        return check_ftp_anonymous(ip, port=port, timeout=self.timeout)

    def check_port(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """Audits open port for applicable vulnerabilities."""
        return run_port_vulnerability_checks(ip, port=port, timeout=self.timeout)
