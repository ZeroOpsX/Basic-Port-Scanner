"""
NetPulse Vulnerability and Misconfiguration Checker Module.
Audits open network ports for common security vulnerabilities and dangerous default configurations,
including unauthenticated anonymous FTP access (RFC 1635).
"""

import ftplib
import json
import logging
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
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


# Mapping of common banner keywords to (vendor, product) for CIRCL CVE search
COMMON_VENDOR_PRODUCT_MAP: Dict[str, tuple] = {
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "apache2": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "iis": ("microsoft", "iis"),
    "microsoft-iis": ("microsoft", "iis"),
    "tomcat": ("apache", "tomcat"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "bind": ("isc", "bind"),
}

BANNER_REGEX = re.compile(
    r"(?:SSH-2\.0-)?(?P<product>[A-Za-z0-9_-]+)[/_ ]v?(?P<version>\d+(?:\.\d+)+(?:[a-zA-Z0-9_.-]*))"
)


def parse_service_banner(banner: str) -> Dict[str, Optional[str]]:
    """
    Extracts product name, version string, and estimated vendor from a service banner.

    Examples:
      - 'Apache 2.4.49' -> product: 'http_server', vendor: 'apache', version: '2.4.49'
      - 'nginx/1.18.0' -> product: 'nginx', vendor: 'nginx', version: '1.18.0'
      - 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.5' -> product: 'openssh', vendor: 'openbsd', version: '8.2p1'
      - 'vsftpd 3.0.3' -> product: 'vsftpd', vendor: 'vsftpd', version: '3.0.3'

    Args:
        banner: Raw service banner or HTTP Server header.

    Returns:
        Dictionary with 'product', 'version', 'vendor', and 'raw_product'.
    """
    if not banner or not isinstance(banner, str):
        return {"product": None, "version": None, "vendor": None, "raw_product": None}

    clean_banner = banner.strip()
    match = BANNER_REGEX.search(clean_banner)

    if match:
        raw_product = match.group("product")
        version = match.group("version")
        norm_key = raw_product.lower()
        if norm_key in COMMON_VENDOR_PRODUCT_MAP:
            vendor, product = COMMON_VENDOR_PRODUCT_MAP[norm_key]
        else:
            vendor, product = norm_key, norm_key

        return {
            "product": product,
            "version": version,
            "vendor": vendor,
            "raw_product": raw_product,
        }

    # Fallback: check for standalone single word product
    tokens = clean_banner.split()
    if tokens:
        first_token = re.sub(r"[^A-Za-z0-9_-]", "", tokens[0]).lower()
        if first_token in COMMON_VENDOR_PRODUCT_MAP:
            vendor, product = COMMON_VENDOR_PRODUCT_MAP[first_token]
            return {
                "product": product,
                "version": None,
                "vendor": vendor,
                "raw_product": tokens[0],
            }

    return {"product": None, "version": None, "vendor": None, "raw_product": None}


def query_circl_cve(
    vendor: str,
    product: str,
    version: Optional[str] = None,
    limit: int = 5,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Queries the public CIRCL CVE search API (https://cve.circl.lu) for vulnerabilities.

    Args:
        vendor: Software vendor identifier (e.g. 'apache', 'nginx', 'openbsd').
        product: Software product name (e.g. 'http_server', 'nginx', 'openssh').
        version: Optional version filter (e.g. '2.4.49').
        limit: Maximum number of CVE entries to return (default: 5).
        timeout: Request timeout in seconds.

    Returns:
        List of formatted CVE finding dictionaries.
    """
    url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(vendor)}/{urllib.parse.quote(product)}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NetPulse-PortScanner/1.0", "Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                return []
            data = json.loads(response.read().decode("utf-8"))

        cves: List[Dict[str, Any]] = []

        # CIRCL CVE v5 format returns a dictionary with 'results' -> 'nvd'
        if isinstance(data, dict) and "results" in data:
            results_nvd = data.get("results", {}).get("nvd", [])
            for item in results_nvd:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    cve_id_key, record = item
                    metadata = record.get("cveMetadata", {})
                    cve_id = metadata.get("cveId", str(cve_id_key).upper())
                    cna = record.get("containers", {}).get("cna", {})
                    title = cna.get("title", "")
                    descriptions = cna.get("descriptions", [{}])
                    summary = descriptions[0].get("value", "") if descriptions else ""

                    # Extract CVSS score and severity
                    score = None
                    severity = "UNKNOWN"
                    for adp in record.get("containers", {}).get("adp", []):
                        for metric in adp.get("metrics", []):
                            if "cvssV3_1" in metric:
                                score = metric["cvssV3_1"].get("baseScore")
                                severity = metric["cvssV3_1"].get("baseSeverity", "UNKNOWN")
                            elif "cvssV3_0" in metric and score is None:
                                score = metric["cvssV3_0"].get("baseScore")
                                severity = metric["cvssV3_0"].get("baseSeverity", "UNKNOWN")

                    published = metadata.get("datePublished", "")[:10]
                    cve_entry = {
                        "id": cve_id,
                        "title": title or summary[:80],
                        "summary": summary,
                        "cvss": score,
                        "severity": severity,
                        "published": published,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                    cves.append(cve_entry)

        # Legacy CIRCL API format: list of dicts with 'id', 'summary', 'cvss'
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    cve_id = entry.get("id") or entry.get("cve") or ""
                    if not cve_id:
                        continue
                    cvss_val = entry.get("cvss")
                    try:
                        cvss_float = float(cvss_val) if cvss_val is not None else None
                    except (ValueError, TypeError):
                        cvss_float = None

                    cves.append({
                        "id": cve_id,
                        "title": entry.get("summary", "")[:80],
                        "summary": entry.get("summary", ""),
                        "cvss": cvss_float,
                        "severity": "HIGH" if cvss_float and cvss_float >= 7.0 else "MEDIUM",
                        "published": str(entry.get("Published", ""))[:10],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })

        # If a specific version was requested, prioritize CVEs mentioning that version
        if version:
            ver_clean = str(version).strip()
            matched = [
                c for c in cves
                if ver_clean in c["summary"] or ver_clean in c["title"]
            ]
            if matched:
                return matched[:limit]

        return cves[:limit]

    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout, json.JSONDecodeError, OSError) as err:
        logger.debug(f"CIRCL CVE lookup failed for {vendor}/{product}: {err}")
        return []


def query_nvd_cve(
    keyword: str,
    limit: int = 5,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Queries the official NIST National Vulnerability Database (NVD) 2.0 API.

    Args:
        keyword: Query search term (e.g. 'Apache 2.4.49').
        limit: Maximum results to retrieve.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of formatted CVE dictionaries.
    """
    query_str = urllib.parse.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query_str}&resultsPerPage={limit}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NetPulse-PortScanner/1.0", "Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                return []
            data = json.loads(response.read().decode("utf-8"))

        cves: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "")
            if not cve_id:
                continue

            descs = cve_obj.get("descriptions", [{}])
            summary = descs[0].get("value", "") if descs else ""

            # Parse CVSS score
            score = None
            severity = "UNKNOWN"
            metrics = cve_obj.get("metrics", {})
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "UNKNOWN")

            cves.append({
                "id": cve_id,
                "title": summary[:80],
                "summary": summary,
                "cvss": score,
                "severity": severity,
                "published": cve_obj.get("published", "")[:10],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        return cves[:limit]

    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout, json.JSONDecodeError, OSError) as err:
        logger.debug(f"NVD CVE lookup failed for '{keyword}': {err}")
        return []


def query_cve_by_banner(
    banner: str,
    api_provider: str = "circl",
    limit: int = 5,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Parses a grabbed service banner (e.g., 'Apache 2.4.49', 'nginx/1.18.0', 'OpenSSH_8.2p1')
    and queries a public CVE API (CIRCL or NVD) to retrieve potential vulnerabilities.

    Args:
        banner: Grabbed service banner string or HTTP Server header.
        api_provider: CVE API service to query ('circl' or 'nvd', default: 'circl').
        limit: Maximum number of CVE findings to return (default: 5).
        timeout: HTTP request timeout in seconds (default: 5.0s).

    Returns:
        List of CVE vulnerability dictionaries:
          - 'id': str (e.g. 'CVE-2021-41773')
          - 'title': str
          - 'summary': str
          - 'cvss': Optional[float]
          - 'severity': str
          - 'published': str
          - 'url': str
    """
    parsed = parse_service_banner(banner)
    product = parsed.get("product")
    vendor = parsed.get("vendor") or product
    version = parsed.get("version")

    if not product:
        return []

    provider = api_provider.lower().strip()
    if provider == "nvd":
        keyword = f"{parsed.get('raw_product') or product} {version}".strip() if version else product
        return query_nvd_cve(keyword=keyword, limit=limit, timeout=timeout)
    else:
        # Default to CIRCL CVE search API
        results = query_circl_cve(
            vendor=vendor, product=product, version=version, limit=limit, timeout=timeout
        )
        if not results and version:
            # Fallback to NVD keyword query if CIRCL returned no results
            keyword = f"{parsed.get('raw_product') or product} {version}".strip()
            results = query_nvd_cve(keyword=keyword, limit=limit, timeout=timeout)
        return results


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
            "allowed": allowed,
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

    def lookup_banner_cves(
        self, banner: str, limit: int = 5, api_provider: str = "circl"
    ) -> List[Dict[str, Any]]:
        """Queries public CVE database for vulnerabilities matching a grabbed service banner."""
        return query_cve_by_banner(
            banner=banner,
            api_provider=api_provider,
            limit=limit,
            timeout=self.timeout,
        )
