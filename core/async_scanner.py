"""
NetPulse Asynchronous Port Scanner Engine.
Provides ultra-fast, event-loop-driven TCP port scanning powered by Python's asyncio.
Serves as a high-performance alternative to ThreadPoolExecutor multi-threading,
supporting concurrency limits via asyncio.Semaphore and rate limiting.
"""

import asyncio
import logging
import socket
from typing import Callable, Dict, List, Optional

from .constants import COMMON_PORTS, DEFAULT_TIMEOUT
from .scanner import (
    CLOSED_ERRNOS,
    PortStatus,
)

try:
    from utils.logger import logger
except ImportError:
    logger = logging.getLogger("NetPulse")

# Additional Winsock / Windows-specific errno for connection refused
CLOSED_ERRNOS.update({1225, 10061, 10054})


async def async_scan_port(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> PortStatus:
    """
    Asynchronously probes a single TCP port using asyncio.open_connection.

    Port Classifications:
      - 'OPEN': TCP handshake succeeded.
      - 'CLOSED': ConnectionRefusedError or TCP RST received.
      - 'FILTERED': Probe timed out or dropped by firewall.

    Args:
        ip: Target IPv4 address or hostname string.
        port: TCP port number (1-65535).
        timeout: Socket connection timeout in seconds (default: 1.5s).

    Returns:
        PortStatus enum-like string: 'OPEN', 'CLOSED', or 'FILTERED'.
    """
    try:
        connect_coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return PortStatus.OPEN

    except ConnectionRefusedError:
        return PortStatus.CLOSED

    except (asyncio.TimeoutError, TimeoutError):
        return PortStatus.FILTERED

    except OSError as err:
        err_code = getattr(err, "errno", None)
        win_code = getattr(err, "winerror", None)
        if (
            err_code in CLOSED_ERRNOS
            or win_code in CLOSED_ERRNOS
            or "refus" in str(err).lower()
        ):
            return PortStatus.CLOSED
        return PortStatus.FILTERED

    except asyncio.CancelledError:
        raise

    except Exception as err:
        logger.debug(f"Unexpected error probing {ip}:{port} -> {err}")
        return PortStatus.FILTERED


async def async_grab_banner(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """
    Asynchronously connects to an open port and attempts to grab a service banner.
    """
    try:
        connect_coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
        try:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode("utf-8", errors="ignore").strip()
            return banner.splitlines()[0] if banner else ""
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return ""


async def scan_single_port_full(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    grab_banners: bool = False,
    include_closed: bool = False,
    rate_limit_ms: float = 0.0,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> Optional[Dict]:
    """
    Worker coroutine for scanning a single port within a concurrency-limiting semaphore.
    """
    if rate_limit_ms > 0:
        await asyncio.sleep(rate_limit_ms / 1000.0)

    async def _probe():
        # First attempt connection and optionally grab banner on the same open socket
        state = PortStatus.FILTERED
        banner = ""

        try:
            connect_coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
            state = PortStatus.OPEN

            if grab_banners:
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                    raw_banner = data.decode("utf-8", errors="ignore").strip()
                    if raw_banner:
                        banner = raw_banner.splitlines()[0]
                except Exception:
                    banner = ""

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        except ConnectionRefusedError:
            state = PortStatus.CLOSED
        except (asyncio.TimeoutError, TimeoutError):
            state = PortStatus.FILTERED
        except OSError as err:
            err_code = getattr(err, "errno", None)
            win_code = getattr(err, "winerror", None)
            if (
                err_code in CLOSED_ERRNOS
                or win_code in CLOSED_ERRNOS
                or "refus" in str(err).lower()
            ):
                state = PortStatus.CLOSED
            else:
                state = PortStatus.FILTERED
        except asyncio.CancelledError:
            raise
        except Exception:
            state = PortStatus.FILTERED

        if not include_closed and state != PortStatus.OPEN:
            return None

        service = COMMON_PORTS.get(port, "Unknown")
        return {
            "port": port,
            "state": str(state),
            "service": service,
            "banner": banner,
        }

    if semaphore:
        async with semaphore:
            return await _probe()
    else:
        return await _probe()


async def scan_ports_async(
    ip: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = 500,
    rate_limit_ms: float = 0.0,
    grab_banners: bool = False,
    include_closed: bool = False,
    on_port_scanned: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Scans a collection of ports asynchronously using asyncio and a Semaphore concurrency barrier.

    Args:
        ip: Target IPv4 address or hostname.
        ports: List of port numbers to scan.
        timeout: Socket timeout per port probe in seconds.
        concurrency: Maximum number of simultaneous async connection attempts (default: 500).
        rate_limit_ms: Milliseconds delay between probes (default: 0.0).
        grab_banners: Whether to perform banner grabbing on open ports.
        include_closed: Whether to include CLOSED and FILTERED ports in results.
        on_port_scanned: Callback invoked immediately when a port record is discovered.

    Returns:
        Sorted list of discovered port result dictionaries.
    """
    if not ports:
        return []

    limit = max(1, concurrency)
    semaphore = asyncio.Semaphore(limit)
    results: List[Dict] = []

    async def _wrapped_scan(port: int):
        try:
            record = await scan_single_port_full(
                ip=ip,
                port=port,
                timeout=timeout,
                grab_banners=grab_banners,
                include_closed=include_closed,
                rate_limit_ms=rate_limit_ms,
                semaphore=semaphore,
            )
            if record is not None:
                results.append(record)
                if on_port_scanned:
                    on_port_scanned(record)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            logger.debug(f"Exception scanning port {port}: {err}")

    tasks = [_wrapped_scan(port) for port in ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    results.sort(key=lambda x: x["port"])
    return results


def run_async_scan(
    ip: str,
    ports: List[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = 500,
    rate_limit_ms: float = 0.0,
    grab_banners: bool = False,
    include_closed: bool = False,
    on_port_scanned: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Synchronous helper that runs `scan_ports_async` inside an asyncio event loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If an event loop is already running (e.g. nested/Jupyter), create a new task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(
                    asyncio.run,
                    scan_ports_async(
                        ip=ip,
                        ports=ports,
                        timeout=timeout,
                        concurrency=concurrency,
                        rate_limit_ms=rate_limit_ms,
                        grab_banners=grab_banners,
                        include_closed=include_closed,
                        on_port_scanned=on_port_scanned,
                    ),
                ).result()
    except RuntimeError:
        pass

    return asyncio.run(
        scan_ports_async(
            ip=ip,
            ports=ports,
            timeout=timeout,
            concurrency=concurrency,
            rate_limit_ms=rate_limit_ms,
            grab_banners=grab_banners,
            include_closed=include_closed,
            on_port_scanned=on_port_scanned,
        )
    )


class AsyncPortScanner:
    """
    Asynchronous TCP Port Scanner class leveraging asyncio.
    Provides an ultra-fast alternative to thread-based scanning engines.
    """

    def __init__(
        self,
        target: str,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = 500,
        rate_limit_ms: float = 0.0,
    ):
        self.raw_target = target
        self.timeout = timeout
        self.concurrency = concurrency
        self.rate_limit_ms = rate_limit_ms
        self.target_ip = self._resolve_target(target)

    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IPv4 address."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as err:
            raise ValueError(f"Unable to resolve host '{target}': {err}") from err

    async def scan_port(
        self,
        port: int,
        grab_banner: bool = False,
        timeout: Optional[float] = None,
        include_closed: bool = False,
    ) -> Optional[Dict]:
        """Asynchronously scans a single port."""
        active_timeout = timeout if timeout is not None else self.timeout
        return await scan_single_port_full(
            ip=self.target_ip,
            port=port,
            timeout=active_timeout,
            grab_banners=grab_banner,
            include_closed=include_closed,
            rate_limit_ms=self.rate_limit_ms,
        )

    async def scan_ports_async(
        self,
        ports: List[int],
        grab_banner: bool = False,
        timeout: Optional[float] = None,
        rate_limit_ms: Optional[float] = None,
        on_port_scanned: Optional[Callable[[Dict], None]] = None,
        include_closed: bool = False,
    ) -> List[Dict]:
        """Asynchronously scans a list of ports."""
        active_timeout = timeout if timeout is not None else self.timeout
        active_rate_limit = (
            rate_limit_ms if rate_limit_ms is not None else self.rate_limit_ms
        )
        return await scan_ports_async(
            ip=self.target_ip,
            ports=ports,
            timeout=active_timeout,
            concurrency=self.concurrency,
            rate_limit_ms=active_rate_limit,
            grab_banners=grab_banner,
            include_closed=include_closed,
            on_port_scanned=on_port_scanned,
        )

    def scan_ports(
        self,
        ports: List[int],
        grab_banner: bool = False,
        timeout: Optional[float] = None,
        rate_limit_ms: Optional[float] = None,
        on_port_scanned: Optional[Callable[[Dict], None]] = None,
        include_closed: bool = False,
    ) -> List[Dict]:
        """Synchronous wrapper for scanning ports using the asyncio engine."""
        active_timeout = timeout if timeout is not None else self.timeout
        active_rate_limit = (
            rate_limit_ms if rate_limit_ms is not None else self.rate_limit_ms
        )
        return run_async_scan(
            ip=self.target_ip,
            ports=ports,
            timeout=active_timeout,
            concurrency=self.concurrency,
            rate_limit_ms=active_rate_limit,
            grab_banners=grab_banner,
            include_closed=include_closed,
            on_port_scanned=on_port_scanned,
        )
