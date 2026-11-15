#!/usr/bin/env python3
"""
NetPulse - Modern CLI-based Port Scanner
Main Entry Point connecting CLI parsing, target validation, and sequential scanning
with execution time tracking, graceful signal handling, and reporting.
"""

import signal
import sys
import time
from typing import Any, Dict

from core.constants import COMMON_PORTS
from core.host_discovery import is_host_online
from core.scanner import scan_port, scan_ports_concurrent
from utils.banner import print_banner
from utils.cli import parse_arguments
from utils.helpers import export_results
from utils.logger import logger
from utils.validators import resolve_target

# Global scan context shared with the signal handler
scan_context: Dict[str, Any] = {
    "interrupted": False,
    "start_timestamp": 0.0,
    "start_time_str": "",
    "scanned_count": 0,
    "total_ports": 0,
    "target": "",
    "target_ip": "",
    "open_ports": [],
    "output_format": None,
}


def format_timestamp(timestamp: float) -> str:
    """Formats a UNIX epoch timestamp into 'YYYY-MM-DD HH:MM:SS' using the time module."""
    if not timestamp:
        return "N/A"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def format_duration(seconds: float) -> str:
    """Formats seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    rem_seconds = seconds % 60
    return f"{minutes}m {rem_seconds:.2f}s"


def signal_handler(signum: int, frame: Any) -> None:
    """
    Handles SIGINT (Ctrl+C) and SIGTERM signals.
    Halts scanning immediately, ensures socket cleanup, and outputs partial results
    along with exact start, end, and elapsed execution time.
    """
    if scan_context["interrupted"]:
        # Prevent cascading interruptions
        sys.exit(130)

    scan_context["interrupted"] = True

    end_timestamp = time.time()
    start_timestamp = scan_context["start_timestamp"] or end_timestamp
    duration = end_timestamp - start_timestamp
    start_time_str = scan_context["start_time_str"] or format_timestamp(start_timestamp)
    end_time_str = format_timestamp(end_timestamp)

    print("\n\n" + "=" * 65)
    print("[!] Scan aborted by user (Ctrl+C). Cleaning up resources...")
    print("=" * 65)

    open_ports = scan_context["open_ports"]
    scanned = scan_context["scanned_count"]
    total = scan_context["total_ports"]

    print("\n--- [ PARTIAL SCAN RESULTS ] ---")
    if open_ports:
        print(f"{'PORT':<12}{'STATE':<10}{'SERVICE':<15}")
        print("-" * 37)
        for entry in open_ports:
            port_label = f"{entry['port']}/tcp"
            service_label = entry.get("service", "Unknown")
            print(f"{port_label:<12}{'OPEN':<10}{service_label:<15}")
    else:
        print("No open ports were discovered prior to interruption.")

    print("\n--- [ EXECUTION TIMING ] ---")
    print(f"[*] Start Time     : {start_time_str}")
    print(f"[*] End Time       : {end_time_str} (Aborted)")
    print(f"[*] Total Duration : {duration:.2f} seconds ({format_duration(duration)})")
    print(f"[*] Ports Scanned  : {scanned}/{total}")
    print(f"[*] Open Found     : {len(open_ports)}")
    print("=" * 65)

    # Export partial results if an output format was configured
    if scan_context.get("output_format") and open_ports:
        try:
            saved_file = export_results(
                results=open_ports,
                target=scan_context["target"],
                target_ip=scan_context["target_ip"],
                output_dir="output",
                export_format=scan_context["output_format"],
            )
            logger.info(f"Partial results exported to: {saved_file}")
        except Exception as err:
            logger.error(f"Failed to export partial results: {err}")

    logger.info("Scan stopped cleanly. Exiting.")
    sys.exit(130)


def main():
    """Main CLI execution flow."""
    # 1. Register signal handlers for graceful shutdown on Ctrl+C (SIGINT)
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # 2. Parse command-line arguments using cli.py
    args = parse_arguments()

    # 3. Display ASCII art banner and ethical disclaimer
    if not args.quiet:
        print_banner()

    # 4. Validate and resolve target IP/Domain using validators.py
    try:
        canonical_target, target_ip = resolve_target(args.target)
    except ValueError as err:
        logger.error(f"Target validation failed: {err}")
        sys.exit(1)

    ports = args.ports_list

    # Check host availability prior to port scanning unless -Pn is specified
    if args.Pn:
        logger.info(f"Host discovery skipped (-Pn). Forcing scan on '{canonical_target}'.")
    else:
        logger.info(f"Checking host availability on {canonical_target} ({target_ip})...")
        if is_host_online(target_ip, timeout=args.timeout):
            logger.info(f"Target '{canonical_target}' is online and responsive.")
        else:
            logger.warning(
                f"Target '{canonical_target}' did not respond to ICMP/TCP ping (host may be down or firewalling probes)."
            )

    # Record exact start time
    start_timestamp = time.time()
    start_time_str = format_timestamp(start_timestamp)

    # Initialize shared scan context
    scan_context["start_timestamp"] = start_timestamp
    scan_context["start_time_str"] = start_time_str
    scan_context["total_ports"] = len(ports)
    scan_context["scanned_count"] = 0
    scan_context["target"] = canonical_target
    scan_context["target_ip"] = target_ip
    scan_context["output_format"] = args.output
    scan_context["open_ports"] = []
    scan_context["interrupted"] = False

    # Print scan header with start time
    logger.info(f"Target: {canonical_target} ({target_ip})")
    logger.info(f"Scan Started at: {start_time_str}")
    rate_limit_msg = f" | Rate Limit: {args.rate_limit}ms" if args.rate_limit > 0 else ""
    logger.info(
        f"Initiating multi-threaded scan on {len(ports)} port(s) with {args.threads} worker threads (Timeout: {args.timeout}s{rate_limit_msg})..."
    )
    print("-" * 65)
    print(f"{'PORT':<12}{'STATE':<10}{'SERVICE':<15}")
    print("-" * 65)

    def on_port_discovered(port_entry: dict):
        scan_context["open_ports"].append(port_entry)
        port_label = f"{port_entry['port']}/tcp"
        print(f"{port_label:<12}{'OPEN':<10}{port_entry['service']:<15}")

    # 5. Multi-threaded scanning loop using queue.Queue & concurrent.futures.ThreadPoolExecutor
    scan_ports_concurrent(
        ip=target_ip,
        ports=ports,
        timeout=args.timeout,
        max_workers=args.threads,
        rate_limit_ms=args.rate_limit,
        grab_banners=args.banner,
        on_port_scanned=on_port_discovered,
    )
    scan_context["scanned_count"] = len(ports)

    # Record exact end time and duration
    end_timestamp = time.time()
    end_time_str = format_timestamp(end_timestamp)
    total_duration = end_timestamp - start_timestamp

    open_ports = scan_context["open_ports"]
    scanned_count = scan_context["scanned_count"]

    # 6. Detailed Timing & Execution Summary
    print("-" * 65)
    print("                    [ SCAN SUMMARY ]")
    print("-" * 65)
    print(f"[*] Exact Start Time : {start_time_str}")
    print(f"[*] Exact End Time   : {end_time_str}")
    print(f"[*] Total Duration   : {total_duration:.2f} seconds ({format_duration(total_duration)})")
    print(f"[*] Ports Scanned    : {scanned_count}/{len(ports)}")
    print(f"[*] Open Ports Found : {len(open_ports)}")
    print("-" * 65)

    # Export scan report if requested
    if args.output:
        saved_file = export_results(
            results=open_ports,
            target=canonical_target,
            target_ip=target_ip,
            export_format=args.output,
        )
        logger.info(f"Report exported successfully: {saved_file}")


if __name__ == "__main__":
    main()
