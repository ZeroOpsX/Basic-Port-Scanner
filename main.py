#!/usr/bin/env python3
"""
NetPulse - Modern CLI-based Port Scanner
Main Entry Point connecting CLI parsing, target validation, and sequential scanning
with graceful SIGINT (Ctrl+C) signal handling and partial results reporting.
"""

import signal
import sys
import time
from typing import Any, Dict

from core.constants import COMMON_PORTS
from core.scanner import scan_port
from utils.banner import print_banner
from utils.cli import parse_arguments
from utils.helpers import export_results
from utils.logger import logger
from utils.validators import resolve_target

# Global scan context shared with the signal handler
scan_context: Dict[str, Any] = {
    "interrupted": False,
    "start_time": 0.0,
    "scanned_count": 0,
    "total_ports": 0,
    "target": "",
    "target_ip": "",
    "open_ports": [],
    "output_format": None,
}


def signal_handler(signum: int, frame: Any) -> None:
    """
    Handles SIGINT (Ctrl+C) and SIGTERM signals.
    Halts scanning immediately, ensures socket cleanup, and outputs partial results.
    """
    if scan_context["interrupted"]:
        # Prevent cascading interruptions
        sys.exit(130)

    scan_context["interrupted"] = True

    print("\n\n" + "=" * 65)
    print("[!] Scan aborted by user (Ctrl+C). Cleaning up resources...")
    print("=" * 65)

    start_time = scan_context["start_time"]
    elapsed = time.time() - start_time if start_time else 0.0
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

    print("-" * 65)
    logger.info(
        f"Elapsed Time: {elapsed:.2f}s | Scanned: {scanned}/{total} ports | Open: {len(open_ports)}"
    )

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

    # Initialize shared scan context
    scan_context["start_time"] = time.time()
    scan_context["total_ports"] = len(ports)
    scan_context["scanned_count"] = 0
    scan_context["target"] = canonical_target
    scan_context["target_ip"] = target_ip
    scan_context["output_format"] = args.output
    scan_context["open_ports"] = []
    scan_context["interrupted"] = False

    # Print scan header
    logger.info(f"Target: {canonical_target} ({target_ip})")
    logger.info(f"Initiating sequential scan on {len(ports)} port(s) (Timeout: {args.timeout}s)...")
    print("-" * 60)
    print(f"{'PORT':<12}{'STATE':<10}{'SERVICE':<15}")
    print("-" * 60)

    # 5. Iterate through the parsed port list and scan sequentially using scanner.py
    for port in ports:
        if scan_context["interrupted"]:
            break

        scan_context["scanned_count"] += 1
        is_open = scan_port(target_ip, port, timeout=args.timeout)

        if is_open:
            service = COMMON_PORTS.get(port, "Unknown")
            port_entry = {
                "port": port,
                "state": "OPEN",
                "service": service,
            }
            scan_context["open_ports"].append(port_entry)
            port_label = f"{port}/tcp"
            print(f"{port_label:<12}{'OPEN':<10}{service:<15}")

    elapsed = time.time() - scan_context["start_time"]
    open_ports = scan_context["open_ports"]
    scanned_count = scan_context["scanned_count"]

    # 6. Summary and Reporting on normal completion
    print("-" * 60)
    logger.info(
        f"Scan completed in {elapsed:.2f}s | Scanned: {scanned_count}/{len(ports)} | Open ports found: {len(open_ports)}"
    )

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
