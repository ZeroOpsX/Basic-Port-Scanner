#!/usr/bin/env python3
"""
NetPulse - Modern CLI-based Port Scanner
Main Entry Point
"""

import sys
import time

from core.constants import COMMON_PORTS
from core.scanner import PortScanner
from utils.banner import print_banner
from utils.cli import parse_arguments
from utils.helpers import export_results, parse_port_range, validate_target
from utils.logger import logger


def main():
    """Main CLI execution flow."""
    args = parse_arguments()

    if not args.quiet:
        print_banner()

    if not validate_target(args.target):
        print(f"[!] Error: Invalid target '{args.target}'")
        sys.exit(1)

    # Determine port list
    if args.common:
        ports = sorted(list(COMMON_PORTS.keys()))
    elif args.ports:
        try:
            ports = parse_port_range(args.ports)
        except ValueError as e:
            print(f"[!] Error parsing ports: {e}")
            sys.exit(1)
    else:
        # Default standard range: 1 - 1024
        ports = list(range(1, 1025))

    # Initialize scanner
    try:
        scanner = PortScanner(
            target=args.target,
            timeout=args.timeout,
            max_workers=args.workers,
        )
    except ValueError as e:
        print(f"[!] Target resolution failed: {e}")
        sys.exit(1)

    print(f"[*] Target: {args.target} ({scanner.target_ip})")
    print(f"[*] Scanning {len(ports)} port(s) with {args.workers} threads (Timeout: {args.timeout}s)...")
    print("-" * 65)
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'BANNER'}")
    print("-" * 65)

    def on_port_found(result: dict):
        banner_display = result["banner"] if result["banner"] else "-"
        print(
            f"{result['port']:<10}{result['state']:<10}{result['service']:<15}{banner_display}"
        )

    start_time = time.time()
    try:
        results = scanner.scan_ports(
            ports=ports,
            grab_banner=args.banner,
            on_port_scanned=on_port_found,
        )
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)

    elapsed = time.time() - start_time
    print("-" * 65)
    print(f"[*] Scan completed in {elapsed:.2f} seconds.")
    print(f"[*] Open ports found: {len(results)}")

    if args.output:
        saved_file = export_results(
            results=results,
            target=args.target,
            target_ip=scanner.target_ip,
            export_format=args.output,
        )
        print(f"[+] Report exported successfully: {saved_file}")


if __name__ == "__main__":
    main()
