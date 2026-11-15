#!/usr/bin/env python3
"""
NetPulse - Modern CLI-based Port Scanner
Main Entry Point connecting CLI parsing, target validation, and sequential scanning.
"""

import sys
import time

from core.constants import COMMON_PORTS
from core.scanner import scan_port
from utils.banner import print_banner
from utils.cli import parse_arguments
from utils.helpers import export_results
from utils.logger import logger
from utils.validators import resolve_target


def main():
    """Main CLI execution flow."""
    # 1. Parse command-line arguments using cli.py
    args = parse_arguments()

    # 2. Display ASCII art banner and ethical disclaimer
    if not args.quiet:
        print_banner()

    # 3. Validate and resolve target IP/Domain using validators.py
    try:
        canonical_target, target_ip = resolve_target(args.target)
    except ValueError as err:
        logger.error(f"Target validation failed: {err}")
        sys.exit(1)

    ports = args.ports_list

    # Print scan header
    logger.info(f"Target: {canonical_target} ({target_ip})")
    logger.info(f"Initiating sequential scan on {len(ports)} port(s) (Timeout: {args.timeout}s)...")
    print("-" * 60)
    print(f"{'PORT':<12}{'STATE':<10}{'SERVICE':<15}")
    print("-" * 60)

    open_ports = []
    scanned_count = 0
    start_time = time.time()

    # 4. Iterate through the parsed port list and scan sequentially using scanner.py
    try:
        for port in ports:
            scanned_count += 1
            is_open = scan_port(target_ip, port, timeout=args.timeout)

            if is_open:
                service = COMMON_PORTS.get(port, "Unknown")
                port_entry = {
                    "port": port,
                    "state": "OPEN",
                    "service": service,
                }
                open_ports.append(port_entry)
                print(f"{f'{port}/tcp':<12}{'OPEN':<10}{service:<15}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")

    elapsed = time.time() - start_time

    # 5. Summary and Reporting
    print("-" * 60)
    logger.info(
        f"Scan completed in {elapsed:.2f}s | Scanned: {scanned_count}/{len(ports)} | Open ports found: {len(open_ports)}"
    )

    # Optional output export
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
