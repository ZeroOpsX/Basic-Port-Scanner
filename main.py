#!/usr/bin/env python3
"""
NetPulse - Modern CLI-based Port Scanner
Main Entry Point
"""

import argparse
import sys
import time

from core.constants import COMMON_PORTS, DEFAULT_THREADS, DEFAULT_TIMEOUT
from core.scanner import PortScanner
from utils.banner import print_banner
from utils.helpers import export_results, parse_port_range, validate_target


def parse_arguments() -> argparse.Namespace:
    """Configures and parses CLI command line arguments."""
    parser = argparse.ArgumentParser(
        prog="NetPulse",
        description="Fast, multi-threaded command-line TCP Port Scanner.",
        epilog="Examples:\n"
        "  python main.py 127.0.0.1 -p 80,443,8080\n"
        "  python main.py scanme.nmap.org -p 1-1024 -w 200 -b\n"
        "  python main.py localhost --common -o json\n",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("target", help="Target hostname or IP address to scan")
    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        default=None,
        help="Port specification (e.g., '80', '1-1024', '80,443,8080'). Default: 1-1024",
    )
    parser.add_argument(
        "--common",
        action="store_true",
        help="Scan top standard/common ports only",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Socket connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Maximum concurrent worker threads (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="Attempt service banner grabbing on open ports",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "txt"],
        help="Export scan results to file in output/ directory (json or txt)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress ASCII art banner header",
    )

    return parser.parse_args()


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
