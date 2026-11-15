"""
NetPulse CLI Argument Parser Module.
Configures command-line options, descriptions, custom usage documentation,
and port parsing logic for single ports, comma-separated lists, and ranges.
"""

import argparse
import sys
from typing import List, Optional

try:
    from .config import COMMON_PORTS_LIST, DEFAULT_THREADS, DEFAULT_TIMEOUT, TOOL_NAME, VERSION
except ImportError:
    TOOL_NAME = "NetPulse"
    VERSION = "1.0.0"
    DEFAULT_TIMEOUT = 1.5
    DEFAULT_THREADS = 100
    COMMON_PORTS_LIST = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

CUSTOM_USAGE = """%(prog)s [-h] (-t TARGET | TARGET) [-p PORTS | --common]
                [-w WORKERS] [--timeout TIMEOUT] [-b] [-o {json,txt}] [-q] [-v]"""

CUSTOM_DESCRIPTION = f"""
================================================================================
 {TOOL_NAME} - Advanced CLI TCP Port Scanner (v{VERSION})
================================================================================
A fast, multi-threaded network reconnaissance tool designed for security auditing,
network diagnostics, and port discovery.
"""

CUSTOM_EPILOG = """
Examples:
  # Scan a single port:
  python main.py -t 192.168.1.1 -p 80

  # Scan comma-separated ports:
  python main.py -t 192.168.1.1 -p 80,443,8080

  # Scan a port range:
  python main.py -t scanme.nmap.org -p 1-1000 -w 200

  # Combined single ports and ranges:
  python main.py -t example.com -p 22,80-90,443,8000-8080 -b

  # Scan top common ports and export results:
  python main.py --target 127.0.0.1 --common -o json
"""


def parse_ports(port_input: str) -> List[int]:
    """
    Parses a port specification string into a sorted list of unique integers.

    Supports:
      - Single port:           "80"          -> [80]
      - Comma-separated:       "80,443"      -> [80, 443]
      - Port ranges:           "1-1000"      -> [1, 2, ..., 1000]
      - Mixed/Combinations:    "22,80-85,443"-> [22, 80, 81, 82, 83, 84, 85, 443]

    Args:
        port_input: Raw port specification string from CLI.

    Returns:
        Sorted list of unique integer port numbers within 1-65535.

    Raises:
        ValueError: If any port is malformed, out of boundaries (1-65535), or inverted range.
    """
    if not port_input or not isinstance(port_input, str):
        raise ValueError("Port input must be a non-empty string.")

    ports = set()
    tokens = [token.strip() for token in port_input.split(",") if token.strip()]

    if not tokens:
        raise ValueError(f"Invalid port specification: '{port_input}'")

    for token in tokens:
        if "-" in token:
            range_bounds = token.split("-")
            if len(range_bounds) != 2:
                raise ValueError(f"Malformed port range: '{token}'. Expected format 'start-end' (e.g. 1-1000).")

            try:
                start = int(range_bounds[0].strip())
                end = int(range_bounds[1].strip())
            except ValueError:
                raise ValueError(f"Non-numeric values in port range: '{token}'")

            if start > end:
                raise ValueError(f"Inverted port range: '{token}'. Start port ({start}) cannot exceed end port ({end}).")

            if start < 1 or end > 65535:
                raise ValueError(f"Port range out of valid boundaries (1-65535): '{token}'")

            ports.update(range(start, end + 1))
        else:
            try:
                port = int(token)
            except ValueError:
                raise ValueError(f"Invalid non-numeric port: '{token}'")

            if port < 1 or port > 65535:
                raise ValueError(f"Port number out of valid boundaries (1-65535): {port}")

            ports.add(port)

    return sorted(list(ports))


def create_parser() -> argparse.ArgumentParser:
    """Creates and returns the configured ArgumentParser instance."""
    parser = argparse.ArgumentParser(
        prog="NetPulse",
        usage=CUSTOM_USAGE,
        description=CUSTOM_DESCRIPTION,
        epilog=CUSTOM_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # Target specification: support both -t / --target and optional positional
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-t",
        "--target",
        dest="target_flag",
        type=str,
        default=None,
        help="Target IP address or domain name (e.g. 192.168.1.1, scanme.nmap.org)",
    )
    target_group.add_argument(
        "positional_target",
        nargs="?",
        default=None,
        metavar="TARGET",
        help=argparse.SUPPRESS,  # Positional fallback for convenience
    )

    # Port options
    port_group = parser.add_argument_group("Port Scan Options")
    port_group.add_argument(
        "-p",
        "--ports",
        dest="ports",
        type=str,
        default=None,
        help="Ports to scan: single (80), comma-separated (80,443), or range (1-1000). Default: 1-1024",
    )
    port_group.add_argument(
        "--common",
        action="store_true",
        help="Scan top standard common ports only (HTTP, SSH, MySQL, etc.)",
    )

    # Performance & Timing
    perf_group = parser.add_argument_group("Performance & Timing")
    perf_group.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Socket connection timeout in seconds (default: {DEFAULT_TIMEOUT}s)",
    )
    perf_group.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent worker threads (default: {DEFAULT_THREADS})",
    )

    # Scanning Features & Output
    scan_group = parser.add_argument_group("Features & Output")
    scan_group.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="Attempt service banner grabbing on open ports",
    )
    scan_group.add_argument(
        "-o",
        "--output",
        choices=["json", "txt"],
        help="Export scan results to file in output/ directory (json or txt)",
    )

    # General / Flags
    misc_group = parser.add_argument_group("General Options")
    misc_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress ASCII art banner and disclaimers",
    )
    misc_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug output",
    )
    misc_group.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"{TOOL_NAME} v{VERSION}",
        help="Show program's version number and exit",
    )

    return parser


def parse_arguments(args: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parses and validates CLI arguments.
    Resolves target and parses port specifications into an integer list.
    """
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # Resolve target from either -t/--target or positional fallback
    target = parsed_args.target_flag or parsed_args.positional_target

    if not target:
        parser.print_usage(sys.stderr)
        print(
            f"\n[!] Error: Target is required. Use -t/--target <IP/Domain>.\n"
            f"Run '{parser.prog} --help' for usage and examples.",
            file=sys.stderr,
        )
        sys.exit(2)

    parsed_args.target = target

    # Validate timeout argument
    if parsed_args.timeout <= 0:
        print(
            f"[!] Error: Timeout must be a positive float greater than 0 (received: {parsed_args.timeout}).",
            file=sys.stderr,
        )
        sys.exit(2)

    # Parse port specifications into a list of integers
    if parsed_args.common:
        parsed_args.ports_list = COMMON_PORTS_LIST
    elif parsed_args.ports:
        try:
            parsed_args.ports_list = parse_ports(parsed_args.ports)
        except ValueError as err:
            print(f"[!] Error parsing ports: {err}", file=sys.stderr)
            sys.exit(2)
    else:
        # Default standard port range: 1 - 1024
        parsed_args.ports_list = list(range(1, 1025))

    return parsed_args


if __name__ == "__main__":
    cli_args = parse_arguments()
    print(f"Target: {cli_args.target}")
    print(f"Parsed Ports Count: {len(cli_args.ports_list)}")
    print(f"Sample Ports: {cli_args.ports_list[:10]}")
