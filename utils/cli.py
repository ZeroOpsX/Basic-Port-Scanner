"""
NetPulse CLI Argument Parser Module.
Configures command-line options, descriptions, custom usage documentation,
and port parsing logic for single ports, comma-separated lists, and ranges.
"""

import argparse
import os
import random
import re
import sys
from typing import List, Optional

try:
    from .config import (
        COMMON_PORTS_LIST,
        DEFAULT_THREADS,
        DEFAULT_TIMEOUT,
        TOOL_NAME,
        TOP_100_PORTS_LIST,
        VERSION,
    )
except ImportError:
    TOOL_NAME = "NetPulse"
    VERSION = "1.0.0"
    DEFAULT_TIMEOUT = 1.5
    DEFAULT_THREADS = 100
    COMMON_PORTS_LIST = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
    TOP_100_PORTS_LIST = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]

CUSTOM_USAGE = """%(prog)s [-h] (-t TARGET | -iL FILE | TARGET) [-p PORTS | --common | --top-ports]
                [--exclude-ports PORTS] [-Pn] [-r] [--async] [-T THREADS] [--timeout TIMEOUT]
                [--rate-limit MS] [-b] [-o {json,txt}] [-q] [-v]"""

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

  # Scan a port range with custom thread count:
  python main.py -t scanme.nmap.org -p 1-1000 -T 200

  # Scan top 100 ports with 150 worker threads:
  python main.py -t example.com --top-ports --threads 150

  # Combined single ports and ranges:
  python main.py -t example.com -p 22,80-90,443,8000-8080 -b

  # Scan top common ports and export results:
  python main.py --target 127.0.0.1 --common -o json

  # Scan top 100 most common TCP ports:
  python main.py -t scanme.nmap.org --top-ports

  # Rate-limited scan (50ms delay between requests) to evade firewall thresholds:
  python main.py -t 192.168.1.1 --top-ports --rate-limit 50

  # Randomize port scan order to evade sequential IDS detection:
  python main.py -t 192.168.1.1 -p 1-1000 --randomize

  # Ultra-fast asynchronous scan using asyncio:
  python main.py -t 192.168.1.1 -p 1-10000 --async

  # Scan a CIDR subnet range across multiple hosts:
  python main.py -t 192.168.1.0/24 -p 80,443 --async

  # Scan targets from an input file one by one (like Nmap -iL):
  python main.py -iL targets.txt -p 80,443

  # Exclude specific ports from scan (e.g. skip sensitive ports):
  python main.py -t 192.168.1.1 -p 1-1000 --exclude-ports 80,443,8000-8080

  # Skip host alive check and force port scan (like Nmap -Pn):
  python main.py -t 192.168.1.1 -p 80,443 -Pn
"""


def read_targets_from_file(filepath: str) -> List[str]:
    """
    Reads target specifications (IPs, domains, CIDR ranges) from a text file.
    Supports one target per line, comma or whitespace separation, and strips
    comments (lines starting with '#' or inline comments).

    Args:
        filepath: Path to the target text file.

    Returns:
        List of non-empty target strings.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a regular file or contains no valid targets.
    """
    if not filepath or not os.path.exists(filepath):
        raise FileNotFoundError(f"Target list file not found: '{filepath}'")

    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a regular file: '{filepath}'")

    targets = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue
            # Remove inline comments e.g. "192.168.1.1 # webserver"
            clean_line = clean_line.split("#")[0].strip()
            tokens = [t.strip() for t in re.split(r"[\s,]+", clean_line) if t.strip()]
            targets.extend(tokens)

    if not targets:
        raise ValueError(f"No valid targets found in file: '{filepath}'")

    return targets


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
        help="Target IP address, CIDR range (e.g. 192.168.1.0/24), or domain name (e.g. scanme.nmap.org)",
    )
    target_group.add_argument(
        "-iL",
        "--input-file",
        dest="input_file",
        type=str,
        default=None,
        help="Read target list of IPs/domains/CIDR ranges from a .txt file (one per line)",
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
    port_group.add_argument(
        "--top-ports",
        dest="top_ports",
        action="store_true",
        help="Scan the top 100 most common TCP ports based on Nmap statistics",
    )
    port_group.add_argument(
        "--exclude-ports",
        dest="exclude_ports",
        type=str,
        default=None,
        help="Exclude specific ports from the scan queue (e.g. single: 80, list: 80,443, range: 100-200)",
    )
    port_group.add_argument(
        "-r",
        "--randomize",
        dest="randomize",
        action="store_true",
        help="Randomize port scan order using random.shuffle() to evade sequential IDS detection",
    )

    # Host Discovery Options
    discovery_group = parser.add_argument_group("Host Discovery Options")
    discovery_group.add_argument(
        "-Pn",
        "--Pn",
        dest="Pn",
        action="store_true",
        help="Treat target as online -- skip ICMP/TCP host alive check and force scan",
    )

    # Performance & Timing
    perf_group = parser.add_argument_group("Performance & Timing")
    perf_group.add_argument(
        "--async",
        dest="use_async",
        action="store_true",
        help="Enable ultra-fast asynchronous port scanning engine powered by asyncio",
    )
    perf_group.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Socket connection timeout in seconds (default: {DEFAULT_TIMEOUT}s)",
    )
    perf_group.add_argument(
        "--rate-limit",
        dest="rate_limit",
        type=float,
        default=0.0,
        help="Delay in milliseconds between requests per worker to evade firewall rate-limiting (default: 0ms)",
    )
    perf_group.add_argument(
        "-T",
        "--threads",
        "-w",
        "--workers",
        dest="threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent worker threads for ThreadPoolExecutor (default: {DEFAULT_THREADS})",
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

    # Resolve target from -t/--target, positional fallback, or -iL input file
    target = parsed_args.target_flag or parsed_args.positional_target
    input_file = parsed_args.input_file

    if not target and not input_file:
        parser.print_usage(sys.stderr)
        print(
            f"\n[!] Error: Target is required. Use -t/--target <IP/Domain/CIDR> or -iL <file.txt>.\n"
            f"Run '{parser.prog} --help' for usage and examples.",
            file=sys.stderr,
        )
        sys.exit(2)

    if input_file:
        try:
            file_targets = read_targets_from_file(input_file)
        except (FileNotFoundError, ValueError) as err:
            print(f"[!] Error loading targets from file: {err}", file=sys.stderr)
            sys.exit(2)

        if target:
            parsed_args.targets_list = [target] + file_targets
            parsed_args.target = f"{target},file:{input_file}"
        else:
            parsed_args.targets_list = file_targets
            parsed_args.target = f"file:{input_file}"
    else:
        parsed_args.target = target
        parsed_args.targets_list = [target]

    # Validate timeout argument
    if parsed_args.timeout <= 0:
        print(
            f"[!] Error: Timeout must be a positive float greater than 0 (received: {parsed_args.timeout}).",
            file=sys.stderr,
        )
        sys.exit(2)

    # Validate threads argument and map workers alias
    if parsed_args.threads < 1:
        print(
            f"[!] Error: Thread count must be at least 1 (received: {parsed_args.threads}).",
            file=sys.stderr,
        )
        sys.exit(2)
    parsed_args.workers = parsed_args.threads

    # Validate rate-limit argument
    if parsed_args.rate_limit < 0:
        print(
            f"[!] Error: Rate limit must be 0 or a positive number (received: {parsed_args.rate_limit}ms).",
            file=sys.stderr,
        )
        sys.exit(2)

    # Parse port specifications into a list of integers
    if parsed_args.top_ports:
        parsed_args.ports_list = list(TOP_100_PORTS_LIST)
    elif parsed_args.common:
        parsed_args.ports_list = list(COMMON_PORTS_LIST)
    elif parsed_args.ports:
        try:
            parsed_args.ports_list = parse_ports(parsed_args.ports)
        except ValueError as err:
            print(f"[!] Error parsing ports: {err}", file=sys.stderr)
            sys.exit(2)
    else:
        # Default standard port range: 1 - 1024
        parsed_args.ports_list = list(range(1, 1025))

    # Apply port exclusions if specified
    if parsed_args.exclude_ports:
        try:
            excluded_set = set(parse_ports(parsed_args.exclude_ports))
        except ValueError as err:
            print(f"[!] Error parsing excluded ports: {err}", file=sys.stderr)
            sys.exit(2)

        parsed_args.excluded_ports_list = sorted(list(excluded_set))
        parsed_args.ports_list = [p for p in parsed_args.ports_list if p not in excluded_set]

        if not parsed_args.ports_list:
            print("[!] Error: No ports remaining to scan after applying exclusions.", file=sys.stderr)
            sys.exit(2)
    else:
        parsed_args.excluded_ports_list = []

    # Randomize port scan order if requested to evade sequential IDS detection
    if parsed_args.randomize:
        parsed_args.ports_list = list(parsed_args.ports_list)
        random.shuffle(parsed_args.ports_list)

    return parsed_args


if __name__ == "__main__":
    cli_args = parse_arguments()
    print(f"Target: {cli_args.target}")
    print(f"Parsed Ports Count: {len(cli_args.ports_list)}")
    print(f"Sample Ports: {cli_args.ports_list[:10]}")
