"""
NetPulse CLI Argument Parser Module.
Configures command-line options, descriptions, and custom usage documentation.
"""

import argparse
import sys
from typing import List, Optional

try:
    from .config import DEFAULT_THREADS, DEFAULT_TIMEOUT, TOOL_NAME, VERSION
except ImportError:
    TOOL_NAME = "NetPulse"
    VERSION = "1.0.0"
    DEFAULT_TIMEOUT = 1.5
    DEFAULT_THREADS = 100

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
  # Scan default ports (1-1024) on target IP:
  python main.py -t 192.168.1.1

  # Scan specific ports with service banner grabbing:
  python main.py -t scanme.nmap.org -p 22,80,443,8080 -b

  # Scan common ports with 200 concurrent threads and export to JSON:
  python main.py --target example.com --common -w 200 -o json

  # Quick scan on localhost with custom timeout:
  python main.py -t 127.0.0.1 -p 1-500 --timeout 0.5 -q
"""


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
        help=argparse.SUPPRESS,  # Hidden positional fallback for convenience
    )

    # Port options
    port_group = parser.add_argument_group("Port Scan Options")
    port_group.add_argument(
        "-p",
        "--ports",
        type=str,
        default=None,
        help="Port specification (e.g. '80', '1-1024', '80,443,8080'). Default: 1-1024",
    )
    port_group.add_argument(
        "--common",
        action="store_true",
        help="Scan top well-known ports only (HTTP, SSH, MySQL, etc.)",
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
    Resolves target from either -t/--target or positional input.
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
    return parsed_args


if __name__ == "__main__":
    cli_args = parse_arguments()
    print(f"Target selected: {cli_args.target}")
