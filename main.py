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

from core.async_scanner import run_async_scan
from core.constants import COMMON_PORTS
from core.host_discovery import get_host_os_guess, is_host_online
from core.scanner import scan_port, scan_ports_concurrent
from core.syn_scanner import check_admin_privileges, syn_scan_ports
from core.udp_scanner import scan_udp_ports_concurrent
from core.vuln_checks import check_ftp_anonymous, run_port_vulnerability_checks
from utils.banner import print_banner
from utils.cli import parse_arguments
from utils.helpers import export_results
from utils.logger import logger
from utils.validators import resolve_target, resolve_targets

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
        if scan_context.get("multi_host"):
            print(f"{'HOST':<18}{'PORT':<12}{'STATE':<10}{'SERVICE':<15}")
            print("-" * 55)
            for entry in open_ports:
                host_label = entry.get("host", scan_context["target"])
                port_label = f"{entry['port']}/tcp"
                service_label = entry.get("service", "Unknown")
                print(f"{host_label:<18}{port_label:<12}{'OPEN':<10}{service_label:<15}")
        else:
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

    # 4. Validate and resolve target IP/Domain/CIDR using validators.py
    try:
        targets = []
        raw_targets = getattr(args, "targets_list", [args.target])
        for t in raw_targets:
            targets.extend(resolve_targets(t))
    except ValueError as err:
        logger.error(f"Target validation failed: {err}")
        sys.exit(1)

    ports = args.ports_list
    multi_host = len(targets) > 1 or bool(getattr(args, "input_file", None))

    # Enforce root/administrator privileges upfront if TCP SYN scan is requested
    if getattr(args, "syn_scan", False):
        try:
            check_admin_privileges()
        except PermissionError as err:
            logger.error(str(err))
            print(f"[!] Error: {err}", file=sys.stderr)
            sys.exit(1)

    # Record exact start time
    start_timestamp = time.time()
    start_time_str = format_timestamp(start_timestamp)

    # Initialize shared scan context
    scan_context["start_timestamp"] = start_timestamp
    scan_context["start_time_str"] = start_time_str
    scan_context["total_ports"] = len(ports) * len(targets)
    scan_context["scanned_count"] = 0
    scan_context["target"] = args.target
    scan_context["target_ip"] = targets[0][1] if len(targets) == 1 else args.target
    scan_context["output_format"] = args.output
    scan_context["open_ports"] = []
    scan_context["interrupted"] = False
    scan_context["multi_host"] = multi_host

    # Engine messaging
    rate_limit_msg = f" | Rate Limit: {args.rate_limit}ms" if args.rate_limit > 0 else ""
    randomize_msg = " | Order: Randomized" if args.randomize else ""
    exclude_msg = (
        f" | Excluded: {len(args.excluded_ports_list)} port(s)"
        if getattr(args, "exclude_ports", None)
        else ""
    )
    if getattr(args, "syn_scan", False):
        concurrency = min(args.threads, 30)
        engine_msg = f"TCP SYN stealth engine (Half-Open Scapy, {concurrency} workers)"
    elif getattr(args, "udp_scan", False):
        concurrency = min(args.threads, 30)
        engine_msg = f"UDP engine (SOCK_DGRAM, {concurrency} workers)"
    elif args.use_async:
        concurrency = args.threads if args.threads != 100 else 500
        engine_msg = f"asyncio engine (Concurrency: {concurrency})"
    else:
        concurrency = args.threads
        engine_msg = f"{args.threads} worker threads"

    if getattr(args, "input_file", None):
        logger.info(f"Target Source: File '{args.input_file}' ({len(targets)} host(s) to scan)")
    elif multi_host:
        logger.info(f"Target CIDR: {args.target} (Expanded to {len(targets)} hosts)")
    else:
        logger.info(f"Target: {targets[0][0]} ({targets[0][1]})")
        os_info = get_host_os_guess(targets[0][1], timeout=args.timeout)
        if os_info and os_info.get("os") != "Unknown":
            logger.info(
                f"Target OS Guess: {os_info['os']} (Observed TTL: {os_info['ttl']}, ~{os_info['hops']} hop{'s' if os_info['hops'] != 1 else ''})"
            )

    logger.info(f"Scan Started at: {start_time_str}")
    logger.info(
        f"Initiating scan on {len(ports)} port(s) across {len(targets)} host(s) with {engine_msg} (Timeout: {args.timeout}s{rate_limit_msg}{randomize_msg}{exclude_msg})..."
    )
    print("-" * 65)
    if multi_host:
        print(f"{'HOST':<18}{'PORT':<12}{'STATE':<10}{'SERVICE':<15}")
    else:
        print(f"{'PORT':<12}{'STATE':<10}{'SERVICE':<15}")
    print("-" * 65)

    def on_port_discovered(port_entry: dict):
        scan_context["open_ports"].append(port_entry)
        proto = port_entry.get("protocol") or ("udp" if getattr(args, "udp_scan", False) else "tcp")
        port_label = f"{port_entry['port']}/{proto}"
        if multi_host:
            host_label = port_entry.get("host", "")
            print(f"{host_label:<18}{port_label:<12}{'OPEN':<10}{port_entry['service']:<15}")
        else:
            print(f"{port_label:<12}{'OPEN':<10}{port_entry['service']:<15}")

        if port_entry.get("banner"):
            print(f"  └── Response/Banner: {port_entry['banner']}")

        # Check for service vulnerabilities (e.g., FTP anonymous login on port 21)
        if proto == "tcp":
            host_ip = port_entry.get("host") or (targets[0][1] if len(targets) == 1 else args.target)
            vulns = run_port_vulnerability_checks(host_ip, port_entry["port"], timeout=args.timeout)
            if vulns:
                port_entry["vulns"] = vulns
                for vuln in vulns:
                    flag = vuln.get("flag") or f"[!] VULN: {vuln.get('title')}"
                    print(f"  └── {flag}")

    # 5. Execute Scan across resolved target hosts
    for canonical_target, target_ip in targets:
        # Check host availability unless -Pn is specified
        if not args.Pn:
            if not is_host_online(target_ip, timeout=args.timeout):
                logger.warning(
                    f"Target '{canonical_target}' ({target_ip}) did not respond to ICMP/TCP ping (host down or firewalling probes)."
                )
                scan_context["scanned_count"] += len(ports)
                continue

        # Inspect TTL to guess remote operating system for multi-host scans
        if multi_host:
            os_info = get_host_os_guess(target_ip, timeout=args.timeout)
            if os_info and os_info.get("os") != "Unknown":
                logger.info(
                    f"[{target_ip}] OS Guess: {os_info['os']} (Observed TTL: {os_info['ttl']}, ~{os_info['hops']} hop{'s' if os_info['hops'] != 1 else ''})"
                )

        def make_port_callback(host_ip):
            def _cb(entry):
                entry["host"] = host_ip
                on_port_discovered(entry)
            return _cb

        cb = make_port_callback(target_ip)

        if getattr(args, "syn_scan", False):
            syn_scan_ports(
                ip=target_ip,
                ports=ports,
                timeout=args.timeout,
                max_workers=min(args.threads, 30),
                rate_limit_ms=args.rate_limit,
                on_port_scanned=cb,
                enforce_admin=False,
            )
        elif getattr(args, "udp_scan", False):
            scan_udp_ports_concurrent(
                ip=target_ip,
                ports=ports,
                timeout=args.timeout,
                max_workers=min(args.threads, 30),
                rate_limit_ms=args.rate_limit,
                include_open_filtered=False,
                on_port_scanned=cb,
            )
        elif args.use_async:
            run_async_scan(
                ip=target_ip,
                ports=ports,
                timeout=args.timeout,
                concurrency=concurrency,
                rate_limit_ms=args.rate_limit,
                grab_banners=args.banner,
                on_port_scanned=cb,
            )
        else:
            scan_ports_concurrent(
                ip=target_ip,
                ports=ports,
                timeout=args.timeout,
                max_workers=args.threads,
                rate_limit_ms=args.rate_limit,
                grab_banners=args.banner,
                on_port_scanned=cb,
            )
        scan_context["scanned_count"] += len(ports)

    # Record exact end time and duration
    end_timestamp = time.time()
    end_time_str = format_timestamp(end_timestamp)
    total_duration = end_timestamp - start_timestamp

    open_ports = scan_context["open_ports"]
    scanned_count = scan_context["scanned_count"]
    total_probes = len(ports) * len(targets)

    # 6. Detailed Timing & Execution Summary
    print("-" * 65)
    print("                    [ SCAN SUMMARY ]")
    print("-" * 65)
    print(f"[*] Exact Start Time : {start_time_str}")
    print(f"[*] Exact End Time   : {end_time_str}")
    print(f"[*] Total Duration   : {total_duration:.2f} seconds ({format_duration(total_duration)})")
    if multi_host:
        print(f"[*] Hosts In Range   : {len(targets)}")
    print(f"[*] Ports Scanned    : {scanned_count}/{total_probes}")
    print(f"[*] Open Ports Found : {len(open_ports)}")
    total_vulns = sum(len(p.get("vulns", [])) for p in open_ports)
    if total_vulns > 0:
        print(f"[*] Vulnerabilities  : {total_vulns} flagged")
    print("-" * 65)

    # Export scan report if requested
    if args.output:
        saved_file = export_results(
            results=open_ports,
            target=args.target,
            target_ip=targets[0][1] if len(targets) == 1 else args.target,
            export_format=args.output,
        )
        logger.info(f"Report exported successfully: {saved_file}")


if __name__ == "__main__":
    main()
