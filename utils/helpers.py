"""Input validation, port range parsing, and report exporting helpers."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def parse_port_range(port_str: str) -> List[int]:
    """
    Parses port specification strings into a sorted list of unique port integers.
    Supports formats:
      - Single port: "80"
      - Comma-separated: "80,443,8080"
      - Range: "1-1024"
      - Combined: "22,80-85,443"
    """
    ports = set()
    parts = [p.strip() for p in port_str.split(",") if p.strip()]

    for part in parts:
        if "-" in part:
            sub_parts = part.split("-")
            if len(sub_parts) != 2:
                raise ValueError(f"Invalid range format: '{part}'")
            start, end = int(sub_parts[0]), int(sub_parts[1])
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Port range out of valid boundaries (1-65535): '{part}'")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of valid range (1-65535): {port}")
            ports.add(port)

    return sorted(list(ports))


def validate_target(target: str) -> bool:
    """Basic validation for target host/IP string."""
    if not target or not isinstance(target, str):
        return False
    return len(target.strip()) > 0


def export_results(
    results: List[Dict],
    target: str,
    target_ip: str,
    output_dir: str = "output",
    export_format: str = "json",
) -> str:
    """Exports scan results into JSON or TXT file inside output directory."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = target.replace(".", "_").replace(":", "_")
    filename = f"scan_{clean_target}_{timestamp}.{export_format}"
    file_path = out_path / filename

    data = {
        "target": target,
        "target_ip": target_ip,
        "scan_time": datetime.now().isoformat(),
        "open_ports_count": len(results),
        "results": results,
    }

    if export_format.lower() == "json":
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    else:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"NetPulse Scan Report\n")
            f.write(f"Target: {target} ({target_ip})\n")
            f.write(f"Timestamp: {data['scan_time']}\n")
            f.write(f"{'-' * 50}\n")
            f.write(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'BANNER'}\n")
            f.write(f"{'-' * 50}\n")
            for r in results:
                f.write(
                    f"{r['port']:<10}{r['state']:<10}{r['service']:<15}{r.get('banner', '')}\n"
                )

    return str(file_path)
