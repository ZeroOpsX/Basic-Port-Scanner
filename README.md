# ⚡ NetPulse — High-Performance Network Reconnaissance & Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT">
  <img src="https://img.shields.io/badge/Tests-145%20Passed-brightgreen?style=for-the-badge&logo=pytest&logoColor=white" alt="Tests">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platform">
</p>

<p align="center">
  <strong>NetPulse</strong> is an advanced, high-performance command-line network exploration and port scanning tool engineered in Python. Built with both <code>concurrent.futures</code> multi-threading and an <code>asyncio</code> asynchronous engine, NetPulse delivers rapid port discovery, deep service banner grabbing, SSL/TLS inspection, OS fingerprinting, vulnerability auditing, and multi-format report exports (JSON, CSV, and Dark-Mode HTML).
</p>

---

## 🌟 Key Features

| Capability | Description |
| :--- | :--- |
| 🚀 **Dual Scan Engines** | Multi-threaded (`ThreadPoolExecutor` up to 1000+ workers) or ultra-fast non-blocking asynchronous (`asyncio`). |
| 🛡️ **SYN Stealth Scan (`-sS`)** | Half-open raw TCP SYN scanning via Scapy that bypasses full 3-way handshakes and evasively detects filtered states. |
| 📡 **UDP Scanner (`-sU`)** | Native `SOCK_DGRAM` probe scanner for critical UDP services (DNS:53, NTP:123, SNMP:161, DHCP:67). |
| 🔍 **Deep Banner Grabbing (`-b`)** | Interactive socket probes, HTTP `HEAD` header inspection (`Server`, `X-Powered-By`), and OpenSSH OS banner parsing. |
| 🔒 **SSL/TLS Inspector** | Inspects SSL/TLS certificates on HTTPS, SMTPS, and IMAPS ports; extracts Common Name (CN), Issuer, and Expiry date. |
| 💻 **OS Fingerprinting & Host Discovery** | ICMP / TCP ping alive check with TTL (Time To Live) inspection to deduce target operating systems (Linux, Windows, Cisco). |
| ⚠️ **Vulnerability Auditing** | Detects anonymous FTP logins (Port 21) and correlates service versions against CIRCL/NVD public CVE databases. |
| 🎯 **Target Flexibility** | Supports single IP addresses, FQDN hostnames, CIDR blocks (e.g. `192.168.1.0/24`), and target files (`-iL targets.txt`). |
| ⏱️ **Evasion & Rate-Limiting** | Port order randomization (`-r`), per-thread delay pacing (`--rate-limit`), port exclusion lists (`--exclude-ports`), and forced scan (`-Pn`). |
| 🎨 **Rich Terminal UI** | Colorized port states (Open = Green, Closed = Red, Filtered = Yellow), live progress bar with ETA, and summary tables. |
| 📊 **Multi-Format Exporters** | Export audit reports to structured `.json` (`-oJ`), spreadsheet `.csv` (`-oC`), or responsive dark-mode `.html` (`-oH`). |
| 📦 **Pip Installable** | Standard `pyproject.toml` and `setup.py` packaging — install once and run globally using the `netpulse` CLI. |

---

## 📁 Repository Structure

```text
NetPulse/
├── core/
│   ├── __init__.py           # Core exports
│   ├── constants.py          # Port maps (IANA, Top-100), timeouts & defaults
│   ├── host_discovery.py     # ICMP/TCP ping alive checks & TTL-based OS fingerprinting
│   ├── scanner.py            # Multi-threaded & Async scan engines with Rich progress
│   ├── service_detector.py   # Banner grabbing, HTTP HEAD analysis, and SSH parser
│   ├── ssl_inspector.py      # SSL/TLS certificate inspector (CN, Issuer, Expiry)
│   ├── syn_scanner.py        # Scapy raw TCP SYN stealth half-open scanner
│   ├── udp_scanner.py        # UDP socket scanner for common datagram services
│   └── vuln_checks.py        # Anonymous FTP checks & CIRCL CVE vulnerability lookup
├── output/
│   ├── __init__.py           # Output package exports
│   ├── display.py            # Rich colorized terminal output & formatted summary tables
│   └── exporter.py           # JSON, CSV, and responsive dark-mode HTML report generators
├── utils/
│   ├── __init__.py           # Utilities package exports
│   ├── banner.py             # ASCII banner & terminal header
│   ├── cli.py                # Command-line argument parser & custom help formatters
│   └── helpers.py            # IP/CIDR/target validation, port ranges, and file I/O
├── tests/
│   ├── __init__.py
│   └── test_scanner.py       # Comprehensive pytest suite (145 tests)
├── pyproject.toml            # Modern PEP 517/518 build configuration
├── setup.py                  # Setup script & console script entry point (`netpulse`)
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 🛠️ Installation

### Option A: Install Globally via Pip (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/NetPulse.git
cd "NetPulse"

# Install locally as an editable package
pip install -e .
```

Now you can invoke `netpulse` directly anywhere in your terminal:
```bash
netpulse --version
netpulse --help
```

### Option B: Run in a Virtual Environment

```bash
# 1. Clone repository
git clone https://github.com/your-username/NetPulse.git
cd "NetPulse"

# 2. Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run directly with Python
python main.py --help
```

> [!NOTE]
> **Raw SYN Scanning Prerequisites**: TCP SYN stealth scanning (`-sS`) uses raw sockets via Scapy. On Windows, [Npcap](https://npcap.com/) or WinPcap must be installed and you must run your terminal as Administrator. On Linux/macOS, execute with `sudo netpulse -sS ...`.

---

## 📖 CLI Flags & Options Reference

| Option | Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| **Target** | `-t`, `--target` | Target IP, hostname (`scanme.nmap.org`), or CIDR subnet (`192.168.1.0/24`) | *Required* |
| **Target File** | `-iL`, `--input-file` | Load targets from a `.txt` file (one IP/domain per line) | `None` |
| **Port Specification** | `-p`, `--ports` | Ports to scan: single (`80`), list (`80,443`), or range (`1-1000`) | `1-1024` |
| **Common Ports** | `--common` | Scan well-known common service ports (HTTP, SSH, FTP, MySQL, etc.) | `False` |
| **Top Ports** | `--top-ports` | Scan the top 100 most common TCP ports | `False` |
| **Port Exclusion** | `--exclude-ports` | Exclude specific ports from scan queue (e.g. `80,443,8000-8080`) | `None` |
| **Randomize** | `-r`, `--randomize` | Randomize port scan sequence to evade sequential IDS detection | `False` |
| **Host Discovery** | `-Pn`, `--Pn` | Skip ICMP/TCP alive check and force scanning | `False` |
| **SYN Stealth** | `-sS`, `--syn` | Perform half-open raw TCP SYN scan (requires root/admin) | `False` |
| **UDP Scan** | `-sU`, `--udp` | Probe common UDP services (DNS, NTP, SNMP, DHCP) | `False` |
| **Async Engine** | `--async` | Enable non-blocking `asyncio` scanning engine | `False` |
| **Worker Threads** | `-T`, `--threads` | Number of concurrent worker threads | `100` |
| **Socket Timeout** | `--timeout` | Connection timeout in seconds | `1.5s` |
| **Rate Limit** | `--rate-limit` | Delay in milliseconds between requests per worker | `0ms` |
| **Banner Grabbing** | `-b`, `--banner` | Grab service banners, HTTP headers, SSH versions, and SSL info | `False` |
| **Verbose Mode** | `-v`, `--verbose` | Show closed/filtered ports and real-time connection attempts | `False` |
| **JSON Export** | `-oJ`, `--json` | Export scan results to JSON in `output/` directory | `False` |
| **CSV Export** | `-oC`, `--csv` | Export scan results table to CSV spreadsheet | `False` |
| **HTML Export** | `-oH`, `--html` | Export an interactive dark-mode HTML report | `False` |
| **Generic Export** | `-o {format}` | Save scan results (`json`, `csv`, `html`, `txt`) | `None` |
| **Quiet Mode** | `-q`, `--quiet` | Suppress ASCII logo banner and header | `False` |

---

## 🚀 Usage Recipes & Examples

### 1. Basic & Common Port Scans
```bash
# Scan default ports (1-1024)
netpulse -t 192.168.1.1

# Scan top 100 most common TCP ports with banner grabbing
netpulse -t scanme.nmap.org --top-ports -b

# Scan specific ports and ranges with custom thread pool
netpulse -t 192.168.1.1 -p 22,80,443,8000-8080 -T 250
```

### 2. High-Speed Asynchronous Subnet Scanning
```bash
# Scan an entire /24 CIDR subnet asynchronously across web ports
netpulse -t 192.168.1.0/24 -p 80,443,8080 --async
```

### 3. Evading Firewalls & IDS
```bash
# Randomize port order and add 50ms delay between connections
netpulse -t 10.0.0.1 -p 1-1000 -r --rate-limit 50 --exclude-ports 135,139,445
```

### 4. Stealth SYN & UDP Scanning
```bash
# TCP SYN half-open stealth scan (run as sudo or administrator)
sudo netpulse -t 192.168.1.100 -sS -p 21,22,80,443

# UDP scan for DNS, SNMP, and NTP
netpulse -t 8.8.8.8 -sU
```

### 5. Multi-Target Batch Scanning from File
```bash
# Scan multiple hosts listed in targets.txt
netpulse -iL targets.txt --common -b -oJ
```

### 6. Comprehensive Audit with Multi-Format Export
```bash
# Scan top ports, grab banners, audit vulnerabilities, and export reports to JSON, CSV, and HTML
netpulse -t scanme.nmap.org --top-ports -b -v -oJ -oC -oH
```

---

## 🖥️ Sample Terminal Output

NetPulse renders an interactive, colorized terminal UI powered by **Rich**:

```text
================================================================================
  _   _      _   ____        _          
 | \ | | ___| |_|  _ \ _   _| |___  ___ 
 |  \| |/ _ \ __| |_) | | | | / __|/ _ \
 | |\  |  __/ |_|  __/| |_| | \__ \  __/
 |_| \_|\___|\__|_|    \__,_|_|___/\___|
                                        
 NetPulse — High-Performance Network & Port Scanner v1.0.0
================================================================================
[+] Target Host        : 192.168.1.15 (ubuntu-server.local)
[+] Estimated OS       : Linux / Unix (TTL: 64)
[+] Scan Mode          : Multi-threaded (100 workers) | Timeout: 1.5s
[+] Ports to Scan      : 21, 22, 80, 443, 3306
────────────────────────────────────────────────────────────────────────────────
Scanning [━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━] 100% 5/5 ports • 00:00:01

[+] [OPEN]     Port 21/tcp (ftp)
    └── Response/Banner: 220 ProFTPD 1.3.5 Server
    [!] Vulnerability Flagged: [HIGH] Anonymous FTP login enabled (anonymous:anonymous@)
[+] [OPEN]     Port 22/tcp (ssh)
    └── Response/Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
[+] [OPEN]     Port 80/tcp (http)
    └── Response/Banner: HTTP/1.1 200 OK | Server: nginx/1.18.0
[+] [OPEN]     Port 443/tcp (https)
    └── Response/Banner: HTTP/1.1 200 OK | Server: nginx/1.18.0
    └── SSL/TLS: CN=*.example.com | Issuer=Let's Encrypt | Expires=2026-08-15

┏━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ Protocol ┃ State  ┃ Service ┃ Banner / Version Details                            ┃
┡━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 21   │ tcp      │ OPEN   │ ftp     │ 220 ProFTPD 1.3.5 | [VULN] Anonymous FTP Allowed    │
│ 22   │ tcp      │ OPEN   │ ssh     │ OpenSSH 8.9p1 (Ubuntu Linux)                        │
│ 80   │ tcp      │ OPEN   │ http    │ nginx/1.18.0                                        │
│ 443  │ tcp      │ OPEN   │ https   │ nginx/1.18.0 | SSL: *.example.com (Valid)           │
│ 3306 │ tcp      │ CLOSED │ mysql   │ Connection refused                                  │
└──────┴──────────┴────────┴─────────┴─────────────────────────────────────────────────────┘

[✓] Scan completed in 1.42s
[*] Total Ports Scanned : 5
[*] Open Ports Detected : 4
[*] Vulnerabilities     : 1 flagged
[+] Reports saved to:
    - output/scan_192.168.1.15_20261116_103000.json
    - output/scan_192.168.1.15_20261116_103000.csv
    - output/scan_192.168.1.15_20261116_103000.html
```

---

## 🌐 Dark-Mode HTML Report Preview

When using `-oH` or `--html`, NetPulse generates a self-contained, responsive report with a modern cyber-dark aesthetic:

- 📊 **Executive Summary Cards**: Target IP, Hostname, Detected OS, Scan Duration, Ports Open vs Filtered vs Closed.
- 🏷️ **Status Badges**: Color-coded pill badges indicating port states and discovered protocols.
- 🛡️ **Vulnerability Alerts**: Prominently highlighted security findings (such as Anonymous FTP access or outdated banners).
- 📱 **Mobile & Desktop Responsive**: Pure CSS layout requiring zero external dependencies or internet access to view.

---

## 🧪 Running the Test Suite

NetPulse includes unit and integration tests covering port parsing, network helpers, scanners, display styling, and report exporters:

```bash
# Run tests with pytest
pytest tests/ -v

# Or run with Python's built-in unittest framework
python -m unittest discover tests
```

---

## ⚖️ Legal Disclaimer

> [!CAUTION]
> **FOR EDUCATIONAL AND AUTHORIZED SECURITY AUDITING PURPOSES ONLY.**
> 
> Scanning networks, hosts, or ports without explicit, written permission from the target owner is illegal in many jurisdictions and may violate federal, state, and international laws (such as the US Computer Fraud and Abuse Act - CFAA).
> 
> The developers of NetPulse assume **no liability** and are **not responsible** for any misuse, unauthorized access, or damage caused by this program. Users are strictly responsible for adhering to all applicable laws and regulations in their jurisdiction.

---

## 📄 License

This project is open-source software licensed under the **[MIT License](LICENSE)**.
