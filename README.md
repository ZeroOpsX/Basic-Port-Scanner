# NetPulse - CLI Port Scanner

**NetPulse** is a lightweight, multi-threaded command-line TCP port scanner written in Python. It is designed for network diagnostics, security audits, and quick port discovery.

---

## 📁 Project Structure

```text
NetPulse/
├── core/
│   ├── __init__.py         # Package exports
│   ├── constants.py        # Default configurations & well-known port mapping
│   └── scanner.py          # Concurrent PortScanner engine with ThreadPoolExecutor
├── utils/
│   ├── __init__.py         # Helper exports
│   ├── banner.py           # CLI ASCII header & terminal styling
│   └── helpers.py          # Target validation, port parser & report exporters
├── output/
│   └── .gitkeep            # Directory for exported scan reports (.json / .txt)
├── tests/
│   ├── __init__.py
│   └── test_scanner.py     # Unit tests for core scanning & parsing logic
├── .gitignore              # Standard Python gitignore rules
├── main.py                 # CLI entry point
├── requirements.txt        # Optional CLI enhancement & testing dependencies
└── README.md               # Documentation
```

---

## 🚀 Quick Start

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-username/NetPulse.git
cd "NetPulse"

# (Optional) Create virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Usage Examples

Scan default ports (1-1024):
```bash
python main.py 127.0.0.1
```

Scan specific ports:
```bash
python main.py 192.168.1.1 -p 80,443,8080
```

Scan a port range with 200 concurrent threads and banner grabbing:
```bash
python main.py scanme.nmap.org -p 20-100 -w 200 -b
```

Scan top common ports and export results to JSON:
```bash
python main.py localhost --common -o json
```

### 3. Running Tests

Run the built-in test suite:
```bash
python -m unittest discover tests
```
or with pytest:
```bash
pytest
```
