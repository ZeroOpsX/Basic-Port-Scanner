"""
ASCII art banner and ethical use disclaimer for NetPulse Port Scanner.
"""

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM
except ImportError:
    CYAN = ""
    GREEN = ""
    YELLOW = ""
    RED = ""
    BLUE = ""
    MAGENTA = ""
    WHITE = ""
    RESET = ""
    BRIGHT = ""
    DIM = ""

try:
    from .config import TOOL_NAME, VERSION
except ImportError:
    TOOL_NAME = "NetPulse"
    VERSION = "1.0.0"

# Cybersecurity / Pulse themed ASCII logo
BANNER_ART = r"""
 ███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
 ██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██║     ███████╗█████╗  
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
 ██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝███████╗███████║███████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
                     [ >> PORT SCANNER << ]
"""

DISCLAIMER_TEXT = (
    "LEGAL DISCLAIMER: NetPulse is designed strictly for educational purposes, authorized\n"
    "network auditing, and penetration testing on systems you own or have explicit\n"
    "written permission to test. Unauthorized port scanning or reconnaissance against\n"
    "third-party infrastructure is illegal and punishable under cybersecurity laws."
)


def get_banner() -> str:
    """Builds and returns the complete styled banner with metadata and disclaimer."""
    divider = "═" * 72
    thin_divider = "─" * 72

    output = []
    output.append(f"{CYAN}{BRIGHT}{BANNER_ART}{RESET}")
    output.append(f"{BLUE}{divider}{RESET}")
    output.append(
        f" {WHITE}{BRIGHT}Tool:{RESET} {CYAN}{TOOL_NAME} Port Scanner{RESET} "
        f"| {WHITE}{BRIGHT}Version:{RESET} {GREEN}v{VERSION}{RESET} "
        f"| {WHITE}{BRIGHT}Engine:{RESET} {MAGENTA}TCP SYN & Connect{RESET}"
    )
    output.append(f"{BLUE}{thin_divider}{RESET}")
    output.append(f"{YELLOW}{BRIGHT}[!] ETHICAL USE NOTICE & DISCLAIMER:{RESET}")
    for line in DISCLAIMER_TEXT.splitlines():
        output.append(f"{YELLOW}{DIM}    {line}{RESET}")
    output.append(f"{BLUE}{divider}{RESET}\n")

    return "\n".join(output)


def print_banner() -> None:
    """Prints the styled ASCII art banner and ethical use disclaimer to stdout."""
    print(get_banner())


if __name__ == "__main__":
    print_banner()
