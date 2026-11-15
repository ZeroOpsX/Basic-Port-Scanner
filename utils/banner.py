"""ASCII banner and styling for NetPulse CLI."""

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT
except ImportError:
    CYAN = ""
    GREEN = ""
    YELLOW = ""
    RED = ""
    RESET = ""
    BRIGHT = ""

BANNER = r"""
 _   _      _   ____        _          
| \ | | ___| |_|  _ \ _   _| |___  ___ 
|  \| |/ _ \ __| |_) | | | | / __|/ _ \
| |\  |  __/ |_|  __/| |_| | \__ \  __/
|_| \_|\___|\__|_|    \__,_|_|___/\___|
"""

from .config import AUTHOR, TOOL_NAME, VERSION


def print_banner() -> None:
    """Prints the application header banner."""
    print(f"{CYAN}{BRIGHT}{BANNER}{RESET}")
    print(f"{YELLOW}  [ NetPulse - Modern CLI Port Scanner v{VERSION} ]{RESET}")
    print(f"{YELLOW}  [ Author: Professional Security Toolkit ]\n{RESET}")
