"""
NetPulse Logging Module
Configures dual logging:
  - Formatted, colored/prefixed status messages to console (INFO / WARNING / ERROR)
  - Detailed error and exception traces to 'scanner.log' file (ERROR / CRITICAL)
"""

import logging
import sys
from pathlib import Path
from typing import Optional

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False


class ConsoleFormatter(logging.Formatter):
    """Custom formatter providing clean CLI prefixes and optional terminal colors."""

    PREFIXES = {
        logging.DEBUG: ("[DEBUG]", Fore.LIGHTBLACK_EX if COLOR_ENABLED else ""),
        logging.INFO: ("[*]", Fore.CYAN if COLOR_ENABLED else ""),
        logging.WARNING: ("[WARNING]", Fore.YELLOW if COLOR_ENABLED else ""),
        logging.ERROR: ("[-]", Fore.RED if COLOR_ENABLED else ""),
        logging.CRITICAL: ("[CRITICAL]", Fore.RED + Style.BRIGHT if COLOR_ENABLED else ""),
    }

    def format(self, record: logging.LogRecord) -> str:
        prefix_text, color = self.PREFIXES.get(record.levelno, ("[*]", ""))
        reset = Style.RESET_ALL if COLOR_ENABLED else ""

        message = super().format(record)
        return f"{color}{prefix_text} {message}{reset}"


def setup_logger(
    name: str = "NetPulse",
    log_file: str = "scanner.log",
    verbose: bool = False,
    file_level: int = logging.ERROR,
) -> logging.Logger:
    """
    Initializes and configures the application logger.

    Args:
        name: Logger identifier name.
        log_file: Path to file where errors will be recorded.
        verbose: When True, console outputs DEBUG-level messages.
        file_level: Logging level for the log file (default: logging.ERROR).

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Avoid adding duplicate handlers on multiple invocations
    if logger.handlers:
        return logger

    # 1. Console Stream Handler (INFO/WARNING/DEBUG)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_formatter = ConsoleFormatter("%(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 2. File Handler for Errors (scanner.log)
    try:
        log_path = Path(log_file)
        if log_path.parent and not log_path.parent.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(file_level)
        file_formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | [%(name)s:%(filename)s:%(lineno)d] | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except (OSError, IOError) as err:
        logger.warning(f"Could not initialize log file '{log_file}': {err}")

    return logger


# Default application-wide logger instance
logger = setup_logger()
