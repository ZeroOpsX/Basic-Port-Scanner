"""Backwards compatibility layer: re-exports constants from utils.config."""

from utils.config import (
    COMMON_PORTS,
    COMMON_PORTS_LIST,
    COMMON_UDP_PORTS,
    COMMON_UDP_PORTS_LIST,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    TOOL_NAME,
    TOP_100_PORTS,
    TOP_100_PORTS_LIST,
    VERSION,
)

__all__ = [
    "COMMON_PORTS",
    "COMMON_PORTS_LIST",
    "COMMON_UDP_PORTS",
    "COMMON_UDP_PORTS_LIST",
    "TOP_100_PORTS",
    "TOP_100_PORTS_LIST",
    "DEFAULT_TIMEOUT",
    "DEFAULT_THREADS",
    "DEFAULT_OUTPUT_DIR",
    "TOOL_NAME",
    "VERSION",
]
