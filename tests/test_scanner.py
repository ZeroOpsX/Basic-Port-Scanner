"""Unit tests for NetPulse core logic and helper utilities."""

import os
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from core.constants import COMMON_PORTS
from core.scanner import PortScanner
from utils.helpers import export_results, parse_port_range, validate_target


class TestPortParser(unittest.TestCase):
    """Tests for CLI port parsing logic."""

    def test_single_port(self):
        self.assertEqual(parse_port_range("80"), [80])

    def test_comma_separated(self):
        self.assertEqual(parse_port_range("80, 443, 8080"), [80, 443, 8080])

    def test_range(self):
        self.assertEqual(parse_port_range("20-25"), [20, 21, 22, 23, 24, 25])

    def test_combination(self):
        self.assertEqual(parse_port_range("22, 80-82"), [22, 80, 81, 82])

    def test_invalid_range_raises(self):
        with self.assertRaises(ValueError):
            parse_port_range("100-50")

    def test_out_of_bounds_raises(self):
        with self.assertRaises(ValueError):
            parse_port_range("70000")


class TestHelpers(unittest.TestCase):
    """Tests for validation and export helpers."""

    def test_validate_target(self):
        self.assertTrue(validate_target("127.0.0.1"))
        self.assertTrue(validate_target("localhost"))
        self.assertFalse(validate_target(""))

    def test_export_results_json(self):
        sample_results = [
            {"port": 80, "state": "OPEN", "service": "HTTP", "banner": ""}
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = export_results(
                results=sample_results,
                target="localhost",
                target_ip="127.0.0.1",
                output_dir=tmp_dir,
                export_format="json",
            )
            self.assertTrue(os.path.exists(file_path))
            self.assertTrue(file_path.endswith(".json"))


class TestScanner(unittest.TestCase):
    """Tests for PortScanner class."""

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    def test_target_resolution(self, mock_resolve):
        scanner = PortScanner(target="localhost")
        self.assertEqual(scanner.target_ip, "127.0.0.1")

    @patch("socket.socket")
    @patch("socket.gethostbyname", return_value="127.0.0.1")
    def test_scan_port_open(self, mock_resolve, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner(target="127.0.0.1")
        result = scanner.scan_port(80)

        self.assertIsNotNone(result)
        self.assertEqual(result["port"], 80)
        self.assertEqual(result["state"], "OPEN")
        self.assertEqual(result["service"], COMMON_PORTS.get(80))

    @patch("socket.socket")
    def test_scan_port_standalone_open(self, mock_socket_cls):
        from core.scanner import PortStatus, scan_port
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        status = scan_port("127.0.0.1", 443, timeout=1.0)
        self.assertTrue(status)
        self.assertEqual(status, PortStatus.OPEN)
        self.assertEqual(status, "OPEN")
        mock_sock.connect_ex.assert_called_with(("127.0.0.1", 443))
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_standalone_closed(self, mock_socket_cls):
        from core.scanner import PortStatus, scan_port
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        status = scan_port("127.0.0.1", 9999, timeout=1.0)
        self.assertFalse(status)
        self.assertEqual(status, PortStatus.CLOSED)
        self.assertEqual(status, "CLOSED")
        mock_sock.connect_ex.assert_called_with(("127.0.0.1", 9999))
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_handles_timeout(self, mock_socket_cls):
        from core.scanner import PortStatus, scan_port
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value = mock_sock

        status = scan_port("192.168.1.1", 80, timeout=0.5)
        self.assertFalse(status)
        self.assertEqual(status, PortStatus.FILTERED)
        self.assertEqual(status, "FILTERED")
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_winsock_codes(self, mock_socket_cls):
        from core.scanner import PortStatus, scan_port
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # WSAECONNREFUSED (10061) -> CLOSED
        mock_sock.connect_ex.return_value = 10061
        self.assertEqual(scan_port("127.0.0.1", 21), PortStatus.CLOSED)

        # WSAETIMEDOUT (10060) -> FILTERED
        mock_sock.connect_ex.return_value = 10060
        self.assertEqual(scan_port("127.0.0.1", 23), PortStatus.FILTERED)

    @patch("socket.socket")
    @patch("socket.gethostbyname", return_value="127.0.0.1")
    def test_port_scanner_include_closed(self, mock_resolve, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_cls.return_value = mock_sock

        scanner = PortScanner(target="127.0.0.1")
        result = scanner.scan_port(80, include_closed=True)
        self.assertIsNotNone(result)
        self.assertEqual(result["state"], "CLOSED")

    @patch("socket.socket")
    def test_scan_port_handles_gaierror(self, mock_socket_cls):
        from core.scanner import scan_port
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.gaierror(11001, "getaddrinfo failed")
        mock_socket_cls.return_value = mock_sock

        self.assertFalse(scan_port("invalid.host", 80, timeout=0.5))
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_handles_socket_error(self, mock_socket_cls):
        from core.scanner import scan_port
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.error("Connection reset by peer")
        mock_socket_cls.return_value = mock_sock

        self.assertFalse(scan_port("127.0.0.1", 80, timeout=0.5))
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_scan_port_handles_keyboard_interrupt(self, mock_socket_cls):
        from core.scanner import scan_port
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = KeyboardInterrupt()
        mock_socket_cls.return_value = mock_sock

        # Must not raise KeyboardInterrupt or crash
        self.assertFalse(scan_port("127.0.0.1", 80, timeout=0.5))
        mock_sock.close.assert_called_once()


class TestLogger(unittest.TestCase):
    """Tests for utils/logger.py."""

    def test_logger_file_and_console(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_log_file = os.path.join(tmp_dir, "test_scanner.log")
            from utils.logger import setup_logger
            test_logger = setup_logger(name="TestNetPulse", log_file=test_log_file)
            test_logger.info("Informational message")
            test_logger.error("Critical connection failure")

            # Close handlers on Windows so the temp file can be cleaned up
            for handler in test_logger.handlers[:]:
                handler.close()
                test_logger.removeHandler(handler)

            self.assertTrue(os.path.exists(test_log_file))
            with open(test_log_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Critical connection failure", content)
            self.assertNotIn("Informational message", content)


class TestCLI(unittest.TestCase):
    """Tests for utils/cli.py."""

    def test_cli_target_flag(self):
        from utils.cli import parse_arguments
        args = parse_arguments(["-t", "192.168.1.1", "-p", "80,443"])
        self.assertEqual(args.target, "192.168.1.1")
        self.assertEqual(args.ports, "80,443")

    def test_cli_target_long_flag(self):
        from utils.cli import parse_arguments
        args = parse_arguments(["--target", "scanme.nmap.org", "--common"])
        self.assertEqual(args.target, "scanme.nmap.org")
        self.assertTrue(args.common)

    def test_cli_missing_target_exits(self):
        from utils.cli import parse_arguments
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr"):
                parse_arguments([])
        self.assertEqual(cm.exception.code, 2)

    def test_parse_ports_single(self):
        from utils.cli import parse_ports
        self.assertEqual(parse_ports("80"), [80])

    def test_parse_ports_comma_separated(self):
        from utils.cli import parse_ports
        self.assertEqual(parse_ports("80,443"), [80, 443])

    def test_parse_ports_range(self):
        from utils.cli import parse_ports
        ports = parse_ports("1-1000")
        self.assertEqual(len(ports), 1000)
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 1000)

    def test_parse_ports_combined_with_whitespace(self):
        from utils.cli import parse_ports
        self.assertEqual(parse_ports(" 22, 80 , 100-102 "), [22, 80, 100, 101, 102])

    def test_cli_ports_list_parsing(self):
        from utils.cli import parse_arguments
        args = parse_arguments(["-t", "127.0.0.1", "-p", "1-1000"])
        self.assertEqual(len(args.ports_list), 1000)
        self.assertEqual(args.ports_list[0], 1)
        self.assertEqual(args.ports_list[-1], 1000)

    def test_cli_timeout_argument(self):
        from utils.cli import parse_arguments
        args = parse_arguments(["-t", "127.0.0.1", "--timeout", "3.2"])
        self.assertAlmostEqual(args.timeout, 3.2)

    def test_cli_negative_timeout_exits(self):
        from utils.cli import parse_arguments
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr"):
                parse_arguments(["-t", "127.0.0.1", "--timeout", "-1.0"])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_pn_flag(self):
        from utils.cli import parse_arguments
        args_short = parse_arguments(["-t", "127.0.0.1", "-Pn"])
        self.assertTrue(args_short.Pn)

        args_long = parse_arguments(["-t", "127.0.0.1", "--Pn"])
        self.assertTrue(args_long.Pn)

        args_default = parse_arguments(["-t", "127.0.0.1"])
        self.assertFalse(args_default.Pn)

    def test_cli_top_ports_flag(self):
        from utils.cli import parse_arguments
        from utils.config import TOP_100_PORTS, TOP_100_PORTS_LIST

        self.assertEqual(len(TOP_100_PORTS), 100)
        self.assertEqual(len(TOP_100_PORTS_LIST), 100)

        args = parse_arguments(["-t", "127.0.0.1", "--top-ports"])
        self.assertTrue(args.top_ports)
        self.assertEqual(len(args.ports_list), 100)
        self.assertIn(80, args.ports_list)
        self.assertIn(443, args.ports_list)
        self.assertIn(22, args.ports_list)


class TestValidators(unittest.TestCase):
    """Tests for utils/validators.py using ipaddress module."""

    def test_valid_ipv4(self):
        from utils.validators import is_valid_ipv4
        self.assertTrue(is_valid_ipv4("127.0.0.1"))
        self.assertTrue(is_valid_ipv4("192.168.1.254"))
        self.assertTrue(is_valid_ipv4("10.0.0.1"))
        self.assertTrue(is_valid_ipv4(" 8.8.8.8 "))

    def test_invalid_ipv4(self):
        from utils.validators import is_valid_ipv4
        self.assertFalse(is_valid_ipv4("256.1.1.1"))
        self.assertFalse(is_valid_ipv4("192.168.1"))
        self.assertFalse(is_valid_ipv4("example.com"))
        self.assertFalse(is_valid_ipv4("::1"))
        self.assertFalse(is_valid_ipv4(""))
        self.assertFalse(is_valid_ipv4(None))

    @patch("socket.gethostbyname", return_value="93.184.216.34")
    def test_resolve_domain_success(self, mock_dns):
        from utils.validators import resolve_domain, resolve_domain_to_ipv4
        self.assertEqual(resolve_domain("example.com"), "93.184.216.34")
        self.assertEqual(resolve_domain("https://example.com/"), "93.184.216.34")
        self.assertEqual(resolve_domain_to_ipv4("example.com"), "93.184.216.34")

    @patch("socket.gethostbyname", side_effect=socket.gaierror(11001, "getaddrinfo failed"))
    def test_resolve_nonexistent_domain(self, mock_dns):
        from utils.validators import resolve_domain, resolve_domain_to_ipv4
        # Graceful return None
        self.assertIsNone(resolve_domain("this-domain-definitely-does-not-exist.test"))
        # Descriptive ValueError
        with self.assertRaises(ValueError) as ctx:
            resolve_domain_to_ipv4("this-domain-definitely-does-not-exist.test")
        self.assertIn("Domain does not exist", str(ctx.exception))

    def test_resolve_empty_domain(self):
        from utils.validators import resolve_domain, resolve_domain_to_ipv4
        self.assertIsNone(resolve_domain(""))
        with self.assertRaises(ValueError):
            resolve_domain_to_ipv4("")


class TestSignalHandler(unittest.TestCase):
    """Tests for signal_handler in main.py."""

    def test_signal_handler_prints_partial_and_exits(self):
        import signal
        from main import scan_context, signal_handler

        scan_context["start_timestamp"] = 100.0
        scan_context["start_time_str"] = "1970-01-01 00:01:40"
        scan_context["scanned_count"] = 5
        scan_context["total_ports"] = 100
        scan_context["target"] = "localhost"
        scan_context["target_ip"] = "127.0.0.1"
        scan_context["open_ports"] = [
            {"port": 80, "state": "OPEN", "service": "HTTP"}
        ]
        scan_context["interrupted"] = False

        with self.assertRaises(SystemExit) as cm:
            signal_handler(signal.SIGINT, None)

        self.assertEqual(cm.exception.code, 130)
        self.assertTrue(scan_context["interrupted"])


class TestHostDiscovery(unittest.TestCase):
    """Tests for core/host_discovery.py."""

    @patch("subprocess.run")
    def test_icmp_ping_success(self, mock_run):
        from core.host_discovery import icmp_ping
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(icmp_ping("127.0.0.1", timeout=1.0))

    @patch("subprocess.run")
    def test_icmp_ping_failure(self, mock_run):
        from core.host_discovery import icmp_ping
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(icmp_ping("192.0.2.1", timeout=1.0))

    @patch("socket.socket")
    def test_tcp_ping_success(self, mock_sock_cls):
        from core.host_discovery import tcp_ping
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock_cls.return_value = mock_sock
        self.assertTrue(tcp_ping("127.0.0.1", port=80, timeout=1.0))

    @patch("socket.socket")
    def test_tcp_ping_failure(self, mock_sock_cls):
        from core.host_discovery import tcp_ping
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 10060  # WSAETIMEDOUT
        mock_sock_cls.return_value = mock_sock
        self.assertFalse(tcp_ping("192.0.2.1", port=80, timeout=1.0))

    @patch("core.host_discovery.icmp_ping", return_value=True)
    def test_is_host_online_via_icmp(self, mock_icmp):
        from core.host_discovery import is_host_online
        self.assertTrue(is_host_online("127.0.0.1"))

    @patch("core.host_discovery.icmp_ping", return_value=False)
    @patch("core.host_discovery.tcp_ping", side_effect=lambda t, port, timeout: port == 443)
    def test_is_host_online_via_tcp_fallback(self, mock_icmp, mock_tcp):
        from core.host_discovery import is_host_online
        self.assertTrue(is_host_online("192.168.1.1", fallback_ports=[80, 443]))

    @patch("core.host_discovery.icmp_ping", return_value=False)
    @patch("core.host_discovery.tcp_ping", return_value=False)
    def test_is_host_online_offline(self, mock_icmp, mock_tcp):
        from core.host_discovery import is_host_online
        self.assertFalse(is_host_online("192.0.2.1", fallback_ports=[80]))


if __name__ == "__main__":
    unittest.main()
