"""Unit tests for NetPulse core logic and helper utilities."""

import os
import socket
import ssl
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
    def test_scan_ports_concurrent(self, mock_socket_cls):
        from core.scanner import scan_ports_concurrent
        mock_sock = MagicMock()
        # Ports 80 and 443 open, 8080 closed
        mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] in (80, 443) else 111
        mock_socket_cls.return_value = mock_sock

        discovered = []
        results = scan_ports_concurrent(
            ip="127.0.0.1",
            ports=[80, 443, 8080],
            timeout=0.5,
            max_workers=5,
            on_port_scanned=lambda res: discovered.append(res["port"]),
        )
        self.assertEqual(len(results), 2)
        self.assertEqual([r["port"] for r in results], [80, 443])
        self.assertEqual(sorted(discovered), [80, 443])

    @patch("socket.socket")
    def test_concurrent_append_thread_safety(self, mock_socket_cls):
        from core.scanner import scan_ports_concurrent
        mock_sock = MagicMock()
        # All 50 ports open
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        ports = list(range(1000, 1050))
        results = scan_ports_concurrent(
            ip="127.0.0.1",
            ports=ports,
            timeout=0.1,
            max_workers=20,
        )
        # All 50 ports should be appended safely without omission or race condition
        self.assertEqual(len(results), 50)
        self.assertEqual([r["port"] for r in results], ports)

    def test_create_port_queue(self):
        from core.scanner import create_port_queue
        ports = [21, 22, 80, 443]
        q = create_port_queue(ports)
        self.assertEqual(q.qsize(), 4)
        extracted = []
        while not q.empty():
            extracted.append(q.get_nowait())
        self.assertEqual(extracted, ports)

    @patch("time.sleep")
    @patch("socket.socket")
    def test_scan_ports_concurrent_rate_limiting(self, mock_socket_cls, mock_sleep):
        from core.scanner import scan_ports_concurrent
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        results = scan_ports_concurrent(
            ip="127.0.0.1",
            ports=[80, 443],
            timeout=0.1,
            max_workers=1,
            rate_limit_ms=50.0,
        )
        self.assertEqual(len(results), 2)
        # Verify time.sleep was called with 50ms (0.05 seconds)
        mock_sleep.assert_called_with(0.05)

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

    def test_cli_threads_arguments(self):
        from utils.cli import parse_arguments
        # Test -T
        args_short = parse_arguments(["-t", "127.0.0.1", "-T", "50"])
        self.assertEqual(args_short.threads, 50)
        self.assertEqual(args_short.workers, 50)

        # Test --threads
        args_long = parse_arguments(["-t", "127.0.0.1", "--threads", "200"])
        self.assertEqual(args_long.threads, 200)
        self.assertEqual(args_long.workers, 200)

        # Test default
        args_default = parse_arguments(["-t", "127.0.0.1"])
        self.assertEqual(args_default.threads, 100)

        # Test invalid threads (< 1)
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr"):
                parse_arguments(["-t", "127.0.0.1", "-T", "0"])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_rate_limit_argument(self):
        from utils.cli import parse_arguments
        args = parse_arguments(["-t", "127.0.0.1", "--rate-limit", "50.5"])
        self.assertAlmostEqual(args.rate_limit, 50.5)

        # Default should be 0.0
        args_default = parse_arguments(["-t", "127.0.0.1"])
        self.assertAlmostEqual(args_default.rate_limit, 0.0)

        # Negative rate-limit exits
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr"):
                parse_arguments(["-t", "127.0.0.1", "--rate-limit", "-10"])
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

    def test_cli_randomize_flag(self):
        from utils.cli import parse_arguments
        from utils.config import TOP_100_PORTS_LIST

        # Default should be False
        args_default = parse_arguments(["-t", "127.0.0.1", "-p", "1-10"])
        self.assertFalse(args_default.randomize)
        self.assertEqual(args_default.ports_list, list(range(1, 11)))

        # Test -r flag
        args_short = parse_arguments(["-t", "127.0.0.1", "-p", "1-10", "-r"])
        self.assertTrue(args_short.randomize)
        self.assertEqual(sorted(args_short.ports_list), list(range(1, 11)))

        # Test --randomize flag
        args_long = parse_arguments(["-t", "127.0.0.1", "-p", "1-100", "--randomize"])
        self.assertTrue(args_long.randomize)
        self.assertEqual(sorted(args_long.ports_list), list(range(1, 101)))
        # For 100 items, shuffled order is virtually guaranteed not to match sequential order
        self.assertNotEqual(args_long.ports_list, list(range(1, 101)))

        # Verify random.shuffle was called
        with patch("random.shuffle") as mock_shuffle:
            parse_arguments(["-t", "127.0.0.1", "-p", "80,443", "--randomize"])
            mock_shuffle.assert_called_once()

        # Verify that original TOP_100_PORTS_LIST is not mutated when randomized
        original_top_copy = list(TOP_100_PORTS_LIST)
        args_top_rand = parse_arguments(["-t", "127.0.0.1", "--top-ports", "--randomize"])
        self.assertEqual(TOP_100_PORTS_LIST, original_top_copy)
        self.assertEqual(sorted(args_top_rand.ports_list), sorted(original_top_copy))

    def test_cli_async_flag(self):
        from utils.cli import parse_arguments
        args_default = parse_arguments(["-t", "127.0.0.1"])
        self.assertFalse(args_default.use_async)

        args_async = parse_arguments(["-t", "127.0.0.1", "--async"])
        self.assertTrue(args_async.use_async)

    def test_read_targets_from_file(self):
        from utils.cli import read_targets_from_file

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
            tf.write("# Header comment\n")
            tf.write("192.168.1.1\n")
            tf.write("\n")
            tf.write("192.168.1.50 # Web Server\n")
            tf.write("example.com, scanme.nmap.org\n")
            tf.write("10.0.0.0/30\n")
            temp_path = tf.name

        try:
            targets = read_targets_from_file(temp_path)
            self.assertEqual(
                targets,
                ["192.168.1.1", "192.168.1.50", "example.com", "scanme.nmap.org", "10.0.0.0/30"],
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_read_targets_from_file_errors(self):
        from utils.cli import read_targets_from_file

        # Non-existent file
        with self.assertRaises(FileNotFoundError):
            read_targets_from_file("non_existent_targets_file_12345.txt")

        # Empty file / comments only
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
            tf.write("# Just comments\n\n   \n# More comments\n")
            empty_path = tf.name

        try:
            with self.assertRaises(ValueError):
                read_targets_from_file(empty_path)
        finally:
            if os.path.exists(empty_path):
                os.remove(empty_path)

    def test_cli_il_flag(self):
        from utils.cli import parse_arguments

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
            tf.write("127.0.0.1\n10.0.0.1\n")
            temp_path = tf.name

        try:
            args = parse_arguments(["-iL", temp_path, "-p", "80"])
            self.assertEqual(args.input_file, temp_path)
            self.assertEqual(args.targets_list, ["127.0.0.1", "10.0.0.1"])
            self.assertEqual(args.ports_list, [80])

            # Test invalid input file exits with code 2
            with self.assertRaises(SystemExit) as cm:
                with patch("sys.stderr"):
                    parse_arguments(["-iL", "definitely_does_not_exist_file.txt"])
            self.assertEqual(cm.exception.code, 2)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_cli_missing_target_and_il_exits(self):
        from utils.cli import parse_arguments
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr"):
                parse_arguments([])
        self.assertEqual(cm.exception.code, 2)

    def test_cli_exclude_ports(self):
        from utils.cli import parse_arguments

        # Test comma-separated exclusion
        args = parse_arguments(["-t", "127.0.0.1", "-p", "80-85", "--exclude-ports", "80,81,82"])
        self.assertEqual(args.ports_list, [83, 84, 85])
        self.assertEqual(args.excluded_ports_list, [80, 81, 82])

        # Test range exclusion
        args_range = parse_arguments(["-t", "127.0.0.1", "-p", "1-100", "--exclude-ports", "1-90"])
        self.assertEqual(args_range.ports_list, list(range(91, 101)))
        self.assertEqual(len(args_range.excluded_ports_list), 90)

        # Test exclusion from --top-ports
        args_top = parse_arguments(["-t", "127.0.0.1", "--top-ports", "--exclude-ports", "80,443"])
        self.assertNotIn(80, args_top.ports_list)
        self.assertNotIn(443, args_top.ports_list)
        self.assertEqual(len(args_top.ports_list), 98)

        # Test excluding all ports raises SystemExit 2
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr"):
                parse_arguments(["-t", "127.0.0.1", "-p", "80,443", "--exclude-ports", "80,443"])
        self.assertEqual(cm.exception.code, 2)

        # Test invalid exclusion port format raises SystemExit 2
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stderr"):
                parse_arguments(["-t", "127.0.0.1", "-p", "80-90", "--exclude-ports", "abc"])
        self.assertEqual(cm.exception.code, 2)


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

    def test_is_valid_cidr(self):
        from utils.validators import is_valid_cidr
        self.assertTrue(is_valid_cidr("192.168.1.0/24"))
        self.assertTrue(is_valid_cidr("10.0.0.0/16"))
        self.assertTrue(is_valid_cidr("172.16.1.5/30"))
        self.assertTrue(is_valid_cidr("192.168.1.1/32"))
        self.assertTrue(is_valid_cidr(" 192.168.1.0/24 "))

        self.assertFalse(is_valid_cidr("192.168.1.1"))
        self.assertFalse(is_valid_cidr("192.168.1.0/35"))
        self.assertFalse(is_valid_cidr("invalid/24"))
        self.assertFalse(is_valid_cidr("2001:db8::/32"))
        self.assertFalse(is_valid_cidr(""))
        self.assertFalse(is_valid_cidr(None))

    def test_parse_cidr(self):
        from utils.validators import parse_cidr
        # Test /30
        hosts_30 = parse_cidr("192.168.1.0/30")
        self.assertEqual(hosts_30, ["192.168.1.1", "192.168.1.2"])

        # Test /24
        hosts_24 = parse_cidr("192.168.1.0/24")
        self.assertEqual(len(hosts_24), 254)
        self.assertEqual(hosts_24[0], "192.168.1.1")
        self.assertEqual(hosts_24[-1], "192.168.1.254")

        # Test /32 host route
        hosts_32 = parse_cidr("10.0.0.1/32")
        self.assertEqual(hosts_32, ["10.0.0.1"])

        # Test invalid inputs
        with self.assertRaises(ValueError):
            parse_cidr("not-a-cidr")
        with self.assertRaises(ValueError):
            parse_cidr("192.168.1.0/35")
        with self.assertRaises(ValueError):
            parse_cidr("0.0.0.0/0")  # Prefix < 8 rejected

    def test_resolve_targets(self):
        from utils.validators import resolve_targets

        # Test CIDR
        cidr_targets = resolve_targets("192.168.1.0/30")
        self.assertEqual(
            cidr_targets,
            [("192.168.1.1", "192.168.1.1"), ("192.168.1.2", "192.168.1.2")],
        )

        # Test single IP
        single_ip = resolve_targets("127.0.0.1")
        self.assertEqual(single_ip, [("127.0.0.1", "127.0.0.1")])

        # Test invalid target
        with self.assertRaises(ValueError):
            resolve_targets("this-target-does-not-exist.invalid-domain-test")


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


class TestAsyncScanner(unittest.IsolatedAsyncioTestCase):
    """Unit tests for core/async_scanner.py using asyncio."""

    @patch("asyncio.open_connection")
    async def test_async_scan_port_open(self, mock_connect):
        from core.async_scanner import PortStatus, async_scan_port
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = MagicMock()
        # In asyncio, wait_closed can be an async mock or coroutine
        async def fake_wait_closed():
            return None
        mock_writer.wait_closed.side_effect = fake_wait_closed

        mock_connect.return_value = (mock_reader, mock_writer)

        status = await async_scan_port("127.0.0.1", 80, timeout=1.0)
        self.assertEqual(status, PortStatus.OPEN)
        self.assertTrue(status)
        mock_writer.close.assert_called_once()

    @patch("asyncio.open_connection", side_effect=ConnectionRefusedError("Connection refused"))
    async def test_async_scan_port_closed(self, mock_connect):
        from core.async_scanner import PortStatus, async_scan_port
        status = await async_scan_port("127.0.0.1", 81, timeout=1.0)
        self.assertEqual(status, PortStatus.CLOSED)
        self.assertFalse(status)

    @patch("asyncio.open_connection", side_effect=TimeoutError("Timed out"))
    async def test_async_scan_port_filtered(self, mock_connect):
        from core.async_scanner import PortStatus, async_scan_port
        status = await async_scan_port("127.0.0.1", 443, timeout=1.0)
        self.assertEqual(status, PortStatus.FILTERED)
        self.assertFalse(status)

    @patch("asyncio.open_connection")
    async def test_async_grab_banner(self, mock_connect):
        from core.async_scanner import async_grab_banner
        mock_reader = MagicMock()
        async def fake_read(n):
            return b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_reader.read.side_effect = fake_read

        mock_writer = MagicMock()
        async def fake_drain():
            return None
        mock_writer.drain.side_effect = fake_drain
        async def fake_wait_closed():
            return None
        mock_writer.wait_closed.side_effect = fake_wait_closed

        mock_connect.return_value = (mock_reader, mock_writer)

        banner = await async_grab_banner("127.0.0.1", 22, timeout=1.0)
        self.assertEqual(banner, "SSH-2.0-OpenSSH_8.9")

    @patch("asyncio.open_connection")
    async def test_scan_ports_async(self, mock_connect):
        from core.async_scanner import scan_ports_async

        async def fake_open_connection(host, port):
            if port == 80:
                mock_reader = MagicMock()
                mock_writer = MagicMock()
                async def fake_drain():
                    return None
                mock_writer.drain.side_effect = fake_drain
                async def fake_wait_closed():
                    return None
                mock_writer.wait_closed.side_effect = fake_wait_closed
                return (mock_reader, mock_writer)
            elif port == 22:
                raise ConnectionRefusedError("Refused")
            else:
                raise TimeoutError("Timed out")

        mock_connect.side_effect = fake_open_connection

        discovered = []
        def on_scanned(record):
            discovered.append(record)

        results = await scan_ports_async(
            ip="127.0.0.1",
            ports=[80, 22, 443],
            timeout=1.0,
            concurrency=10,
            include_closed=True,
            on_port_scanned=on_scanned,
        )

        self.assertEqual(len(results), 3)
        self.assertEqual([r["port"] for r in results], [22, 80, 443])
        self.assertEqual(results[0]["state"], "CLOSED")
        self.assertEqual(results[1]["state"], "OPEN")
        self.assertEqual(results[1]["service"], "HTTP")
        self.assertEqual(results[2]["state"], "FILTERED")
        self.assertEqual(len(discovered), 3)

    @patch("asyncio.open_connection")
    def test_run_async_scan_synchronous(self, mock_connect):
        from core.async_scanner import run_async_scan
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        async def fake_drain():
            return None
        mock_writer.drain.side_effect = fake_drain
        async def fake_wait_closed():
            return None
        mock_writer.wait_closed.side_effect = fake_wait_closed
        mock_connect.return_value = (mock_reader, mock_writer)

        results = run_async_scan(
            ip="127.0.0.1",
            ports=[80],
            timeout=1.0,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["port"], 80)
        self.assertEqual(results[0]["state"], "OPEN")

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    @patch("asyncio.open_connection")
    def test_async_port_scanner_class(self, mock_connect, mock_dns):
        from core.async_scanner import AsyncPortScanner
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        async def fake_drain():
            return None
        mock_writer.drain.side_effect = fake_drain
        async def fake_wait_closed():
            return None
        mock_writer.wait_closed.side_effect = fake_wait_closed
        mock_connect.return_value = (mock_reader, mock_writer)

        scanner = AsyncPortScanner(target="localhost", timeout=1.0)
        self.assertEqual(scanner.target_ip, "127.0.0.1")

        results = scanner.scan_ports([80])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["port"], 80)


class TestServiceDetector(unittest.TestCase):
    """Unit tests for core/service_detector.py."""

    def test_get_iana_service_name_standard_ports(self):
        from core.service_detector import get_iana_service_name
        self.assertEqual(get_iana_service_name(80), "http")
        self.assertEqual(get_iana_service_name(22), "ssh")
        self.assertEqual(get_iana_service_name(443), "https")
        self.assertEqual(get_iana_service_name(21), "ftp")

    def test_get_iana_service_name_unregistered_and_invalid(self):
        from core.service_detector import get_iana_service_name
        self.assertIsNone(get_iana_service_name(54321))
        self.assertIsNone(get_iana_service_name(0))
        self.assertIsNone(get_iana_service_name(70000))
        self.assertIsNone(get_iana_service_name("80"))  # Non-int
        self.assertIsNone(get_iana_service_name(None))

    def test_get_service_name_with_fallback(self):
        from core.service_detector import get_service_name
        # Standard port resolves via IANA
        self.assertEqual(get_service_name(80), "http")
        self.assertEqual(get_service_name(22), "ssh")

        # Unknown port falls back to 'unknown' or custom default
        self.assertEqual(get_service_name(54321, fallback_to_common=False), "unknown")
        self.assertEqual(get_service_name(54321, default="unassigned", fallback_to_common=False), "unassigned")

    def test_detect_service(self):
        from core.service_detector import detect_service
        self.assertEqual(detect_service(80), "http")
        self.assertEqual(detect_service(22), "ssh")
        self.assertEqual(detect_service(443), "https")

    def test_map_ports_to_services(self):
        from core.service_detector import map_ports_to_services
        mapped = map_ports_to_services([80, 22, 443])
        self.assertEqual(mapped[80], "http")
        self.assertEqual(mapped[22], "ssh")
        self.assertEqual(mapped[443], "https")

    def test_service_detector_class(self):
        from core.service_detector import ServiceDetector
        detector = ServiceDetector()
        self.assertEqual(detector.get_service(80), "http")
        self.assertEqual(detector.get_service(22), "ssh")
        self.assertEqual(detector.get_iana_service(80), "http")
        self.assertIsNone(detector.get_iana_service(54321))

        batch = detector.map_ports([80, 22])
        self.assertEqual(batch, {80: "http", 22: "ssh"})

    @patch("socket.getservbyport", side_effect=OSError("port/proto not found"))
    def test_getservbyport_exception_handling(self, mock_getserv):
        from core.service_detector import get_iana_service_name, get_service_name
        get_iana_service_name.cache_clear()
        try:
            self.assertIsNone(get_iana_service_name(80))
            # With fallback_to_common=False, should return 'unknown'
            self.assertEqual(get_service_name(80, fallback_to_common=False), "unknown")
        finally:
            get_iana_service_name.cache_clear()

    @patch("socket.socket")
    def test_grab_banner_success(self, mock_socket_cls):
        from core.service_detector import grab_banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
        mock_socket_cls.return_value = mock_sock

        banner = grab_banner("127.0.0.1", 22, timeout=1.0)
        self.assertEqual(banner, "OpenSSH 8.9p1 (Ubuntu)")
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 22))
        mock_sock.sendall.assert_called_once_with(b"\r\n")
        mock_sock.recv.assert_called_once_with(1024)
        mock_sock.close.assert_called_once()

    def test_parse_ssh_banner_os_families(self):
        from core.service_detector import format_ssh_banner, parse_ssh_banner

        # Ubuntu
        u_info = parse_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        self.assertIsNotNone(u_info)
        self.assertEqual(u_info["openssh_version"], "8.9p1")
        self.assertEqual(u_info["os_family"], "Ubuntu")
        self.assertEqual(u_info["highlighted"], "OpenSSH 8.9p1 (Ubuntu)")
        self.assertEqual(format_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"), "OpenSSH 8.9p1 (Ubuntu)")

        # Debian
        d_info = parse_ssh_banner("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1")
        self.assertIsNotNone(d_info)
        self.assertEqual(d_info["openssh_version"], "8.4p1")
        self.assertEqual(d_info["os_family"], "Debian")
        self.assertEqual(d_info["highlighted"], "OpenSSH 8.4p1 (Debian)")

        # FreeBSD
        f_info = parse_ssh_banner("SSH-2.0-OpenSSH_9.3p1 FreeBSD-20230719")
        self.assertIsNotNone(f_info)
        self.assertEqual(f_info["openssh_version"], "9.3p1")
        self.assertEqual(f_info["os_family"], "FreeBSD")
        self.assertEqual(f_info["highlighted"], "OpenSSH 9.3p1 (FreeBSD)")

        # CentOS / Red Hat
        r_info = parse_ssh_banner("SSH-2.0-OpenSSH_8.0 (Red Hat Enterprise Linux 8)")
        self.assertIsNotNone(r_info)
        self.assertEqual(r_info["openssh_version"], "8.0")
        self.assertEqual(r_info["os_family"], "Red Hat")
        self.assertEqual(r_info["highlighted"], "OpenSSH 8.0 (Red Hat)")

        # No OS family
        generic = parse_ssh_banner("SSH-2.0-OpenSSH_7.4p1-hpn14v12")
        self.assertIsNotNone(generic)
        self.assertEqual(generic["openssh_version"], "7.4p1")
        self.assertIsNone(generic["os_family"])
        self.assertEqual(generic["highlighted"], "OpenSSH 7.4p1")

        # Invalid or non-SSH banners
        self.assertIsNone(parse_ssh_banner("HTTP/1.1 200 OK"))
        self.assertIsNone(parse_ssh_banner(""))
        self.assertIsNone(parse_ssh_banner(None))

    @patch("socket.socket")
    def test_grab_ssh_info(self, mock_socket_cls):
        from core.service_detector import grab_ssh_info
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
        mock_socket_cls.return_value = mock_sock

        info = grab_ssh_info("127.0.0.1", 22, timeout=1.0)
        self.assertIsNotNone(info)
        self.assertEqual(info["openssh_version"], "8.9p1")
        self.assertEqual(info["os_family"], "Ubuntu")
        self.assertEqual(info["highlighted"], "OpenSSH 8.9p1 (Ubuntu)")

    @patch("socket.socket")
    def test_grab_banner_empty_response(self, mock_socket_cls):
        from core.service_detector import grab_banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        mock_socket_cls.return_value = mock_sock

        banner = grab_banner("127.0.0.1", 21, timeout=1.0)
        self.assertEqual(banner, "")
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_grab_banner_timeout_exception(self, mock_socket_cls):
        from core.service_detector import grab_banner
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("Timed out")
        mock_socket_cls.return_value = mock_sock

        banner = grab_banner("127.0.0.1", 22, timeout=1.0)
        self.assertEqual(banner, "")
        mock_sock.close.assert_called_once()

    @patch("core.service_detector.grab_banner", return_value="HTTP/1.1 200 OK")
    def test_service_detector_grab_banner_delegation(self, mock_gb):
        from core.service_detector import ServiceDetector
        detector = ServiceDetector()
        res = detector.grab_banner("127.0.0.1", 80)
        self.assertEqual(res, "HTTP/1.1 200 OK")
        mock_gb.assert_called_once_with("127.0.0.1", 80, timeout=1.5)

    def test_extract_http_headers(self):
        from core.service_detector import extract_http_headers

        sample_resp = (
            "HTTP/1.1 200 OK\r\n"
            "Date: Mon, 16 Nov 2026 08:00:00 GMT\r\n"
            "Server: Apache/2.4.52 (Ubuntu)\r\n"
            "X-Powered-By: PHP/8.1.2\r\n"
            "Content-Type: text/html\r\n\r\n"
        )
        headers = extract_http_headers(sample_resp)
        self.assertEqual(headers["Server"], "Apache/2.4.52 (Ubuntu)")
        self.assertEqual(headers["X-Powered-By"], "PHP/8.1.2")
        self.assertEqual(headers["server"], "Apache/2.4.52 (Ubuntu)")

        # Empty response
        self.assertEqual(extract_http_headers(""), {})
        self.assertEqual(extract_http_headers(None), {})

    @patch("socket.socket")
    def test_grab_http_headers_port_80(self, mock_socket_cls):
        from core.service_detector import grab_http_headers
        mock_sock = MagicMock()
        mock_sock.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.18.0\r\n"
            b"X-Powered-By: Express\r\n\r\n"
        )
        mock_socket_cls.return_value = mock_sock

        headers = grab_http_headers("127.0.0.1", 80, timeout=1.0)
        self.assertEqual(headers, {"Server": "nginx/1.18.0", "X-Powered-By": "Express"})
        # Verify HEAD request was sent
        sent_data = mock_sock.sendall.call_args[0][0]
        self.assertTrue(sent_data.startswith(b"HEAD / HTTP/1.1\r\n"))

    @patch("ssl.create_default_context")
    @patch("socket.socket")
    def test_grab_http_headers_port_443_ssl(self, mock_socket_cls, mock_ssl_ctx):
        from core.service_detector import grab_http_headers
        mock_raw_sock = MagicMock()
        mock_socket_cls.return_value = mock_raw_sock

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Cloudflare\r\n\r\n"
        )
        mock_ctx_instance = MagicMock()
        mock_ctx_instance.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_ctx.return_value = mock_ctx_instance

        headers = grab_http_headers("127.0.0.1", 443, timeout=1.0)
        self.assertEqual(headers, {"Server": "Cloudflare"})
        self.assertNotIn("X-Powered-By", headers)
        mock_ctx_instance.wrap_socket.assert_called_once()

    @patch("core.service_detector.grab_http_headers")
    def test_grab_banner_http_ports(self, mock_http_headers):
        from core.service_detector import grab_banner
        mock_http_headers.return_value = {
            "Server": "nginx/1.22.0",
            "X-Powered-By": "Next.js",
        }

        # Port 80
        banner_80 = grab_banner("127.0.0.1", 80)
        self.assertEqual(banner_80, "Server: nginx/1.22.0 | X-Powered-By: Next.js")

        # Port 8080
        banner_8080 = grab_banner("127.0.0.1", 8080)
        self.assertEqual(banner_8080, "Server: nginx/1.22.0 | X-Powered-By: Next.js")

        # Only Server header present
        mock_http_headers.return_value = {"Server": "Apache"}
        banner_server_only = grab_banner("127.0.0.1", 80)
        self.assertEqual(banner_server_only, "Server: Apache")


class TestSSLInspector(unittest.TestCase):
    """Unit tests for core/ssl_inspector.py."""

    def test_parse_certificate_dict(self):
        from core.ssl_inspector import parse_certificate_dict

        raw_cert = {
            "subject": ((("commonName", "scanme.nmap.org"),),),
            "issuer": (
                (("countryName", "US"),),
                (("organizationName", "Let's Encrypt"),),
                (("commonName", "R3"),),
            ),
            "notBefore": "Nov 16 00:00:00 2026 GMT",
            "notAfter": "Feb 16 23:59:59 2027 GMT",
            "serialNumber": "04A1B2C3D4",
            "subjectAltName": (("DNS", "scanme.nmap.org"), ("DNS", "nmap.org")),
        }

        parsed = parse_certificate_dict(raw_cert)
        self.assertEqual(parsed["common_name"], "scanme.nmap.org")
        self.assertEqual(parsed["issuer"], "R3")
        self.assertEqual(parsed["expiration_date"], "Feb 16 23:59:59 2027 GMT")
        self.assertEqual(parsed["subject_alt_names"], ["scanme.nmap.org", "nmap.org"])
        self.assertFalse(parsed["is_expired"])
        self.assertIsNotNone(parsed["days_left"])

    def test_parse_certificate_dict_empty(self):
        from core.ssl_inspector import parse_certificate_dict
        parsed = parse_certificate_dict({})
        self.assertEqual(parsed["common_name"], "")
        self.assertEqual(parsed["issuer"], "")
        self.assertEqual(parsed["expiration_date"], "")

    @patch("ssl._ssl._test_decode_cert")
    @patch("ssl.DER_cert_to_PEM_cert")
    @patch("ssl.create_default_context")
    @patch("socket.socket")
    def test_inspect_ssl_success(
        self, mock_socket_cls, mock_ssl_ctx, mock_der_to_pem, mock_decode
    ):
        from core.ssl_inspector import inspect_ssl

        mock_raw_sock = MagicMock()
        mock_socket_cls.return_value = mock_raw_sock

        mock_ssl_sock = MagicMock()
        mock_ssl_sock.version.return_value = "TLSv1.3"
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.getpeercert.return_value = b"\x30\x82\x01..."

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_ctx.return_value = mock_ctx

        mock_der_to_pem.return_value = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
        mock_decode.return_value = {
            "subject": ((("commonName", "secure.example.com"),),),
            "issuer": ((("organizationName", "DigiCert Inc"),), (("commonName", "DigiCert TLS RSA SHA256"),)),
            "notAfter": "May 20 12:00:00 2027 GMT",
        }

        res = inspect_ssl("127.0.0.1", 443, timeout=1.0)
        self.assertIsNotNone(res)
        self.assertTrue(res["has_ssl"])
        self.assertEqual(res["common_name"], "secure.example.com")
        self.assertEqual(res["issuer"], "DigiCert TLS RSA SHA256")
        self.assertEqual(res["expiration_date"], "May 20 12:00:00 2027 GMT")
        self.assertEqual(res["tls_version"], "TLSv1.3")
        self.assertEqual(res["cipher"], "TLS_AES_256_GCM_SHA384")

    @patch("ssl.create_default_context")
    @patch("socket.socket")
    def test_inspect_ssl_non_ssl_port(self, mock_socket_cls, mock_ssl_ctx):
        from core.ssl_inspector import inspect_ssl

        mock_raw_sock = MagicMock()
        mock_socket_cls.return_value = mock_raw_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = ssl.SSLError("UNEXPECTED_EOF_WHILE_READING")
        mock_ssl_ctx.return_value = mock_ctx

        res = inspect_ssl("127.0.0.1", 80, timeout=1.0)
        self.assertIsNone(res)

    @patch("socket.socket")
    def test_inspect_ssl_connection_timeout(self, mock_socket_cls):
        from core.ssl_inspector import inspect_ssl
        mock_raw_sock = MagicMock()
        mock_raw_sock.connect.side_effect = socket.timeout("Timed out")
        mock_socket_cls.return_value = mock_raw_sock

        res = inspect_ssl("192.0.2.1", 443, timeout=1.0)
        self.assertIsNone(res)

    @patch("core.ssl_inspector.inspect_ssl")
    def test_get_ssl_certificate(self, mock_inspect):
        from core.ssl_inspector import get_ssl_certificate
        mock_inspect.return_value = {
            "common_name": "api.example.com",
            "issuer": "Let's Encrypt",
            "expiration_date": "Dec 31 23:59:59 2026 GMT",
            "has_ssl": True,
        }

        cert = get_ssl_certificate("127.0.0.1", 443)
        self.assertEqual(
            cert,
            {
                "common_name": "api.example.com",
                "issuer": "Let's Encrypt",
                "expiration_date": "Dec 31 23:59:59 2026 GMT",
            },
        )

        mock_inspect.return_value = None
        self.assertIsNone(get_ssl_certificate("127.0.0.1", 80))

    @patch("core.ssl_inspector.inspect_ssl")
    def test_is_ssl_port(self, mock_inspect):
        from core.ssl_inspector import is_ssl_port
        mock_inspect.return_value = {"has_ssl": True}
        self.assertTrue(is_ssl_port("127.0.0.1", 443))

        mock_inspect.return_value = None
        self.assertFalse(is_ssl_port("127.0.0.1", 80))

    @patch("core.ssl_inspector.inspect_ssl")
    def test_ssl_inspector_class(self, mock_inspect):
        from core.ssl_inspector import SSLInspector
        mock_inspect.return_value = {
            "common_name": "portal.example.com",
            "issuer": "DigiCert",
            "expiration_date": "Jan 01 00:00:00 2027 GMT",
            "has_ssl": True,
        }

        inspector = SSLInspector(timeout=2.5)
        self.assertEqual(inspector.timeout, 2.5)

        inspected = inspector.inspect("127.0.0.1", 443)
        self.assertEqual(inspected["common_name"], "portal.example.com")

        cert = inspector.get_certificate("127.0.0.1", 443)
        self.assertEqual(cert["common_name"], "portal.example.com")

        self.assertTrue(inspector.is_ssl("127.0.0.1", 443))


class TestVulnChecks(unittest.TestCase):
    """Tests for core/vuln_checks.py FTP anonymous login and vulnerability audits."""

    @patch("core.vuln_checks.ftplib.FTP")
    def test_check_ftp_anonymous_allowed(self, mock_ftp_cls):
        from core.vuln_checks import check_ftp_anonymous
        mock_ftp = MagicMock()
        mock_ftp.getwelcome.return_value = "220 ProFTPD Server ready."
        mock_ftp.login.return_value = "230 Anonymous user logged in."
        mock_ftp_cls.return_value = mock_ftp

        res = check_ftp_anonymous("192.168.1.50", port=21, timeout=2.0)
        self.assertTrue(res["vulnerable"])
        self.assertTrue(res["allowed"])
        self.assertEqual(res["port"], 21)
        self.assertEqual(res["service"], "FTP")
        self.assertEqual(res["vuln_id"], "FTP-ANON-LOGIN")
        self.assertEqual(res["banner"], "220 ProFTPD Server ready.")
        self.assertIn("230", res["response"])
        self.assertEqual(res["flag"], "[!] VULN: FTP Anonymous Login Allowed")
        mock_ftp.connect.assert_called_once_with("192.168.1.50", 21, timeout=2.0)
        mock_ftp.login.assert_called_once_with("anonymous", "anonymous@")
        mock_ftp.quit.assert_called_once()

    @patch("core.vuln_checks.ftplib.FTP")
    def test_check_ftp_anonymous_permission_denied(self, mock_ftp_cls):
        import ftplib
        from core.vuln_checks import check_ftp_anonymous
        mock_ftp = MagicMock()
        mock_ftp.getwelcome.return_value = "220 vsftpd 3.0.3"
        mock_ftp.login.side_effect = ftplib.error_perm("530 Permission denied.")
        mock_ftp_cls.return_value = mock_ftp

        res = check_ftp_anonymous("192.168.1.50", port=21, timeout=1.5)
        self.assertFalse(res["vulnerable"])
        self.assertFalse(res["allowed"])
        self.assertEqual(res["port"], 21)
        self.assertIsNone(res["flag"])
        self.assertIn("530 Permission denied.", res["response"])
        mock_ftp.close.assert_called_once()

    @patch("core.vuln_checks.ftplib.FTP")
    def test_check_ftp_anonymous_timeout_error(self, mock_ftp_cls):
        from core.vuln_checks import check_ftp_anonymous
        mock_ftp = MagicMock()
        mock_ftp.connect.side_effect = socket.timeout("timed out")
        mock_ftp_cls.return_value = mock_ftp

        res = check_ftp_anonymous("10.0.0.1", port=21, timeout=1.0)
        self.assertFalse(res["vulnerable"])
        self.assertFalse(res["allowed"])
        self.assertEqual(res["port"], 21)
        self.assertIsNone(res["flag"])
        self.assertIn("timed out", res["response"])

    @patch("core.vuln_checks.check_ftp_anonymous")
    def test_run_port_vulnerability_checks(self, mock_ftp_check):
        from core.vuln_checks import run_port_vulnerability_checks

        mock_ftp_check.return_value = {
            "vulnerable": True,
            "port": 21,
            "title": "FTP Anonymous Login Allowed",
            "flag": "[!] VULN: FTP Anonymous Login Allowed",
        }
        findings = run_port_vulnerability_checks("127.0.0.1", 21, timeout=1.5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "FTP Anonymous Login Allowed")

        mock_ftp_check.return_value = {"vulnerable": False}
        findings_safe = run_port_vulnerability_checks("127.0.0.1", 21, timeout=1.5)
        self.assertEqual(findings_safe, [])

        # Non-port 21 should return empty list
        non_ftp_findings = run_port_vulnerability_checks("127.0.0.1", 80, timeout=1.5)
        self.assertEqual(non_ftp_findings, [])

    @patch("core.vuln_checks.check_ftp_anonymous")
    def test_vulnerability_checker_class(self, mock_ftp_check):
        from core.vuln_checks import VulnerabilityChecker
        mock_ftp_check.return_value = {
            "vulnerable": True,
            "port": 21,
            "title": "FTP Anonymous Login Allowed",
            "flag": "[!] VULN: FTP Anonymous Login Allowed",
        }
        checker = VulnerabilityChecker(timeout=3.0)
        self.assertEqual(checker.timeout, 3.0)

        res = checker.check_ftp_anonymous("10.0.0.2", port=21)
        self.assertTrue(res["vulnerable"])
        mock_ftp_check.assert_called_with("10.0.0.2", port=21, timeout=3.0)

        findings = checker.check_port("10.0.0.2", 21)
        self.assertEqual(len(findings), 1)

    @patch("sys.argv", ["main.py", "-t", "127.0.0.1", "-p", "21", "-Pn", "-q"])
    @patch("main.is_host_online", return_value=True)
    @patch("main.scan_ports_concurrent")
    @patch("main.run_port_vulnerability_checks")
    def test_main_flags_ftp_vulnerability(
        self, mock_vuln_checks, mock_scan_concurrent, mock_host_online
    ):
        import io
        from unittest.mock import patch
        import main

        mock_vuln_checks.return_value = [
            {
                "vulnerable": True,
                "port": 21,
                "title": "FTP Anonymous Login Allowed",
                "flag": "[!] VULN: FTP Anonymous Login Allowed",
            }
        ]

        def fake_scan(ip, ports, timeout, max_workers, rate_limit_ms, grab_banners, on_port_scanned):
            on_port_scanned({"port": 21, "state": "OPEN", "service": "FTP", "banner": ""})
            return [{"port": 21, "state": "OPEN", "service": "FTP", "banner": ""}]

        mock_scan_concurrent.side_effect = fake_scan

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            main.main()

        output = captured_stdout.getvalue()
        self.assertIn("21/tcp", output)
        self.assertIn("[!] VULN: FTP Anonymous Login Allowed", output)
        self.assertIn("[*] Vulnerabilities  : 1 flagged", output)


if __name__ == "__main__":
    unittest.main()
