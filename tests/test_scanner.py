"""Unit tests for NetPulse core logic and helper utilities."""

import os
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


if __name__ == "__main__":
    unittest.main()
