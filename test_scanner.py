import unittest
from unittest.mock import patch

from scanner import run_scan, HeaderCheck


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


class TestScanner(unittest.TestCase):
    @patch("scanner.requests.get")
    def test_all_headers_present(self, mock_get):
        mock_get.return_value = FakeResponse({
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        })
        report = run_scan("https://example.com")
        self.assertEqual(report["score"], "6/6")
        self.assertTrue(all(r["status"] == "PASS" for r in report["checks"]))

    @patch("scanner.requests.get")
    def test_missing_headers_flagged(self, mock_get):
        mock_get.return_value = FakeResponse({})
        report = run_scan("https://example.com")
        self.assertEqual(report["score"], "0/6")
        self.assertTrue(all(r["status"] == "FAIL" for r in report["checks"]))

    @patch("scanner.requests.get")
    def test_information_leak_detected(self, mock_get):
        mock_get.return_value = FakeResponse({"Server": "Apache/2.4.1"})
        report = run_scan("https://example.com")
        self.assertEqual(len(report["information_leak_headers"]), 1)
        self.assertEqual(report["information_leak_headers"][0]["header"], "Server")


if __name__ == "__main__":
    unittest.main()
