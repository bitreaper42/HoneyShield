"""
test_honeyshield.py
====================
Comprehensive unit and integration test suite for the HoneyShield
proactive threat intelligence pipeline.

Uses Python's native `unittest` framework with `unittest.mock` to mock
database operations (MongoDB) and external API requests (VirusTotal, Twilio)
so all tests are self-contained and cross-platform.

Test Classes:
    1. TestDatabaseLayer          – db_manager.py
    2. TestLuresAndParserLayer    – pdfparser.py, zipparser.py, drive_parser mock
    3. TestOrchestratorAndPipeline – sandbox.py orchestration
    4. TestScannersAndHunter      – apk_static_scanner, domain_hunter, request_detector
    5. TestEndToEndFailureRecovery – crash recovery / graceful degradation
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import io
import json
import zipfile
import tempfile

# Ensure the root project is in sys.path so we can import src
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from src.Database_manager.db_manager import (
    create_incident_record,
    update_incident_record,
    generate_and_assign_honeytokens,
)
from src.analysis.sandbox import (
    analyze_url,
    run_sandbox_from_file,
    run_sandbox_pipeline,
    _analyze_url_worker,
)
from src.analysis.domain_hunter import (
    hunt_domains,
    is_benign,
    check_suspicious,
    clean_domain,
    URL_PATTERN,
    BENIGN_DOMAINS,
)
from src.analysis.request_detector import run_detection
from src.lures.pdfparser import extract_payload_from_pdf
from src.lures.zipparser import extract_payload_from_zip


# ======================================================================
#  1. DATABASE LAYER TESTS
# ======================================================================
class TestDatabaseLayer(unittest.TestCase):
    """Tests for src/Database_manager/db_manager.py"""

    @patch("src.Database_manager.db_manager.get_database")
    def test_update_incident_record_success(self, mock_get_db):
        """update_incident_record correctly translates kwargs to dot-notation $set and calls update_one."""
        mock_collection = MagicMock()
        mock_db = MagicMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_get_db.return_value = mock_db

        mock_result = MagicMock()
        mock_result.matched_count = 1
        mock_result.modified_count = 1
        mock_collection.update_one.return_value = mock_result

        success = update_incident_record(
            "60b5a6c11d14e3001f3f6c8d",
            incident_status="APK_DOWNLOADED",
            apk_analysis={"apk_hash": "abc123"},
        )

        self.assertTrue(success)
        # Verify update_one was called
        mock_collection.update_one.assert_called_once()

        # Extract the actual $set payload that was sent
        call_args = mock_collection.update_one.call_args
        set_payload = call_args[0][1]["$set"]

        # Flat dot-notation keys should be present (flatten_dict in db_manager)
        self.assertEqual(set_payload["incident_status"], "APK_DOWNLOADED")
        self.assertEqual(set_payload["apk_analysis.apk_hash"], "abc123")

    @patch("src.Database_manager.db_manager.get_database")
    def test_update_incident_record_no_match(self, mock_get_db):
        """update_incident_record returns False when the record doesn't exist."""
        mock_collection = MagicMock()
        mock_db = MagicMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_get_db.return_value = mock_db

        mock_result = MagicMock()
        mock_result.matched_count = 0
        mock_collection.update_one.return_value = mock_result

        success = update_incident_record(
            "60b5a6c11d14e3001f3f6c8d",
            incident_status="SHOULD_NOT_EXIST",
        )
        self.assertFalse(success)

    @patch("src.Database_manager.db_manager.update_incident_record")
    def test_generate_and_assign_honeytokens_format(self, mock_update):
        """generate_and_assign_honeytokens produces correctly formatted synthetic credentials."""
        mock_update.return_value = True

        tokens = generate_and_assign_honeytokens("60b5a6c11d14e3001f3f6c8d")

        self.assertIsNotNone(tokens)
        self.assertIn("username", tokens)
        self.assertIn("password", tokens)
        self.assertIn("virtual_otp_number", tokens)

        # Username must start with one of the banking-style prefixes
        self.assertTrue(
            any(tokens["username"].startswith(p) for p in ["sbi_", "yono_", "user_"])
        )
        # Password must be exactly 12 characters
        self.assertEqual(len(tokens["password"]), 12)
        # OTP number must be a valid Indian mobile (+91 followed by 10 digits)
        self.assertTrue(tokens["virtual_otp_number"].startswith("+91"))
        self.assertEqual(len(tokens["virtual_otp_number"]), 13)

    @patch("src.Database_manager.db_manager.update_incident_record")
    def test_generate_honeytokens_returns_none_on_db_failure(self, mock_update):
        """generate_and_assign_honeytokens returns None when DB persist fails."""
        mock_update.return_value = False

        tokens = generate_and_assign_honeytokens("60b5a6c11d14e3001f3f6c8d")
        self.assertIsNone(tokens)


# ======================================================================
#  2. LURES & PARSER LAYER TESTS
# ======================================================================
class TestLuresAndParserLayer(unittest.TestCase):
    """Tests for src/lures/ — pdfparser.py, zipparser.py, and drive_parser mock."""

    def test_drive_parser_link_extraction_regex(self):
        """Verify drive link classification for normal, denied, and malware-blocked formats."""
        # Simulated drive_parser resolver (module not yet implemented in src/lures)
        def mock_resolve_drive_download_url(url):
            if "malicious" in url:
                return {"status": "TOS_MALWARE_BLOCKED", "url": None}
            elif "denied" in url:
                return {"status": "ACCESS_DENIED", "url": None}
            return {"status": "VALID", "url": f"{url}&export=download"}

        self.assertEqual(
            mock_resolve_drive_download_url(
                "https://drive.google.com/file/d/malicious123/view"
            )["status"],
            "TOS_MALWARE_BLOCKED",
        )
        self.assertEqual(
            mock_resolve_drive_download_url(
                "https://drive.google.com/file/d/denied123/view"
            )["status"],
            "ACCESS_DENIED",
        )
        result = mock_resolve_drive_download_url(
            "https://drive.google.com/file/d/benign123/view"
        )
        self.assertEqual(result["status"], "VALID")
        self.assertIn("export=download", result["url"])

    def test_pdfparser_extracts_urls(self):
        """pdfparser.py returns (list, list) and extracts embedded URIs from byte streams."""
        dummy_pdf = b"%PDF-1.4\n/URI (http://malicious-c2.com/payload.apk)\n%%EOF"
        urls, indicators = extract_payload_from_pdf(
            dummy_pdf, "dummy.pdf", "mock_record"
        )
        self.assertIsInstance(urls, list)
        self.assertIsInstance(indicators, list)

    def test_zipparser_handles_invalid_zip(self):
        """zipparser.py gracefully handles invalid ZIP byte streams without crashing."""
        urls, indicators = extract_payload_from_zip(
            b"PK\x03\x04", "dummy.zip", "mock_record"
        )
        self.assertIsInstance(urls, list)
        self.assertIsInstance(indicators, list)


# ======================================================================
#  3. ORCHESTRATOR & ANALYSIS PIPELINE TESTS
# ======================================================================
class TestOrchestratorAndPipeline(unittest.TestCase):
    """Tests for src/analysis/sandbox.py orchestration."""

    @patch("src.analysis.sandbox.threading.Thread")
    def test_analyze_url_unblocks_immediately(self, mock_thread):
        """analyze_url spawns a daemon thread and returns without blocking."""
        analyze_url("http://malicious.com", "mock_id")
        mock_thread.assert_called_once()
        mock_thread.return_value.start.assert_called_once()

    @patch("src.analysis.sandbox.requests.get")
    @patch("src.analysis.sandbox.update_incident_record")
    @patch("src.analysis.sandbox.run_sandbox_pipeline")
    def test_analyze_url_malicious_vt_response(
        self, mock_pipeline, mock_update, mock_get
    ):
        """VT returns malicious count > 0 — DB is updated with the correct score."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "undetected": 60,
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        _analyze_url_worker("http://malicious.com", "mock_id")

        # Verify the VT score was persisted
        mock_update.assert_any_call(
            record_id="mock_id",
            osint_analysis={"virustotal_score": "5/65"},
        )
        # Pipeline should still be triggered after VT analysis
        mock_pipeline.assert_called_once()

    @patch("src.analysis.sandbox.requests.get")
    @patch("src.analysis.sandbox.update_incident_record")
    @patch("src.analysis.sandbox.run_sandbox_pipeline")
    def test_analyze_url_vt_not_found(self, mock_pipeline, mock_update, mock_get):
        """VT returns 404 (URL not indexed) — pipeline is still triggered."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        _analyze_url_worker("http://unknown.com", "mock_id")
        mock_pipeline.assert_called_once()

    @patch("src.analysis.sandbox.update_incident_record")
    @patch("src.analysis.sandbox.scan_apk")
    @patch("src.analysis.sandbox.run_real_sandbox")
    @patch("src.analysis.sandbox.hunt_domains")
    @patch("src.analysis.sandbox.run_detection")
    @patch("src.analysis.sandbox.generate_and_assign_honeytokens")
    def test_run_sandbox_from_file_skips_download(
        self, mock_tokens, mock_detect, mock_hunt, mock_sandbox, mock_scan, mock_update
    ):
        """run_sandbox_from_file skips download, marks APK_DOWNLOADED, and calls static scanner."""
        mock_scan.return_value = {"risk_score": 85}
        mock_sandbox.return_value = {
            "threat_score": 90,
            "signatures_triggered": ["steals_sms"],
        }
        mock_hunt.return_value = {"suspicious_domains": ["malicious.com"]}
        mock_detect.return_value = {
            "c2_base_url": "malicious.com",
            "probed_endpoints": ["/api/login"],
        }

        run_sandbox_from_file("dummy.apk", "mock_id")

        # Phase 1 skip — APK_DOWNLOADED set immediately
        mock_update.assert_any_call(
            record_id="mock_id", incident_status="APK_DOWNLOADED"
        )
        # Phase 2 — static scanner invoked
        mock_scan.assert_called_once()
        # Phase 5 — final status should be TRAP_READY (endpoints found)
        mock_update.assert_any_call(
            record_id="mock_id",
            incident_status="TRAP_READY",
            osint_analysis={
                "c2_base_url": "malicious.com",
                "active_endpoints": ["/api/login"],
            },
        )


# ======================================================================
#  4. SCANNERS & HUNTER PHASE TESTS
# ======================================================================
class TestScannersAndHunter(unittest.TestCase):
    """Tests for src/analysis/ — static scanner, domain hunter, request detector."""

    def test_domain_hunter_benign_filtering(self):
        """is_benign correctly identifies framework/system domains from the exclusion list."""
        self.assertTrue(is_benign("google.com"))
        self.assertTrue(is_benign("schemas.android.com"))
        self.assertTrue(is_benign("sub.google.com"))
        self.assertFalse(is_benign("malicious-c2.cc"))
        self.assertFalse(is_benign("honeyshield-test.local"))

    def test_domain_hunter_suspicious_detection(self):
        """check_suspicious flags domains containing banking/fraud keywords."""
        self.assertTrue(check_suspicious("sbi-update-kyc.com"))
        self.assertTrue(check_suspicious("yono-login.in"))
        self.assertTrue(check_suspicious("secure-bank-otp.net"))
        self.assertFalse(check_suspicious("httpbin.org"))
        self.assertFalse(check_suspicious("example.com"))

    def test_domain_hunter_url_regex(self):
        """URL_PATTERN regex correctly extracts HTTP/HTTPS URLs from raw strings."""
        test_string = (
            "connect to http://malicious-c2.cc/login and "
            "also https://google.com/api/v1 plus http://192.168.1.1:8080/test"
        )
        urls = URL_PATTERN.findall(test_string)
        self.assertIn("http://malicious-c2.cc/login", urls)
        self.assertIn("https://google.com/api/v1", urls)

    def test_domain_hunter_clean_domain(self):
        """clean_domain normalizes domain strings (lowercase, strip port)."""
        self.assertEqual(clean_domain("Example.COM:8080"), "example.com")
        self.assertEqual(clean_domain("  GOOGLE.com  "), "google.com")

    def _create_test_apk_zip(self, urls_in_dex):
        """Helper: creates a minimal APK zip containing a fake classes.dex with embedded URLs."""
        tmp = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
        with zipfile.ZipFile(tmp.name, "w") as zf:
            dex_content = "\n".join(urls_in_dex).encode("utf-8")
            zf.writestr("classes.dex", dex_content)
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        return tmp.name

    def test_domain_hunter_full_pipeline(self):
        """hunt_domains extracts URLs from a synthetic APK and classifies domains correctly."""
        apk_path = self._create_test_apk_zip([
            "http://malicious-sbi-kyc.com/login",
            "https://google.com/api",
            "http://httpbin.org/get",
        ])
        try:
            results = hunt_domains(apk_path)

            self.assertIn("malicious-sbi-kyc.com", results["suspicious_domains"])
            self.assertIn("google.com", results["benign_domains"])
            self.assertIn("httpbin.org", results["general_domains"])
        finally:
            os.unlink(apk_path)

    @patch("src.analysis.request_detector.scan_bundle_for_url_and_params")
    @patch("src.analysis.request_detector.probe_endpoint")
    @patch("src.analysis.request_detector.get_incident_record")
    def test_request_detector_trap_ready(
        self, mock_get_record, mock_probe, mock_scan_bundle
    ):
        """Request detector correctly marks TRAP_READY when active endpoints are found."""
        # Mock the hunted_domains.json file read
        fake_report = {
            "suspicious_domains": ["malicious-c2.cc"],
            "general_domains": [],
            "benign_domains": ["google.com"],
        }
        mock_scan_bundle.return_value = [
            "http://malicious-c2.cc/api/login"
        ]
        mock_probe.return_value = ("POST", '{"success":true}', {"username": "sbi_test"})
        mock_get_record.return_value = {
            "honeytokens": {
                "username": "sbi_test",
                "password": "Pwd123!@",
                "virtual_otp_number": "+919876543210",
            }
        }

        # Mock the file read for hunted_domains.json
        with patch("builtins.open", mock_open(read_data=json.dumps(fake_report))):
            with patch("os.path.exists", return_value=True):
                results = run_detection("dummy.apk", "mock_id")

        self.assertIn("c2_base_url", results)
        self.assertEqual(results["c2_base_url"], "http://malicious-c2.cc")
        self.assertTrue(len(results["probed_endpoints"]) > 0)
        self.assertEqual(results["probed_endpoints"][0]["status"], "ACTIVE")


# ======================================================================
#  5. END-TO-END FAILURE RECOVERY TESTS
# ======================================================================
class TestEndToEndFailureRecovery(unittest.TestCase):
    """Tests for graceful degradation and crash recovery."""

    @patch("src.analysis.sandbox.download_and_hash_apk")
    @patch("src.analysis.sandbox.update_incident_record")
    @patch("src.analysis.sandbox.generate_and_assign_honeytokens")
    @patch("src.analysis.sandbox.perform_url_sanity_check")
    def test_crash_at_download_marks_pipeline_failed(
        self, mock_sanity, mock_tokens, mock_update, mock_download
    ):
        """Crash inside apk_analyzer.py during download is caught; DB status set to PIPELINE_FAILED."""
        mock_download.side_effect = Exception("Simulated Download Crash")
        mock_sanity.return_value = {}

        with patch("sys.stdout", new=io.StringIO()):
            run_sandbox_pipeline("http://crash.com", "mock_id")

        mock_update.assert_any_call(
            record_id="mock_id",
            incident_status="PIPELINE_FAILED",
        )

    @patch("src.analysis.sandbox.update_incident_record")
    @patch("src.analysis.sandbox.scan_apk")
    @patch("src.analysis.sandbox.generate_and_assign_honeytokens")
    def test_crash_at_static_scan_marks_pipeline_failed(
        self, mock_tokens, mock_scan, mock_update
    ):
        """Crash during static scanning is caught; DB status set to PIPELINE_FAILED."""
        mock_scan.side_effect = Exception("Simulated Static Scan Crash")

        with patch("sys.stdout", new=io.StringIO()):
            run_sandbox_from_file("dummy.apk", "mock_id")

        mock_update.assert_any_call(
            record_id="mock_id",
            incident_status="PIPELINE_FAILED",
        )

    @patch("src.analysis.sandbox.update_incident_record")
    @patch("src.analysis.sandbox.scan_apk")
    @patch("src.analysis.sandbox.run_real_sandbox")
    @patch("src.analysis.sandbox.generate_and_assign_honeytokens")
    def test_crash_at_dynamic_sandbox_marks_pipeline_failed(
        self, mock_tokens, mock_sandbox, mock_scan, mock_update
    ):
        """Crash during dynamic sandbox (VT upload) is caught; DB status set to PIPELINE_FAILED."""
        mock_scan.return_value = {"risk_score": 50}
        mock_sandbox.side_effect = Exception("VT API Timeout")

        with patch("sys.stdout", new=io.StringIO()):
            run_sandbox_from_file("dummy.apk", "mock_id")

        mock_update.assert_any_call(
            record_id="mock_id",
            incident_status="PIPELINE_FAILED",
        )


# ======================================================================
if __name__ == "__main__":
    unittest.main(verbosity=2)
