"""Offline tests for read-only diagnostics; no model/AWS/network calls are made."""

from __future__ import annotations

import socket
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from phishpilot.diagnostics import (
    EXPECTED_MODEL_REPOSITORIES,
    GIB,
    MemoryInfo,
    _health_url,
    check_decider_health,
    collect_diagnostics,
    render_report,
)
from phishpilot.errors import ValidationError


class DiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "pyproject.toml").write_text(
            '[project]\nrequires-python = ">=3.12,<3.15"\n', encoding="utf-8"
        )
        self.cache_root = self.root / "hub"
        self.cache_root.mkdir()
        for repository in EXPECTED_MODEL_REPOSITORIES:
            (self.cache_root / ("models--" + repository.replace("/", "--"))).mkdir()
        self.versions = {
            name: "1.0.0"
            for name in (
                "strands-agents",
                "strands-decider",
                "streamlit",
                "boto3",
                "requests",
                "pydantic",
                "python-dotenv",
                "torch",
                "transformers",
                "peft",
                "accelerate",
                "pytest",
                "pytest-cov",
                "ruff",
            )
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _collect(self, **kwargs: object):
        defaults = {
            "project_root": self.root,
            "environment": {"HF_HUB_CACHE": str(self.cache_root)},
            "package_version_reader": self.versions.__getitem__,
            "memory_reader": lambda: MemoryInfo(16 * GIB, 12 * GIB, 25.0),
            "python_version": (3, 14, 4),
        }
        defaults.update(kwargs)
        return collect_diagnostics(**defaults)  # type: ignore[arg-type]

    def test_successful_offline_readiness_uses_metadata_and_cache_presence(self) -> None:
        report = self._collect()

        self.assertTrue(report.python_compatible)
        self.assertEqual(report.package_versions["strands-decider"], "1.0.0")
        self.assertEqual(report.decider_endpoint, "http://127.0.0.1:8000/v1/systemone")
        self.assertEqual(report.decider_timeout_seconds, 60.0)
        self.assertTrue(all(report.model_caches.values()))
        self.assertEqual(report.local_preflight_status, "READY")
        self.assertFalse(report.health_checked)
        self.assertIsNone(report.health_available)

    def test_missing_configuration_uses_safe_decider_defaults(self) -> None:
        report = self._collect(environment={})

        self.assertTrue(report.decider_configuration_valid)
        self.assertEqual(report.decider_endpoint, "http://127.0.0.1:8000/v1/systemone")
        self.assertEqual(report.decider_timeout_seconds, 60.0)
        self.assertFalse(report.environment_present["BEDROCK_MODEL_ID"])
        self.assertFalse(report.environment_present["AWS_REGION or AWS_DEFAULT_REGION"])

    def test_invalid_timeout_is_blocked_without_echoing_value(self) -> None:
        report = self._collect(
            environment={
                "HF_HUB_CACHE": str(self.cache_root),
                "PHISHPILOT_DECIDER_TIMEOUT_SECONDS": "secret-timeout-value",
            }
        )
        rendered = render_report(report)

        self.assertFalse(report.decider_configuration_valid)
        self.assertIsNone(report.decider_timeout_seconds)
        self.assertIn("Decider configuration", rendered)
        self.assertNotIn("secret-timeout-value", rendered)

    def test_memory_access_denied_is_reported_as_unknown(self) -> None:
        def inaccessible_memory() -> MemoryInfo:
            raise PermissionError("private OS detail")

        report = self._collect(memory_reader=inaccessible_memory)
        rendered = render_report(report)

        memory_check = next(
            check for check in report.checks if check.name == "CPU memory preflight"
        )
        self.assertEqual(memory_check.status, "UNKNOWN")
        self.assertIn("access denied", rendered)
        self.assertNotIn("private OS detail", rendered)

    def test_missing_cache_paths_block_local_preflight(self) -> None:
        empty_cache = self.root / "empty-hub"
        empty_cache.mkdir()
        report = self._collect(environment={"HF_HUB_CACHE": str(empty_cache)})

        cache_check = next(check for check in report.checks if check.name == "Model cache paths")
        self.assertEqual(cache_check.status, "BLOCKED")
        self.assertTrue(all(present is False for present in report.model_caches.values()))

    def test_low_memory_blocks_preflight_without_starting_model(self) -> None:
        report = self._collect(
            memory_reader=lambda: MemoryInfo(16 * GIB, 8 * GIB, 50.0)
        )

        memory_check = next(
            check for check in report.checks if check.name == "CPU memory preflight"
        )
        self.assertEqual(memory_check.status, "BLOCKED")
        self.assertEqual(report.local_preflight_status, "BLOCKED")

    def test_default_run_never_calls_health_checker(self) -> None:
        def unexpected_health_check(endpoint: str, timeout: float) -> bool:
            raise AssertionError("health check must require explicit opt-in")

        report = self._collect(health_checker=unexpected_health_check)

        self.assertFalse(report.health_checked)
        self.assertIsNone(report.health_available)

    def test_opt_in_unavailable_health_check_is_reported_as_unavailable(self) -> None:
        calls: list[tuple[str, float]] = []

        def unavailable_health_check(endpoint: str, timeout: float) -> bool:
            calls.append((endpoint, timeout))
            return False

        report = self._collect(check_health=True, health_checker=unavailable_health_check)

        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].startswith("http://127.0.0.1:"))
        self.assertFalse(report.health_available)
        self.assertIn("unavailable", report.health_detail or "")

    def test_opt_in_health_check_can_report_success_from_a_test_double(self) -> None:
        calls: list[tuple[str, float]] = []

        def test_only_health_check(endpoint: str, timeout: float) -> bool:
            calls.append((endpoint, timeout))
            return True

        report = self._collect(check_health=True, health_checker=test_only_health_check)

        self.assertTrue(report.health_available)
        self.assertEqual(report.health_detail, "available")
        self.assertEqual(len(calls), 1)
        self.assertIn("Live Decider inference: NOT checked", render_report(report))

    def test_missing_runtime_package_is_reported_without_install_attempt(self) -> None:
        def incomplete_version_reader(name: str) -> str:
            if name == "strands-decider":
                from importlib.metadata import PackageNotFoundError

                raise PackageNotFoundError(name)
            return self.versions[name]

        report = self._collect(package_version_reader=incomplete_version_reader)

        self.assertIsNone(report.package_versions["strands-decider"])
        package_check = next(check for check in report.checks if check.name == "Runtime packages")
        self.assertEqual(package_check.status, "BLOCKED")

    def test_health_url_rejects_non_loopback_before_any_request(self) -> None:
        with self.assertRaises(ValidationError):
            _health_url("http://example.com:8000/v1/systemone")

    def test_health_check_uses_only_the_local_health_path(self) -> None:
        class HealthHandler(BaseHTTPRequestHandler):
            requested_path: str | None = None

            def do_GET(self) -> None:  # noqa: N802 - standard-library server API
                self.server.requested_path = self.path  # type: ignore[attr-defined]
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://127.0.0.1:{server.server_port}/v1/systemone"
            self.assertTrue(check_decider_health(endpoint, 1.0))
            self.assertEqual(server.requested_path, "/health")  # type: ignore[attr-defined]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_unavailable_local_health_endpoint_returns_false(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        endpoint = f"http://127.0.0.1:{port}/v1/systemone"

        self.assertFalse(check_decider_health(endpoint, 0.2))

    def test_environment_values_and_credentials_are_never_rendered(self) -> None:
        marker = "never-print-this-secret"
        report = self._collect(
            environment={
                "HF_HUB_CACHE": str(self.cache_root),
                "BEDROCK_MODEL_ID": marker,
                "AWS_SECRET_ACCESS_KEY": marker,
                "AWS_REGION": "private-region-value",
            }
        )
        rendered = render_report(report)

        self.assertTrue(report.environment_present["AWS credential env vars present"])
        self.assertNotIn(marker, rendered)
        self.assertNotIn("private-region-value", rendered)


if __name__ == "__main__":
    unittest.main()
