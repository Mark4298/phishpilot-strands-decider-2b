"""Offline tests for the one-request Bedrock smoke entry point.

The reporter is replaced with a test-only double; these tests never call AWS.
"""

from __future__ import annotations

import contextlib
import io
import os
import unittest
from unittest.mock import patch

from phishpilot.bedrock_report_smoke import main
from phishpilot.domain.models import DeciderDecision, EvidenceReport, ReportResult


class BedrockSmokeEntryPointTests(unittest.TestCase):
    def test_requires_explicit_live_call_confirmation(self) -> None:
        with patch("phishpilot.bedrock_report_smoke.BedrockReportClient") as client:
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                main([])
        self.assertEqual(raised.exception.code, 2)
        client.assert_not_called()

    def test_confirmed_path_calls_reporter_once_with_synthetic_fixture(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "AWS_BEARER_TOKEN_BEDROCK": "unit-test-only-token",
                    "AWS_REGION": "ap-southeast-2",
                    "BEDROCK_MODEL_ID": "amazon.nova-micro-v1:0",
                },
            ),
            patch("phishpilot.bedrock_report_smoke.BedrockReportClient") as client_class,
        ):
            reporter = client_class.return_value
            reporter.generate.return_value = ReportResult(True, text="Fixture-only output.")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main(["--confirm-live-call"])

        self.assertEqual(exit_code, 0)
        reporter.generate.assert_called_once()
        evidence, decision = reporter.generate.call_args.args
        self.assertIsInstance(evidence, EvidenceReport)
        self.assertIsInstance(decision, DeciderDecision)
        self.assertEqual(decision.model_id, "synthetic-smoke-test-fixture")
        self.assertIn("not Decider inference", output.getvalue())
        self.assertIn("Fixture-only output.", output.getvalue())

    def test_missing_runtime_settings_prevent_reporter_construction(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("phishpilot.bedrock_report_smoke.BedrockReportClient") as client,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["--confirm-live-call"]), 2)
        client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
