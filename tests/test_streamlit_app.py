"""Offline Streamlit/pipeline tests using test doubles, never real model services."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from phishpilot.domain.models import (
    DeciderDecision,
    ReportResult,
    RiskCategory,
)
from phishpilot.errors import IntegrationUnavailableError
from phishpilot.integrations import bedrock_reporter, decider_http


class _TestDecider:
    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls = 0

    def decide(self, _evidence):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.response


class _TestReporter:
    def __init__(self, result: ReportResult) -> None:
        self.result = result
        self.calls = 0

    def generate(self, _evidence, _decision):  # type: ignore[no-untyped-def]
        self.calls += 1
        return self.result


class StreamlitPipelineOfflineTests(TestCase):
    """These fixtures exercise UI and orchestration contracts, not inference."""

    def test_input_widget_caps_match_domain_and_url_parser_limits(self) -> None:
        app_path = Path(__file__).resolve().parent.parent / "app.py"
        app = AppTest.from_file(app_path).run()
        self.assertEqual(app.text_area[0].max_chars, 20_000)
        self.assertIn("10 extracted URLs", app.text_area[0].help)
        self.assertIn("4096 characters per URL", app.text_area[0].help)

        app.radio[0].set_value("URL")
        app.run()
        self.assertEqual(app.text_area[0].max_chars, 4_096)
        self.assertIn("at most 4096 characters", app.text_area[0].help)

    def _submit(self, decider: _TestDecider, reporter: _TestReporter) -> AppTest:
        with (
            patch.object(decider_http, "DeciderHttpClient", return_value=decider),
            patch.object(bedrock_reporter, "BedrockReportClient", return_value=reporter),
        ):
            app_path = Path(__file__).resolve().parent.parent / "app.py"
            app = AppTest.from_file(app_path).run()
            app.text_area[0].set_value("Urgent message: review https://example.test/account")
            app.checkbox[0].check()
            return app.button[0].click().run()

    def _decision(self) -> DeciderDecision:
        return DeciderDecision(
            RiskCategory.SUSPICIOUS,
            {"likely_benign": 0.1, "suspicious": 0.8, "high_risk": 0.1},
            0.7,
            "test-fixture-only",
        )

    def test_successful_pipeline_shows_typed_decision_separately_from_prose(self) -> None:
        decider = _TestDecider(self._decision())
        reporter = _TestReporter(
            ReportResult(
                True,
                text="Fixture prose says likely_benign; this is deliberately contradictory.",
            )
        )
        app = self._submit(decider, reporter)

        self.assertFalse(app.exception)
        self.assertEqual(decider.calls, 1)
        self.assertEqual(reporter.calls, 1)
        markdown = "\n".join(element.value for element in app.markdown)
        plain_text = "\n".join(element.value for element in app.text)
        self.assertIn("Authoritative typed category:", markdown)
        self.assertIn("suspicious", markdown)
        self.assertIn("Fixture prose says likely_benign", plain_text)
        captions = "\n".join(element.value for element in app.caption)
        self.assertIn("does not change the typed Decider category", captions)

    def test_decider_unavailable_displays_no_replacement_decision_and_skips_report(self) -> None:
        decider = _TestDecider(error=IntegrationUnavailableError("offline fixture"))
        reporter = _TestReporter(ReportResult(False, error_message="should not be used"))
        with (
            patch.object(decider_http, "DeciderHttpClient", return_value=decider),
            patch.object(
                bedrock_reporter, "BedrockReportClient", return_value=reporter
            ) as reporter_factory,
        ):
            app_path = Path(__file__).resolve().parent.parent / "app.py"
            app = AppTest.from_file(app_path).run()
            app.text_area[0].set_value("Urgent message: review https://example.test/account")
            app.checkbox[0].check()
            app.button[0].click().run()

        self.assertEqual(decider.calls, 1)
        self.assertEqual(reporter.calls, 0)
        reporter_factory.assert_not_called()
        self.assertTrue(any("No Decider category was produced" in e.value for e in app.error))
        markdown = "\n".join(element.value for element in app.markdown)
        self.assertNotIn("Authoritative typed category:", markdown)

    def test_invalid_decider_object_is_not_shown_as_a_decision(self) -> None:
        decider = _TestDecider(response={"category": "suspicious"})
        reporter = _TestReporter(ReportResult(False, error_message="should not be used"))
        app = self._submit(decider, reporter)

        self.assertEqual(reporter.calls, 0)
        self.assertTrue(any("No Decider category was produced" in e.value for e in app.error))

    def test_report_failure_preserves_typed_decision_and_shows_unavailable_state(self) -> None:
        decider = _TestDecider(self._decision())
        reporter = _TestReporter(
            ReportResult(
                False,
                error_code="fixture_failure",
                error_message="Fixture report unavailable.",
            )
        )
        app = self._submit(decider, reporter)

        self.assertEqual(decider.calls, 1)
        self.assertEqual(reporter.calls, 1)
        markdown = "\n".join(element.value for element in app.markdown)
        warnings = "\n".join(element.value for element in app.warning)
        self.assertIn("suspicious", markdown)
        self.assertIn("report generation is unavailable", warnings)
        self.assertIn("Fixture report unavailable.", warnings)

    def test_reporter_configuration_failure_occurs_after_decider_and_preserves_choice(self) -> None:
        events: list[str] = []
        decision = self._decision()

        class OrderedDecider:
            def decide(self, _evidence):  # type: ignore[no-untyped-def]
                events.append("decider")
                return decision

        def invalid_reporter_configuration():
            events.append("reporter_factory")
            raise ValueError("fixture secret must not be displayed")

        with (
            patch.object(decider_http, "DeciderHttpClient", return_value=OrderedDecider()),
            patch.object(
                bedrock_reporter,
                "BedrockReportClient",
                side_effect=invalid_reporter_configuration,
            ),
        ):
            app_path = Path(__file__).resolve().parent.parent / "app.py"
            app = AppTest.from_file(app_path).run()
            app.text_area[0].set_value("Synthetic message with no private content")
            app.checkbox[0].check()
            app.button[0].click().run()

        self.assertFalse(app.exception)
        self.assertEqual(events, ["decider", "reporter_factory"])
        markdown = "\n".join(element.value for element in app.markdown)
        warnings = "\n".join(element.value for element in app.warning)
        self.assertIn("Authoritative typed category:", markdown)
        self.assertIn("suspicious", markdown)
        self.assertIn("report generation is unavailable", warnings)
        self.assertNotIn("fixture secret", warnings)

    def test_missing_bedrock_key_is_report_unavailable_without_agent_or_aws_call(self) -> None:
        from phishpilot.integrations.bedrock_reporter import BedrockReportClient

        decider = _TestDecider(self._decision())
        agent_constructions: list[bool] = []
        reporter = BedrockReportClient(
            model_id="amazon.nova-micro-v1:0",
            region="ap-southeast-2",
            agent_factory=lambda *_args: agent_constructions.append(True),
        )
        with (
            patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": ""}),
            patch.object(decider_http, "DeciderHttpClient", return_value=decider),
            patch.object(bedrock_reporter, "BedrockReportClient", return_value=reporter),
        ):
            app_path = Path(__file__).resolve().parent.parent / "app.py"
            app = AppTest.from_file(app_path).run()
            app.text_area[0].set_value("Sanitized offline test message")
            app.checkbox[0].check()
            app.button[0].click().run()

        self.assertFalse(app.exception)
        self.assertEqual(decider.calls, 1)
        markdown = "\n".join(element.value for element in app.markdown)
        warnings = "\n".join(element.value for element in app.warning)
        self.assertIn("Authoritative typed category:", markdown)
        self.assertIn("suspicious", markdown)
        self.assertIn("report generation is unavailable", warnings)
        self.assertIn("AWS_BEARER_TOKEN_BEDROCK", warnings)
        self.assertEqual(agent_constructions, [])

    def test_no_acknowledgement_means_no_model_client_is_constructed(self) -> None:
        decider = _TestDecider(self._decision())
        reporter = _TestReporter(ReportResult(True, text="fixture"))
        with (
            patch.object(
                decider_http, "DeciderHttpClient", return_value=decider
            ) as decider_factory,
            patch.object(
                bedrock_reporter, "BedrockReportClient", return_value=reporter
            ) as reporter_factory,
        ):
            app_path = Path(__file__).resolve().parent.parent / "app.py"
            app = AppTest.from_file(app_path).run()
            app.text_area[0].set_value("Short sanitized example")
            app.button[0].click().run()

        self.assertTrue(any("Acknowledge" in e.value for e in app.warning))
        self.assertEqual(decider.calls, 0)
        self.assertEqual(reporter.calls, 0)
        decider_factory.assert_not_called()
        reporter_factory.assert_not_called()

    def test_invalid_input_is_rejected_before_constructing_clients(self) -> None:
        decider = _TestDecider(self._decision())
        reporter = _TestReporter(ReportResult(True, text="fixture"))
        with (
            patch.object(decider_http, "DeciderHttpClient", return_value=decider),
            patch.object(bedrock_reporter, "BedrockReportClient", return_value=reporter),
        ):
            app_path = Path(__file__).resolve().parent.parent / "app.py"
            app = AppTest.from_file(app_path).run()
            app.text_area[0].set_value("   ")
            app.checkbox[0].check()
            app.button[0].click().run()

        self.assertTrue(any("content must be a non-empty string" in e.value for e in app.error))
        self.assertEqual(decider.calls, 0)
        self.assertEqual(reporter.calls, 0)

    def test_eleven_urls_are_rejected_before_either_client_is_called(self) -> None:
        decider = _TestDecider(self._decision())
        reporter = _TestReporter(ReportResult(True, text="fixture"))
        with (
            patch.object(decider_http, "DeciderHttpClient", return_value=decider),
            patch.object(bedrock_reporter, "BedrockReportClient", return_value=reporter),
        ):
            app_path = Path(__file__).resolve().parent.parent / "app.py"
            app = AppTest.from_file(app_path).run()
            content = " ".join(
                f"https://site-{index}.example.test/path" for index in range(11)
            )
            app.text_area[0].set_value(content)
            app.checkbox[0].check()
            app.button[0].click().run()

        self.assertTrue(any("maximum of 10 URLs" in e.value for e in app.error))
        self.assertEqual(decider.calls, 0)
        self.assertEqual(reporter.calls, 0)

if __name__ == "__main__":
    import unittest

    unittest.main()
