"""Offline orchestration tests using test-local client doubles only."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from phishpilot.domain.models import (
    AnalysisStatus,
    DeciderDecision,
    EvidenceReport,
    InputType,
    InvestigationInput,
    ReportResult,
    RiskCategory,
)
from phishpilot.errors import IntegrationUnavailableError, ValidationError
from phishpilot.pipeline import DecisionReviewPolicy, investigate


def make_decision(
    *,
    category: RiskCategory = RiskCategory.SUSPICIOUS,
    distribution: dict[str, float] | None = None,
    confidence: float = 0.7,
) -> DeciderDecision:
    return DeciderDecision(
        category=category,
        option_distribution=distribution or {
            "likely_benign": 0.1,
            "suspicious": 0.8,
            "high_risk": 0.1,
        },
        confidence=confidence,
        model_id="test-local-only",
    )


class TestDeciderClient:
    """A unit-test-only client; never registered as an application provider."""

    def __init__(
        self,
        result: object = None,
        error: Exception | None = None,
        calls: list | None = None,
    ) -> None:
        self.result = result if result is not None else make_decision()
        self.error = error
        self.calls = calls if calls is not None else []

    def decide(self, evidence: EvidenceReport) -> DeciderDecision:
        self.calls.append(("decider", evidence))
        if self.error:
            raise self.error
        return self.result  # type: ignore[return-value]


class TestReportClient:
    """A unit-test-only report client; never registered as an application provider."""

    def __init__(
        self,
        result: object = None,
        error: Exception | None = None,
        calls: list | None = None,
    ) -> None:
        self.result = result if result is not None else ReportResult(True, text="Test report")
        self.error = error
        self.calls = calls if calls is not None else []

    def generate(self, evidence: EvidenceReport, decision: DeciderDecision) -> ReportResult:
        self.calls.append(("report", evidence, decision))
        if self.error:
            raise self.error
        return self.result  # type: ignore[return-value]


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = DecisionReviewPolicy(minimum_confidence=0.5, minimum_probability_margin=0.05)

    def test_successful_call_order_and_accurate_result(self) -> None:
        calls: list[tuple] = []
        decision = make_decision()
        decider = TestDeciderClient(decision, calls=calls)
        reporter = TestReportClient(calls=calls)
        result = investigate(
            InvestigationInput(InputType.EMAIL, "Please review this notice."),
            decider=decider,
            reporter=reporter,
            review_policy=self.policy,
        )
        self.assertEqual([item[0] for item in calls], ["decider", "report"])
        self.assertIs(calls[0][1], calls[1][1])
        self.assertIs(calls[1][2], decision)
        self.assertEqual(result.status, AnalysisStatus.ASSESSED)
        self.assertIs(result.decision, decision)
        self.assertTrue(result.report.available)
        self.assertEqual(set(result.timings_ms), {"evidence", "decider", "report"})
        self.assertTrue(all(duration >= 0 for duration in result.timings_ms.values()))

    def test_invalid_input_fails_before_either_client(self) -> None:
        calls: list[tuple] = []
        with self.assertRaises(ValidationError):
            investigate(
                "not an InvestigationInput",  # type: ignore[arg-type]
                decider=TestDeciderClient(calls=calls),
                reporter=TestReportClient(calls=calls),
                review_policy=self.policy,
            )
        self.assertEqual(calls, [])

    def test_evidence_extraction_error_is_typed_and_calls_no_clients(self) -> None:
        calls: list[tuple] = []
        with patch(
            "phishpilot.pipeline.extract_email_evidence",
            side_effect=ValidationError("invalid"),
        ):
            with self.assertRaises(ValidationError):
                investigate(
                    InvestigationInput(InputType.EMAIL, "body"),
                    decider=TestDeciderClient(calls=calls),
                    reporter=TestReportClient(calls=calls),
                    review_policy=self.policy,
                )
        self.assertEqual(calls, [])

    def test_decider_failure_prevents_report_and_returns_unavailable(self) -> None:
        calls: list[tuple] = []
        result = investigate(
            InvestigationInput(InputType.EMAIL, "body"),
            decider=TestDeciderClient(
                error=IntegrationUnavailableError("private detail"), calls=calls
            ),
            reporter=TestReportClient(calls=calls),
            review_policy=self.policy,
        )
        self.assertEqual([item[0] for item in calls], ["decider"])
        self.assertEqual(result.status, AnalysisStatus.ANALYSIS_UNAVAILABLE)
        self.assertIsNone(result.decision)
        self.assertFalse(result.report.available)
        self.assertEqual(result.error_code, "decider_unavailable")
        self.assertNotIn("private detail", result.error_message or "")

    def test_decider_timeout_is_reported_safely_without_a_decision(self) -> None:
        calls: list[tuple] = []
        result = investigate(
            InvestigationInput(InputType.EMAIL, "body"),
            decider=TestDeciderClient(
                error=IntegrationUnavailableError("Decider request timed out"), calls=calls
            ),
            reporter=TestReportClient(calls=calls),
            review_policy=self.policy,
        )
        self.assertEqual(result.status, AnalysisStatus.ANALYSIS_UNAVAILABLE)
        self.assertIsNone(result.decision)
        self.assertEqual(result.error_code, "decider_timeout")
        self.assertEqual(
            result.error_message,
            "The Decider exceeded the configured request timeout; no decision was produced.",
        )
        self.assertEqual([item[0] for item in calls], ["decider"])

    def test_unexpected_decider_response_is_unavailable_not_a_guess(self) -> None:
        calls: list[tuple] = []
        result = investigate(
            InvestigationInput(InputType.EMAIL, "body"),
            decider=TestDeciderClient(result={"category": "high_risk"}, calls=calls),
            reporter=TestReportClient(calls=calls),
            review_policy=self.policy,
        )
        self.assertEqual(result.status, AnalysisStatus.ANALYSIS_UNAVAILABLE)
        self.assertIsNone(result.decision)
        self.assertEqual(result.error_code, "decider_invalid_response")
        self.assertEqual([item[0] for item in calls], ["decider"])

    def test_low_confidence_decision_is_needs_review(self) -> None:
        decision = make_decision(
            distribution={"likely_benign": 0.35, "suspicious": 0.4, "high_risk": 0.25},
            confidence=0.1,
        )
        result = investigate(
            InvestigationInput(InputType.EMAIL, "This message is ambiguous."),
            decider=TestDeciderClient(decision),
            reporter=TestReportClient(),
            review_policy=self.policy,
        )
        self.assertEqual(result.status, AnalysisStatus.NEEDS_REVIEW)
        self.assertIs(result.decision, decision)

    def test_small_top_option_margin_requests_review(self) -> None:
        policy = DecisionReviewPolicy(minimum_confidence=0.0, minimum_probability_margin=0.1)
        decision = make_decision(
            distribution={"likely_benign": 0.33, "suspicious": 0.34, "high_risk": 0.33},
            confidence=0.01,
        )
        self.assertTrue(policy.requires_review(decision))

    def test_report_failure_preserves_decision_and_marks_report_unavailable(self) -> None:
        decision = make_decision()
        result = investigate(
            InvestigationInput(InputType.EMAIL, "body"),
            decider=TestDeciderClient(decision),
            reporter=TestReportClient(error=RuntimeError("sensitive provider details")),
            review_policy=self.policy,
        )
        self.assertEqual(result.status, AnalysisStatus.ANALYSIS_UNAVAILABLE)
        self.assertIs(result.decision, decision)
        self.assertFalse(result.report.available)
        self.assertEqual(result.error_code, "report_unavailable")
        self.assertNotIn("sensitive provider details", result.error_message or "")

    def test_invalid_report_response_is_explicit_and_keeps_real_decision(self) -> None:
        decision = make_decision()
        result = investigate(
            InvestigationInput(InputType.EMAIL, "body"),
            decider=TestDeciderClient(decision),
            reporter=TestReportClient(result={"text": "not validated"}),
            review_policy=self.policy,
        )
        self.assertEqual(result.status, AnalysisStatus.ANALYSIS_UNAVAILABLE)
        self.assertIs(result.decision, decision)
        self.assertFalse(result.report.available)

    def test_url_pipeline_does_not_resolve_or_fetch(self) -> None:
        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("network access is forbidden")

        with (
            patch.object(socket, "getaddrinfo", forbidden),
            patch.object(socket, "create_connection", forbidden),
            patch.object(socket, "socket", forbidden),
            patch("urllib.request.urlopen", forbidden),
        ):
            result = investigate(
                InvestigationInput(InputType.URL, "https://example.test/path"),
                decider=TestDeciderClient(),
                reporter=TestReportClient(),
                review_policy=self.policy,
            )
        self.assertEqual(result.evidence.input_type, InputType.URL)
        self.assertEqual(result.status, AnalysisStatus.ASSESSED)

    def test_explicit_policy_is_required_and_validated(self) -> None:
        with self.assertRaises(ValidationError):
            DecisionReviewPolicy(minimum_confidence=1.1)
        with self.assertRaises(ValidationError):
            investigate(
                InvestigationInput(InputType.EMAIL, "body"),
                decider=TestDeciderClient(),
                reporter=TestReportClient(),
                review_policy=None,  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
