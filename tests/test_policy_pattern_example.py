"""Offline tests for the reusable #policy example; doubles are test-only, not inference."""

from __future__ import annotations

import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest.mock import patch

from decision_patterns.evidence_aware_risk_triage.example import (
    classify_evidence,
    main,
    synthetic_evidence,
)
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


def decision_for(category: RiskCategory) -> DeciderDecision:
    probabilities = {
        "likely_benign": 0.1,
        "suspicious": 0.8,
        "high_risk": 0.1,
    }
    probabilities[category.value] = 0.8
    probabilities["suspicious"] = 0.1 if category is not RiskCategory.SUSPICIOUS else 0.8
    return DeciderDecision(
        category=category,
        option_distribution=probabilities,
        confidence=0.7,
        model_id="test-only-fixture-not-inference",
    )


class TestOnlyDecider:
    """A local test double; never selected by the example's executable default path."""

    def __init__(self, result: object = None, error: Exception | None = None) -> None:
        self.result = result if result is not None else decision_for(RiskCategory.SUSPICIOUS)
        self.error = error
        self.received: list[EvidenceReport] = []

    def decide(self, evidence: EvidenceReport) -> DeciderDecision:
        self.received.append(evidence)
        if self.error is not None:
            raise self.error
        return self.result  # type: ignore[return-value]


class TestOnlyReporter:
    """A local report fixture; it cannot change the typed decision."""

    def __init__(self) -> None:
        self.received_decisions: list[DeciderDecision] = []

    def generate(self, evidence: EvidenceReport, decision: DeciderDecision) -> ReportResult:
        self.received_decisions.append(decision)
        return ReportResult(True, text="Fixture prose that does not set a category.")


class PolicyPatternExampleTests(unittest.TestCase):
    def test_all_supported_options_are_valid_typed_decisions(self) -> None:
        for category in RiskCategory:
            with self.subTest(category=category):
                decision = decision_for(category)
                self.assertIs(decision.category, category)
                self.assertEqual(
                    set(decision.option_distribution),
                    {item.value for item in RiskCategory},
                )
                self.assertAlmostEqual(sum(decision.option_distribution.values()), 1.0)

    def test_unsupported_option_and_invalid_distribution_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            DeciderDecision(
                category="unsafe",  # type: ignore[arg-type]
                option_distribution={
                    "likely_benign": 0.1,
                    "suspicious": 0.8,
                    "high_risk": 0.1,
                },
                confidence=0.7,
                model_id="test-only",
            )
        with self.assertRaises(ValidationError):
            DeciderDecision(
                category=RiskCategory.SUSPICIOUS,
                option_distribution={"likely_benign": 0.1, "suspicious": 0.9},
                confidence=0.7,
                model_id="test-only",
            )

    def test_pattern_passes_structured_evidence_and_preserves_typed_decision(self) -> None:
        evidence = synthetic_evidence()
        client = TestOnlyDecider()
        result = classify_evidence(evidence, decider=client)
        self.assertIsInstance(result, DeciderDecision)
        self.assertIs(result, client.result)
        self.assertEqual(client.received, [evidence])

    def test_service_failure_propagates_without_fabricating_a_decision(self) -> None:
        client = TestOnlyDecider(error=IntegrationUnavailableError("test-only unavailable"))
        with self.assertRaises(IntegrationUnavailableError):
            classify_evidence(synthetic_evidence(), decider=client)

    def test_cli_reports_sanitized_typed_failure_without_a_decision(self) -> None:
        class UnavailableClient:
            def __init__(self) -> None:
                pass

            def decide(self, evidence: EvidenceReport) -> DeciderDecision:
                raise IntegrationUnavailableError("Decider request timed out")

        stderr = StringIO()
        with patch(
            "decision_patterns.evidence_aware_risk_triage.example.DeciderHttpClient",
            UnavailableClient,
        ), redirect_stderr(stderr):
            exit_code = main()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            stderr.getvalue().strip(),
            "No decision was produced (IntegrationUnavailableError): "
            "Decider request timed out",
        )

    def test_untyped_client_result_is_rejected(self) -> None:
        client = TestOnlyDecider(result={"category": "high_risk"})
        with self.assertRaises(ValidationError):
            classify_evidence(synthetic_evidence(), decider=client)

    def test_pipeline_uses_pattern_client_decision_as_report_input(self) -> None:
        decision = decision_for(RiskCategory.HIGH_RISK)
        decider = TestOnlyDecider(result=decision)
        reporter = TestOnlyReporter()
        result = investigate(
            InvestigationInput(InputType.EMAIL, "Synthetic test body."),
            decider=decider,
            reporter=reporter,
            review_policy=DecisionReviewPolicy(minimum_confidence=0.5),
        )
        self.assertEqual(result.status, AnalysisStatus.ASSESSED)
        self.assertIs(result.decision, decision)
        self.assertEqual(reporter.received_decisions, [decision])
        self.assertEqual(result.report.text, "Fixture prose that does not set a category.")


if __name__ == "__main__":
    unittest.main()
