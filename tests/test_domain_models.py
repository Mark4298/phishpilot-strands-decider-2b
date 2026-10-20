"""Standard-library tests for the offline domain foundation."""

from __future__ import annotations

import json
import unittest

from phishpilot.domain.models import (
    DEFAULT_MAX_CONTENT_CHARS,
    AnalysisStatus,
    DeciderDecision,
    EvidenceReport,
    EvidenceSignal,
    InputType,
    InvestigationInput,
    InvestigationResult,
    ReportResult,
    RiskCategory,
)
from phishpilot.errors import ValidationError


class InvestigationInputTests(unittest.TestCase):
    def test_valid_email_and_url(self) -> None:
        email = InvestigationInput(
            InputType.EMAIL, "Please review this message", "a@example.test", "Notice"
        )
        url = InvestigationInput(InputType.URL, "https://example.test/path")
        self.assertEqual(email.input_type, InputType.EMAIL)
        self.assertEqual(email.sender, "a@example.test")
        self.assertEqual(url.input_type, InputType.URL)

    def test_empty_invalid_and_oversized_values_rejected(self) -> None:
        for content in ("", "   "):
            with self.subTest(content=repr(content)), self.assertRaises(ValidationError):
                InvestigationInput(InputType.EMAIL, content)
        with self.assertRaises(ValidationError):
            InvestigationInput("attachment", "text")  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            InvestigationInput(InputType.URL, "https://example.test", sender="x@example.test")
        with self.assertRaises(ValidationError):
            InvestigationInput(InputType.EMAIL, "12345", max_content_chars=4)

    def test_default_twenty_thousand_character_limit_boundary(self) -> None:
        at_limit = "x" * DEFAULT_MAX_CONTENT_CHARS
        self.assertEqual(
            len(InvestigationInput(InputType.EMAIL, at_limit).content),
            DEFAULT_MAX_CONTENT_CHARS,
        )
        with self.assertRaises(ValidationError):
            InvestigationInput(InputType.EMAIL, at_limit + "x")


class EvidenceAndDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signal = EvidenceSignal("url_present", "One URL was present", "body")
        self.evidence = EvidenceReport(InputType.EMAIL, (self.signal,), ("No remote content",))

    def decision(self, **overrides: object) -> DeciderDecision:
        values: dict[str, object] = {
            "category": RiskCategory.SUSPICIOUS,
            "option_distribution": {
                "likely_benign": 0.1,
                "suspicious": 0.8,
                "high_risk": 0.1,
            },
            "confidence": 0.7,
            "model_id": "verified-model-id",
        }
        values.update(overrides)
        return DeciderDecision(**values)  # type: ignore[arg-type]

    def test_supported_and_unsupported_status_and_category(self) -> None:
        self.assertEqual(AnalysisStatus("assessed"), AnalysisStatus.ASSESSED)
        self.assertEqual(RiskCategory("high_risk"), RiskCategory.HIGH_RISK)
        with self.assertRaises(ValidationError):
            self.decision(category="unknown")
        with self.assertRaises(ValidationError):
            InvestigationResult(self.evidence, "guessed", None, ReportResult(False, error_code="x"))  # type: ignore[arg-type]

    def test_distribution_confidence_and_selected_category_validated(self) -> None:
        self.decision()
        invalid = [
            {"likely_benign": 0.2, "suspicious": 0.2, "high_risk": 0.2},
            {"likely_benign": 0.1, "suspicious": 0.8, "other": 0.1},
            {"likely_benign": 0.1, "suspicious": float("nan"), "high_risk": 0.1},
        ]
        for distribution in invalid:
            with self.subTest(distribution=distribution), self.assertRaises(ValidationError):
                self.decision(option_distribution=distribution)
        for confidence in (-0.1, 1.1, float("inf")):
            with self.subTest(confidence=confidence), self.assertRaises(ValidationError):
                self.decision(confidence=confidence)
        with self.assertRaises(ValidationError):
            self.decision(option_distribution={"likely_benign": 1.0})

    def test_signal_provenance_is_required(self) -> None:
        with self.assertRaises(ValidationError):
            EvidenceSignal("code", "description", " ")

    def test_decider_usage_and_latency_metadata_are_validated(self) -> None:
        decision = self.decision(
            usage={"input_tokens": 12, "output_tokens": 3},
            server_latency_ms=4.25,
        )
        self.assertEqual(dict(decision.usage or {}), {"input_tokens": 12, "output_tokens": 3})
        self.assertEqual(decision.server_latency_ms, 4.25)
        with self.assertRaises(TypeError):
            (decision.usage or {})["input_tokens"] = 99  # type: ignore[index]
        for usage in (
            {"input_tokens": -1},
            {"output_tokens": True},
            {"other": 1},
        ):
            with self.subTest(usage=usage), self.assertRaises(ValidationError):
                self.decision(usage=usage)
        for latency in (-1, float("nan"), float("inf"), True):
            with self.subTest(latency=latency), self.assertRaises(ValidationError):
                self.decision(server_latency_ms=latency)


class ResultStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = EvidenceReport(InputType.URL)
        self.decision = DeciderDecision(
            RiskCategory.SUSPICIOUS,
            {"likely_benign": 0.1, "suspicious": 0.8, "high_risk": 0.1},
            0.7,
            "verified-model-id",
        )

    def test_missing_report_is_explicit(self) -> None:
        unavailable_report = ReportResult(False, error_code="bedrock_unavailable")
        result = InvestigationResult(
            self.evidence,
            AnalysisStatus.NEEDS_REVIEW,
            self.decision,
            unavailable_report,
            timings_ms={"decider": 12.5},
        )
        self.assertFalse(result.report.available)
        self.assertEqual(result.status, AnalysisStatus.NEEDS_REVIEW)

    def test_missing_decision_and_failure_are_not_success(self) -> None:
        unavailable = InvestigationResult(
            self.evidence,
            AnalysisStatus.ANALYSIS_UNAVAILABLE,
            None,
            ReportResult(False, error_code="decider_unavailable"),
            error_code="decider_unavailable",
        )
        self.assertIsNone(unavailable.decision)
        with self.assertRaises(ValidationError):
            InvestigationResult(
                self.evidence,
                AnalysisStatus.ASSESSED,
                None,
                ReportResult(False, error_code="missing"),
            )
        with self.assertRaises(ValidationError):
            InvestigationResult(
                self.evidence,
                AnalysisStatus.ANALYSIS_UNAVAILABLE,
                self.decision,
                ReportResult(True, text="unexpected successful report"),
                error_code="invalid",
            )
        preserved = InvestigationResult(
            self.evidence,
            AnalysisStatus.ANALYSIS_UNAVAILABLE,
            self.decision,
            ReportResult(False, error_code="report_unavailable"),
            error_code="report_unavailable",
        )
        self.assertIs(preserved.decision, self.decision)
        with self.assertRaises(ValidationError):
            InvestigationResult(
                self.evidence,
                AnalysisStatus.ASSESSED,
                self.decision,
                ReportResult(False, error_code="invalid"),
            )

    def test_serialization_is_json_compatible(self) -> None:
        result = InvestigationResult(
            self.evidence,
            AnalysisStatus.ASSESSED,
            self.decision,
            ReportResult(True, text="Evidence summary"),
        )
        payload = json.loads(json.dumps(result.to_dict()))
        self.assertEqual(payload["status"], "assessed")
        self.assertEqual(payload["decision"]["category"], "suspicious")
        self.assertEqual(payload["decision"]["option_distribution"]["suspicious"], 0.8)


if __name__ == "__main__":
    unittest.main()
