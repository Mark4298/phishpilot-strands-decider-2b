"""Single-pass orchestration for evidence, a real Decider and an optional report."""

from __future__ import annotations

import math
from dataclasses import dataclass
from time import perf_counter

from phishpilot.domain.models import (
    AnalysisStatus,
    DeciderDecision,
    EvidenceReport,
    InputType,
    InvestigationInput,
    InvestigationResult,
    ReportResult,
)
from phishpilot.errors import (
    IntegrationUnavailableError,
    InvalidIntegrationResponseError,
    ValidationError,
)
from phishpilot.evidence.email_parser import extract_email_evidence
from phishpilot.evidence.url_parser import analyze_url
from phishpilot.integrations.protocols import DeciderClient, ReportGenerationClient


@dataclass(frozen=True, slots=True)
class DecisionReviewPolicy:
    """Explicit confidence and option-margin thresholds for requesting review.

    These are application policy settings, not claims about phishing probability or
    validated domain performance. Callers must choose values deliberately.
    """

    minimum_confidence: float
    minimum_probability_margin: float = 0.0

    def __post_init__(self) -> None:
        for name, value in (
            ("minimum_confidence", self.minimum_confidence),
            ("minimum_probability_margin", self.minimum_probability_margin),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValidationError(f"{name} must be numeric")
            if not math.isfinite(float(value)) or not 0.0 <= value <= 1.0:
                raise ValidationError(f"{name} must be between 0 and 1")

    def requires_review(self, decision: DeciderDecision) -> bool:
        if not isinstance(decision, DeciderDecision):
            raise ValidationError("decision must be a validated DeciderDecision")
        top_two = sorted(decision.option_distribution.values(), reverse=True)[:2]
        margin = top_two[0] - top_two[1]
        return (
            decision.confidence < self.minimum_confidence
            or margin < self.minimum_probability_margin
        )


def _elapsed_ms(started: float) -> float:
    return max(0.0, (perf_counter() - started) * 1000.0)


def _evidence_for(investigation: InvestigationInput) -> EvidenceReport:
    if investigation.input_type is InputType.EMAIL:
        return extract_email_evidence(investigation)
    if investigation.input_type is InputType.URL:
        return analyze_url(investigation.content)
    raise ValidationError("unsupported investigation input type")


def _decider_error(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, IntegrationUnavailableError):
        if str(exc) == "Decider request timed out":
            return (
                "decider_timeout",
                "The Decider exceeded the configured request timeout; no decision was produced.",
            )
        return (
            "decider_unavailable",
            "The Decider service is unavailable; no decision was produced.",
        )
    if isinstance(exc, (InvalidIntegrationResponseError, ValidationError)):
        return (
            "decider_invalid_response",
            "The Decider response did not pass validation; no decision was produced.",
        )
    return "decider_error", "The Decider request failed; no decision was produced."


def _implements_client(value: object, method_name: str) -> bool:
    """Check the structural client boundary without runtime-checking Protocol classes."""
    return callable(getattr(value, method_name, None))


def investigate(
    investigation: InvestigationInput,
    *,
    decider: DeciderClient,
    reporter: ReportGenerationClient,
    review_policy: DecisionReviewPolicy,
) -> InvestigationResult:
    """Run one bounded evidence pass, one real decision call, then one report call.

    Invalid caller input and evidence-extraction errors are raised as typed validation
    errors before either model client is called. Integration failures become explicit
    unavailable results; no category is guessed or substituted.
    """
    if not isinstance(investigation, InvestigationInput):
        raise ValidationError("investigation must be an InvestigationInput")
    if not _implements_client(decider, "decide"):
        raise ValidationError("decider must implement the DeciderClient protocol")
    if not _implements_client(reporter, "generate"):
        raise ValidationError("reporter must implement the ReportGenerationClient protocol")
    if not isinstance(review_policy, DecisionReviewPolicy):
        raise ValidationError("review_policy must be an explicit DecisionReviewPolicy")

    timings: dict[str, float] = {}
    started = perf_counter()
    evidence = _evidence_for(investigation)
    timings["evidence"] = _elapsed_ms(started)

    started = perf_counter()
    try:
        decision = decider.decide(evidence)
        if not isinstance(decision, DeciderDecision):
            raise InvalidIntegrationResponseError("Decider returned an unsupported response object")
    except Exception as exc:
        timings["decider"] = _elapsed_ms(started)
        error_code, error_message = _decider_error(exc)
        return InvestigationResult(
            evidence=evidence,
            status=AnalysisStatus.ANALYSIS_UNAVAILABLE,
            decision=None,
            report=ReportResult(False, error_code=error_code, error_message=error_message),
            timings_ms=timings,
            error_code=error_code,
            error_message=error_message,
        )
    timings["decider"] = _elapsed_ms(started)

    needs_review = review_policy.requires_review(decision)
    started = perf_counter()
    try:
        report = reporter.generate(evidence, decision)
        if not isinstance(report, ReportResult):
            raise InvalidIntegrationResponseError(
                "reporter returned an unsupported response object"
            )
    except Exception:
        report = ReportResult(
            False,
            error_code="report_unavailable",
            error_message=(
                "Report generation failed; the validated evidence and Decider decision "
                "are preserved."
            ),
        )
    timings["report"] = _elapsed_ms(started)

    if needs_review:
        status = AnalysisStatus.NEEDS_REVIEW
        error_code = None if report.available else report.error_code or "report_unavailable"
        error_message = None if report.available else report.error_message
    elif report.available:
        status = AnalysisStatus.ASSESSED
        error_code = None
        error_message = None
    else:
        status = AnalysisStatus.ANALYSIS_UNAVAILABLE
        error_code = report.error_code or "report_unavailable"
        error_message = report.error_message or "Report generation is unavailable."

    return InvestigationResult(
        evidence=evidence,
        status=status,
        decision=decision,
        report=report,
        timings_ms=timings,
        error_code=error_code,
        error_message=error_message,
    )
