"""Validated, standard-library domain models for the PhishPilot pipeline."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from enum import Enum
from types import MappingProxyType
from typing import Any

from phishpilot.errors import ValidationError


class InputType(str, Enum):  # noqa: UP042 - preserve existing Enum stringification behavior
    EMAIL = "email"
    URL = "url"


class RiskCategory(str, Enum):  # noqa: UP042 - preserve existing Enum stringification behavior
    LIKELY_BENIGN = "likely_benign"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"


class AnalysisStatus(str, Enum):  # noqa: UP042 - preserve existing Enum stringification behavior
    ASSESSED = "assessed"
    NEEDS_REVIEW = "needs_review"
    ANALYSIS_UNAVAILABLE = "analysis_unavailable"


DEFAULT_MAX_CONTENT_CHARS = 20_000


def _non_empty_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must be a non-empty string")
    return value


def _optional_text(value: str | None, name: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{name} must be a string or None")


@dataclass(frozen=True, slots=True)
class InvestigationInput:
    input_type: InputType
    content: str
    sender: str | None = None
    subject: str | None = None
    max_content_chars: int = DEFAULT_MAX_CONTENT_CHARS

    def __post_init__(self) -> None:
        try:
            normalized_type = InputType(self.input_type)
        except (TypeError, ValueError) as exc:
            raise ValidationError("input_type must be 'email' or 'url'") from exc
        object.__setattr__(self, "input_type", normalized_type)
        _non_empty_text(self.content, "content")
        if not self.content.strip():
            raise ValidationError("content must not be empty or whitespace only")
        if not isinstance(self.max_content_chars, int) or isinstance(self.max_content_chars, bool):
            raise ValidationError("max_content_chars must be a positive integer")
        if self.max_content_chars <= 0:
            raise ValidationError("max_content_chars must be a positive integer")
        if len(self.content) > self.max_content_chars:
            raise ValidationError("content exceeds max_content_chars")
        _optional_text(self.sender, "sender")
        _optional_text(self.subject, "subject")
        if normalized_type is InputType.URL and (
            self.sender is not None or self.subject is not None
        ):
            raise ValidationError("sender and subject are only valid for email input")


@dataclass(frozen=True, slots=True)
class EvidenceSignal:
    code: str
    description: str
    provenance: str

    def __post_init__(self) -> None:
        _non_empty_text(self.code, "code")
        _non_empty_text(self.description, "description")
        _non_empty_text(self.provenance, "provenance")


@dataclass(frozen=True, slots=True)
class EvidenceReport:
    input_type: InputType
    signals: tuple[EvidenceSignal, ...] = ()
    missing_information: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "input_type", InputType(self.input_type))
        except (TypeError, ValueError) as exc:
            raise ValidationError("input_type must be 'email' or 'url'") from exc
        if not isinstance(self.signals, tuple) or any(
            not isinstance(signal, EvidenceSignal) for signal in self.signals
        ):
            raise ValidationError("signals must be a tuple of EvidenceSignal values")
        if not isinstance(self.missing_information, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.missing_information
        ):
            raise ValidationError("missing_information must contain non-empty strings")


@dataclass(frozen=True, slots=True)
class DeciderDecision:
    """A validated decision received from a real Decider integration."""

    category: RiskCategory
    option_distribution: Mapping[str, float]
    confidence: float
    model_id: str
    usage: Mapping[str, int] | None = None
    server_latency_ms: float | None = None

    def __post_init__(self) -> None:
        try:
            category = RiskCategory(self.category)
        except (TypeError, ValueError) as exc:
            raise ValidationError("category must be a supported risk category") from exc
        object.__setattr__(self, "category", category)
        _non_empty_text(self.model_id, "model_id")
        if not isinstance(self.option_distribution, Mapping) or not self.option_distribution:
            raise ValidationError("option_distribution must be a non-empty mapping")
        supported_options = {item.value for item in RiskCategory}
        if set(self.option_distribution) != supported_options:
            raise ValidationError(
                "option_distribution must contain exactly the supported risk categories"
            )
        distribution: dict[str, float] = {}
        for option, probability in self.option_distribution.items():
            if not isinstance(option, str) or not option.strip():
                raise ValidationError("distribution option names must be non-empty strings")
            if isinstance(probability, bool) or not isinstance(probability, (int, float)):
                raise ValidationError("distribution probabilities must be numeric")
            try:
                numeric_probability = float(probability)
            except (OverflowError, ValueError) as exc:
                raise ValidationError("distribution probabilities must be finite numbers") from exc
            if not math.isfinite(numeric_probability) or not 0.0 <= numeric_probability <= 1.0:
                raise ValidationError(
                    "distribution probabilities must be finite values from 0 to 1"
                )
            distribution[option] = numeric_probability
        if not math.isclose(sum(distribution.values()), 1.0, abs_tol=1e-4):
            raise ValidationError("option_distribution probabilities must sum to 1")
        if category.value not in distribution:
            raise ValidationError("option_distribution must include the selected category")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise ValidationError("confidence must be numeric")
        try:
            confidence = float(self.confidence)
        except (OverflowError, ValueError) as exc:
            raise ValidationError("confidence must be a finite number") from exc
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValidationError("confidence must be a finite value from 0 to 1")
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "option_distribution", MappingProxyType(distribution))
        if self.usage is not None:
            if not isinstance(self.usage, Mapping):
                raise ValidationError("usage must be a mapping or None")
            allowed_usage_fields = {"input_tokens", "output_tokens"}
            if not set(self.usage).issubset(allowed_usage_fields):
                raise ValidationError("usage contains unsupported fields")
            normalized_usage: dict[str, int] = {}
            for field_name, count in self.usage.items():
                if field_name not in allowed_usage_fields:
                    raise ValidationError("usage contains unsupported fields")
                if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                    raise ValidationError("usage token counts must be non-negative integers")
                normalized_usage[field_name] = count
            object.__setattr__(self, "usage", MappingProxyType(normalized_usage))
        if self.server_latency_ms is not None:
            if (
                isinstance(self.server_latency_ms, bool)
                or not isinstance(self.server_latency_ms, (int, float))
            ):
                raise ValidationError("server_latency_ms must be numeric or None")
            try:
                latency = float(self.server_latency_ms)
            except (OverflowError, ValueError) as exc:
                raise ValidationError("server_latency_ms must be a finite number") from exc
            if not math.isfinite(latency) or latency < 0:
                raise ValidationError("server_latency_ms must be finite and non-negative")
            object.__setattr__(self, "server_latency_ms", latency)


@dataclass(frozen=True, slots=True)
class ReportResult:
    available: bool
    text: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.available, bool):
            raise ValidationError("available must be a bool")
        _optional_text(self.text, "text")
        _optional_text(self.error_code, "error_code")
        _optional_text(self.error_message, "error_message")
        if self.available and (self.text is None or not self.text.strip()):
            raise ValidationError("an available report must contain non-empty text")
        if self.available and (self.error_code is not None or self.error_message is not None):
            raise ValidationError("an available report cannot contain an error")
        if not self.available and self.text is not None:
            raise ValidationError("an unavailable report cannot contain generated text")
        if not self.available and self.error_code is None and self.error_message is None:
            raise ValidationError("an unavailable report must explain the error")


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    evidence: EvidenceReport
    status: AnalysisStatus
    decision: DeciderDecision | None
    report: ReportResult
    timings_ms: Mapping[str, float] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, EvidenceReport):
            raise ValidationError("evidence must be an EvidenceReport")
        try:
            status = AnalysisStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ValidationError("status must be a supported AnalysisStatus") from exc
        object.__setattr__(self, "status", status)
        if self.decision is not None and not isinstance(self.decision, DeciderDecision):
            raise ValidationError("decision must be a DeciderDecision or None")
        if not isinstance(self.report, ReportResult):
            raise ValidationError("report must be a ReportResult")
        if status is AnalysisStatus.ANALYSIS_UNAVAILABLE:
            if self.error_code is None and self.error_message is None:
                raise ValidationError("analysis_unavailable must include an error")
            if self.report.available:
                raise ValidationError("analysis_unavailable must have an unavailable report")
        elif self.decision is None:
            raise ValidationError("assessed/review results require a real DeciderDecision")
        if status is AnalysisStatus.ASSESSED and not self.report.available:
            raise ValidationError("assessed results require an available report")
        if status is AnalysisStatus.NEEDS_REVIEW and self.decision is None:
            raise ValidationError("needs_review requires a real DeciderDecision")
        _optional_text(self.error_code, "error_code")
        _optional_text(self.error_message, "error_message")
        if not isinstance(self.timings_ms, Mapping):
            raise ValidationError("timings_ms must be a mapping")
        normalized_timings: dict[str, float] = {}
        for component, duration in self.timings_ms.items():
            if not isinstance(component, str) or not component.strip():
                raise ValidationError("timing component names must be non-empty strings")
            if isinstance(duration, bool) or not isinstance(duration, (int, float)):
                raise ValidationError("timing values must be numeric")
            numeric_duration = float(duration)
            if not math.isfinite(numeric_duration) or numeric_duration < 0:
                raise ValidationError("timing values must be finite and non-negative")
            normalized_timings[component] = numeric_duration
        object.__setattr__(self, "timings_ms", MappingProxyType(normalized_timings))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation without persisting input content."""
        return _to_primitive(self)


def _to_primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {
            item.name: _to_primitive(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _to_primitive(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_to_primitive(item) for item in value]
    if isinstance(value, list):
        return [_to_primitive(item) for item in value]
    return value
