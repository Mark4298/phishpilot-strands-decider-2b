"""Streamlit entry point for the PhishPilot local-first triage demo."""

from __future__ import annotations

import math
import os
from collections.abc import Callable
from typing import Any

import streamlit as st

from phishpilot.domain.models import (
    DEFAULT_MAX_CONTENT_CHARS,
    AnalysisStatus,
    DeciderDecision,
    EvidenceReport,
    InputType,
    InvestigationInput,
    InvestigationResult,
    ReportResult,
)
from phishpilot.errors import ValidationError
from phishpilot.evidence.url_parser import MAX_URL_CHARS, MAX_URLS
from phishpilot.integrations.bedrock_reporter import BedrockReportClient
from phishpilot.integrations.decider_http import DeciderHttpClient
from phishpilot.integrations.protocols import DeciderClient, ReportGenerationClient
from phishpilot.pipeline import DecisionReviewPolicy, investigate

DEFAULT_MAX_TEXT_CHARS = DEFAULT_MAX_CONTENT_CHARS


class _LazyReportClient:
    """Defer reporter configuration and credentials until after a Decider result exists."""

    def __init__(self, factory: Callable[[], ReportGenerationClient]) -> None:
        self._factory = factory
        self._client: ReportGenerationClient | None = None

    def generate(
        self, evidence: EvidenceReport, decision: DeciderDecision
    ) -> ReportResult:
        if self._client is None:
            self._client = self._factory()
        return self._client.generate(evidence, decision)


def _bounded_integer(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValidationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be from {minimum} to {maximum}")
    return value


def _bounded_fraction(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValidationError(f"{name} must be numeric") from exc
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValidationError(f"{name} must be between 0 and 1")
    return value


def _show_result(st_api: Any, result: InvestigationResult) -> None:
    st_api.subheader("Evidence")
    if result.evidence.signals:
        for signal in result.evidence.signals:
            st_api.text(f"{signal.code}: {signal.description}\nSource: {signal.provenance}")
    else:
        st_api.text("No static evidence signals were extracted.")
    if result.evidence.missing_information:
        st_api.caption("Information not checked or unavailable:")
        for item in result.evidence.missing_information:
            st_api.text(f"• {item}")

    st_api.subheader("Decider decision")
    if result.decision is None:
        st_api.error("Analysis unavailable. No Decider category was produced.")
        if result.error_message:
            st_api.caption(result.error_message)
    else:
        st_api.markdown(f"**Authoritative typed category:** `{result.decision.category.value}`")
        if result.status is AnalysisStatus.NEEDS_REVIEW:
            st_api.warning(
                "Needs human review. The configured uncertainty policy requested review."
            )
        elif not result.report.available:
            st_api.warning("The Decider decision is available; report generation is unavailable.")
        else:
            st_api.success("The Decider decision and report are available.")

        st_api.write("Decider confidence (not a probability of phishing):")
        st_api.text(str(result.decision.confidence))
        st_api.write("Returned option distribution:")
        for category, value in result.decision.option_distribution.items():
            st_api.text(f"{category}: {value}")

    st_api.subheader("Explanation / report")
    st_api.caption(
        "Generated prose explains the result; it does not change the typed Decider category above."
    )
    if result.report.available:
        # st.text renders the model output as plain text rather than trusted Markdown/HTML.
        st_api.text(result.report.text or "")
    else:
        st_api.warning(result.report.error_message or "Report unavailable.")

    if result.error_message and result.decision is not None:
        st_api.caption(result.error_message)


def main(
    *,
    st_api: Any = st,
    decider_factory: Callable[[], DeciderClient] = DeciderHttpClient,
    reporter_factory: Callable[[], ReportGenerationClient] = BedrockReportClient,
    investigation_runner: Callable[..., InvestigationResult] = investigate,
    review_policy_factory: Callable[[], DecisionReviewPolicy] | None = None,
) -> None:
    """Render the UI; injectable factories keep UI tests offline."""
    st_api.set_page_config(page_title="PhishPilot", page_icon="🛡️", layout="centered")
    st_api.title("PhishPilot")
    st_api.caption(
        "Experimental AI-assisted triage. This is not a definitive verdict or a substitute "
        "for security response."
    )
    st_api.info(
        "Privacy: submitted text is held in the Streamlit session while the page is open; it "
        "is not saved to disk or logged. URLs are analyzed statically and never opened or "
        "resolved. Structured evidence goes to the local Decider; if configured, that "
        "evidence and its decision go to AWS Bedrock for a report, which may incur charges."
    )

    try:
        max_chars = _bounded_integer(
            "PHISHPILOT_MAX_TEXT_CHARS", DEFAULT_MAX_TEXT_CHARS, 1, DEFAULT_MAX_TEXT_CHARS
        )
    except ValidationError as exc:
        st_api.error(str(exc))
        return

    # Keep the mode selector outside the form so changing Email/URL immediately
    # applies the matching input-size limit before a user enters content.
    mode_label = st_api.radio("Input type", ("Email", "URL"), horizontal=True)
    with st_api.form("investigation_form"):
        sender: str | None = None
        subject: str | None = None
        if mode_label == "Email":
            sender = st_api.text_input("Sender (optional)", max_chars=512)
            subject = st_api.text_input("Subject (optional)", max_chars=512)
            input_label = "Email text"
            help_text = (
                f"Plain text only; at most {max_chars} characters, {MAX_URLS} extracted URLs, "
                f"and {MAX_URL_CHARS} characters per URL."
            )
        else:
            input_label = "URL"
            max_chars = min(max_chars, MAX_URL_CHARS)
            help_text = (
                f"URL structure only; at most {max_chars} characters. "
                "The destination will not be visited or resolved."
            )
        content = st_api.text_area(
            input_label,
            max_chars=max_chars,
            height=220,
            help=help_text,
            placeholder="Paste plain-text email content or one URL.",
        )
        acknowledged = st_api.checkbox(
            "I understand analysis uses the local Decider and configured AWS Bedrock may "
            "incur charges."
        )
        submitted = st_api.form_submit_button("Analyze", type="primary", width="stretch")

    if not submitted:
        return
    if not acknowledged:
        st_api.warning(
            "Acknowledge the local analysis and possible Bedrock charge before submitting."
        )
        return

    input_type = InputType.EMAIL if mode_label == "Email" else InputType.URL
    try:
        investigation = InvestigationInput(
            input_type=input_type,
            content=content,
            sender=sender or None if input_type is InputType.EMAIL else None,
            subject=subject or None if input_type is InputType.EMAIL else None,
            max_content_chars=max_chars,
        )
        review_policy = (
            review_policy_factory()
            if review_policy_factory is not None
            else DecisionReviewPolicy(
                minimum_confidence=_bounded_fraction("PHISHPILOT_MIN_DECIDER_CONFIDENCE", 0.55),
                minimum_probability_margin=_bounded_fraction("PHISHPILOT_MIN_DECIDER_MARGIN", 0.05),
            )
        )
        decider = decider_factory()
        # Constructing the Bedrock reporter validates model/region settings. Defer that
        # until the pipeline has a validated Decider result, so reporter configuration
        # errors cannot prevent evidence and a valid category from being returned.
        reporter = _LazyReportClient(reporter_factory)
        with st_api.spinner(
            "Extracting evidence, requesting the Decider choice, then generating a report…"
        ):
            result = investigation_runner(
                investigation,
                decider=decider,
                reporter=reporter,
                review_policy=review_policy,
            )
    except ValidationError as exc:
        st_api.error(f"Input or configuration was rejected: {exc}")
        return
    except Exception:
        st_api.error(
            "PhishPilot could not start the analysis. Check the local Decider endpoint and "
            "application configuration; sensitive exception details are hidden."
        )
        return

    _show_result(st_api, result)


if __name__ == "__main__":
    main()
