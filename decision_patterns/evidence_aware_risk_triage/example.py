"""Run the reusable policy pattern against a real local Decider service.

This module does not synthesize a decision. With no injected client, it always uses
the production loopback HTTP adapter and prints only the validated response it receives.
"""

from __future__ import annotations

import sys

from phishpilot.domain.models import DeciderDecision, EvidenceReport, EvidenceSignal, InputType
from phishpilot.errors import PhishPilotError, ValidationError
from phishpilot.integrations.decider_http import DeciderHttpClient
from phishpilot.integrations.protocols import DeciderClient


def synthetic_evidence() -> EvidenceReport:
    """Return a small, explicitly synthetic evidence report for the runnable example."""
    return EvidenceReport(
        input_type=InputType.EMAIL,
        signals=(
            EvidenceSignal(
                "credential_request",
                "Synthetic example: the message asks the recipient to verify account details.",
                "synthetic example evidence; no real message was analyzed",
            ),
            EvidenceSignal(
                "urgency_language",
                "Synthetic example: the message uses urgent wording.",
                "synthetic example evidence; no real message was analyzed",
            ),
        ),
        missing_information=(
            "No sender-authentication, domain-reputation, or destination-page data is available.",
        ),
    )


def classify_evidence(
    evidence: EvidenceReport,
    *,
    decider: DeciderClient | None = None,
) -> DeciderDecision:
    """Return a validated decision from the configured Decider client.

    The default is the real loopback HTTP adapter, using the same
    ``PHISHPILOT_DECIDER_TIMEOUT_SECONDS`` setting and bounded default as Streamlit.
    An injected client exists only to support offline contract tests or an application's
    existing dependency injection.
    """
    if not isinstance(evidence, EvidenceReport):
        raise ValidationError("evidence must be an EvidenceReport")
    client = decider if decider is not None else DeciderHttpClient()
    if not callable(getattr(client, "decide", None)):
        raise ValidationError("decider must implement the DeciderClient protocol")
    decision = client.decide(evidence)
    if not isinstance(decision, DeciderDecision):
        raise ValidationError("Decider client did not return a validated DeciderDecision")
    return decision


def main() -> int:
    """Submit synthetic structured evidence; never substitute an offline verdict."""
    try:
        decision = classify_evidence(synthetic_evidence())
    except PhishPilotError as exc:
        print(
            f"No decision was produced ({type(exc).__name__}): {exc}",
            file=sys.stderr,
        )
        return 1

    print(f"Selected category: {decision.category.value}")
    print("Actual option distribution:")
    for option, probability in decision.option_distribution.items():
        print(f"  {option}: {probability:.6f}")
    print(f"Decider preference confidence: {decision.confidence:.6f}")
    print("Confidence is not a calibrated probability that the message is phishing.")
    print(f"Model: {decision.model_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
