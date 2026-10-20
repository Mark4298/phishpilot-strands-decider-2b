"""Static extraction of bounded indicators from plain-text email content."""

from __future__ import annotations

from phishpilot.domain.models import EvidenceReport, EvidenceSignal, InputType, InvestigationInput
from phishpilot.errors import ValidationError
from phishpilot.evidence.url_parser import MAX_URLS, analyze_url, extract_urls

_URGENCY_PHRASES = (
    "urgent",
    "immediately",
    "right away",
    "within 24 hours",
    "final warning",
    "account will be closed",
    "action required",
)
_CREDENTIAL_PHRASES = (
    "verify your password",
    "confirm your password",
    "verify your credentials",
    "confirm your credentials",
    "sign in to verify",
    "update your payment details",
    "enter your password",
)


def _contains_phrase(text: str, phrases: tuple[str, ...]) -> bool:
    lowered = text.casefold()
    return any(phrase in lowered for phrase in phrases)


def extract_email_evidence(
    investigation: InvestigationInput,
    *,
    max_urls: int = MAX_URLS,
) -> EvidenceReport:
    """Extract stable, explainable email indicators; does not classify the message."""
    if not isinstance(investigation, InvestigationInput):
        raise ValidationError("investigation must be an InvestigationInput")
    if investigation.input_type is not InputType.EMAIL:
        raise ValidationError("email evidence extraction requires email input")

    content = investigation.content
    signals: list[EvidenceSignal] = []
    missing_information: list[str] = []

    if investigation.sender is not None:
        signals.append(
            EvidenceSignal(
                "email_sender_supplied",
                "A sender value was supplied for this analysis; it has not been authenticated.",
                "user-supplied sender field",
            )
        )
    else:
        missing_information.append("No sender address was supplied for comparison.")
    if investigation.subject is None:
        missing_information.append("No subject was supplied.")

    if _contains_phrase(content, _URGENCY_PHRASES):
        signals.append(
            EvidenceSignal(
                "email_urgency_language",
                "The message contains urgency or consequence language; this alone does not "
                "establish phishing.",
                "message body: matched wording",
            )
        )
    if _contains_phrase(content, _CREDENTIAL_PHRASES):
        signals.append(
            EvidenceSignal(
                "email_credential_request_language",
                "The message asks the reader to verify credentials or account details.",
                "message body: matched wording",
            )
        )

    urls = extract_urls(content, max_urls=max_urls)
    if urls:
        signals.append(
            EvidenceSignal(
                "email_urls_present",
                f"The message contains {len(urls)} URL{'s' if len(urls) != 1 else ''}.",
                "message body",
            )
        )
        for index, url in enumerate(urls, start=1):
            url_report = analyze_url(url)
            for signal in url_report.signals:
                if signal.code == "url_present":
                    continue
                signals.append(
                    EvidenceSignal(
                        signal.code,
                        signal.description,
                        f"message body: URL {index}; {signal.provenance}",
                    )
                )
        missing_information.append("Linked page content and destination behavior were not checked.")
    else:
        missing_information.append(
            "No HTTP, HTTPS, or recognized non-HTTP URL was found in the supplied text."
        )

    if not investigation.sender or investigation.subject is None:
        missing_information.append(
            "Email context is incomplete; the supplied text may omit important headers "
            "or history."
        )
    missing_information.append("Sender authentication and external reputation were not checked.")
    return EvidenceReport(InputType.EMAIL, tuple(signals), tuple(missing_information))
