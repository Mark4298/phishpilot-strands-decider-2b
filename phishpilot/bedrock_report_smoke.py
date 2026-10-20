"""One-request Bedrock reporter smoke test using synthetic evidence only.

This command never invokes Strands Decider. Its typed decision is a local fixture, not
an inference result. Running with ``--confirm-live-call`` sends one Bedrock request and
may consume AWS credits or incur charges.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from phishpilot.domain.models import (
    DeciderDecision,
    EvidenceReport,
    EvidenceSignal,
    InputType,
    RiskCategory,
)
from phishpilot.integrations.bedrock_reporter import BedrockReportClient


def _synthetic_evidence() -> EvidenceReport:
    return EvidenceReport(
        InputType.EMAIL,
        (
            EvidenceSignal(
                "url.scheme_https",
                "Synthetic fixture: an HTTPS URL was present in the message.",
                "smoke_test_fixture",
            ),
        ),
        ("Synthetic fixture: sender authentication was not evaluated.",),
    )


def _synthetic_decision() -> DeciderDecision:
    return DeciderDecision(
        RiskCategory.SUSPICIOUS,
        {"likely_benign": 0.1, "suspicious": 0.8, "high_risk": 0.1},
        0.8,
        "synthetic-smoke-test-fixture",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishpilot-bedrock-smoke", description=__doc__)
    parser.add_argument(
        "--confirm-live-call",
        action="store_true",
        help="confirm one real Bedrock report request that may consume credits or incur charges",
    )
    args = parser.parse_args(argv)
    if not args.confirm_live_call:
        parser.error("one live Bedrock request requires --confirm-live-call")

    required_environment = (
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_REGION",
        "BEDROCK_MODEL_ID",
    )
    missing = [name for name in required_environment if not os.getenv(name, "").strip()]
    if missing:
        print(
            f"Smoke test not sent; missing process settings: {', '.join(missing)}.",
            file=sys.stderr,
        )
        return 2
    try:
        reporter = BedrockReportClient()
    except ValueError as exc:
        print(f"Smoke test not sent; invalid reporter configuration: {exc}", file=sys.stderr)
        return 2

    print("Sending one report request with synthetic evidence and a synthetic decision fixture.")
    print("This is not Decider inference; the request may consume AWS credits or incur charges.")
    result = reporter.generate(_synthetic_evidence(), _synthetic_decision())
    if not result.available:
        print(
            f"Report unavailable: {result.error_message or result.error_code}",
            file=sys.stderr,
        )
        return 1
    print("Synthetic-input Bedrock report:")
    print(result.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
