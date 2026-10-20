"""Typed integration interfaces; no live provider implementation is included."""

from __future__ import annotations

from typing import Protocol

from phishpilot.domain.models import DeciderDecision, EvidenceReport, ReportResult


class DeciderClient(Protocol):
    """Return a decision obtained from a real, schema-validated Decider response."""

    def decide(self, evidence: EvidenceReport) -> DeciderDecision:
        """Raise an integration error when the real decision is unavailable/invalid."""


class ReportGenerationClient(Protocol):
    """Generate a grounded report after receiving a real immutable decision."""

    def generate(self, evidence: EvidenceReport, decision: DeciderDecision) -> ReportResult:
        """Return report availability explicitly; do not alter the decision."""
