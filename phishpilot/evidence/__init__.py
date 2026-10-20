"""Deterministic static evidence extraction with no network access."""

from phishpilot.evidence.email_parser import extract_email_evidence
from phishpilot.evidence.url_parser import analyze_url, extract_urls

__all__ = ["analyze_url", "extract_email_evidence", "extract_urls"]
