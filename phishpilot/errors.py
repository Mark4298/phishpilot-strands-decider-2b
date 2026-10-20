"""Typed application errors for validation and unavailable integrations."""


class PhishPilotError(Exception):
    """Base exception for expected application-level errors."""


class ValidationError(PhishPilotError, ValueError):
    """Raised when untrusted input or a boundary object is invalid."""


class IntegrationUnavailableError(PhishPilotError):
    """Raised when a real external model integration cannot be used."""


class InvalidIntegrationResponseError(PhishPilotError):
    """Raised when an integration response does not match its verified schema."""
