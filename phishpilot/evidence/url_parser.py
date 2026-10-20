"""Bounded, static URL inspection. This module never performs network I/O."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlsplit

from phishpilot.domain.models import EvidenceReport, EvidenceSignal, InputType
from phishpilot.errors import ValidationError

MAX_URLS = 10
MAX_URL_CHARS = 4096
LONG_URL_CHARS = 512
LONG_HOST_CHARS = 253
_URL_PREFIXES = ("https://", "http://", "ftp://", "javascript:", "data:", "mailto:")
_TOKEN_END = frozenset(" \t\r\n\v\f<>\"'`{}\x00")
_TRAILING_PUNCTUATION = ".,;:!?)]}"


def _signal(code: str, description: str, provenance: str = "submitted URL") -> EvidenceSignal:
    return EvidenceSignal(code=code, description=description, provenance=provenance)


def extract_urls(text: str, *, max_urls: int = MAX_URLS) -> tuple[str, ...]:
    """Extract supported URL-like tokens in one bounded pass over already bounded text.

    Finds common web schemes and a small explicit set of non-HTTP schemes so those can
    be reported as unsupported instead of silently ignored. It does not normalize or
    dereference candidates.
    """
    if not isinstance(text, str):
        raise ValidationError("email content must be text")
    if (
        not isinstance(max_urls, int)
        or isinstance(max_urls, bool)
        or not 1 <= max_urls <= MAX_URLS
    ):
        raise ValidationError(f"max_urls must be between 1 and {MAX_URLS}")
    lowered = text.lower()
    found: list[str] = []
    cursor = 0
    while cursor < len(text):
        next_match: tuple[int, str] | None = None
        for prefix in _URL_PREFIXES:
            position = lowered.find(prefix, cursor)
            if position >= 0 and (next_match is None or position < next_match[0]):
                next_match = (position, prefix)
        if next_match is None:
            break
        start, _ = next_match
        end = start
        while end < len(text) and text[end] not in _TOKEN_END:
            end += 1
        candidate = text[start:end].rstrip(_TRAILING_PUNCTUATION)
        if candidate:
            found.append(candidate)
            if len(found) > max_urls:
                raise ValidationError(f"email contains more than the maximum of {max_urls} URLs")
        cursor = max(end, start + 1)
    for candidate in found:
        if len(candidate) > MAX_URL_CHARS:
            raise ValidationError(f"URL exceeds the maximum of {MAX_URL_CHARS} characters")
    return tuple(found)


def analyze_url(url: str, *, max_url_chars: int = MAX_URL_CHARS) -> EvidenceReport:
    """Create structural evidence about a URL string without making a network request."""
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("URL must be a non-empty string")
    if not isinstance(max_url_chars, int) or isinstance(max_url_chars, bool) or max_url_chars < 1:
        raise ValidationError("max_url_chars must be a positive integer")
    if len(url) > max_url_chars:
        raise ValidationError(f"URL exceeds the maximum of {max_url_chars} characters")

    signals: list[EvidenceSignal] = [_signal("url_present", "A URL was supplied.")]
    if len(url) >= LONG_URL_CHARS:
        signals.append(_signal("url_long", "The URL is unusually long."))
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        signals.append(_signal("url_control_characters", "The URL contains control characters."))
        signals.append(
            _signal(
                "url_malformed",
                "The URL was not parsed because it contains control characters.",
            )
        )
        return EvidenceReport(
            InputType.URL, tuple(signals), ("URL structure could not be safely parsed.",)
        )

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        # Accessing .port is required to validate a malformed or out-of-range port.
        port = parsed.port
    except ValueError:
        signals.append(
            _signal(
                "url_malformed", "The URL contains malformed authority or port information."
            )
        )
        return EvidenceReport(
            InputType.URL, tuple(signals), ("URL structure could not be parsed.",)
        )

    if scheme in ("http", "https"):
        signals.append(
            _signal(
                "url_scheme_https" if scheme == "https" else "url_scheme_http",
                f"The URL uses the {scheme.upper()} scheme; scheme alone does not establish "
                "safety or maliciousness.",
            )
        )
    else:
        signals.append(
            _signal(
                "url_scheme_unsupported",
                "The URL does not use a supported HTTP or HTTPS scheme and will not be opened.",
            )
        )

    if not scheme or url[: len(scheme) + 3].casefold() != f"{scheme}://":
        signals.append(
            _signal("url_malformed", "The URL is not an absolute URL with an authority.")
        )
        return EvidenceReport(
            InputType.URL,
            tuple(signals),
            ("A valid absolute HTTP or HTTPS URL was not established.",),
        )
    if not parsed.netloc or not hostname:
        signals.append(_signal("url_malformed", "The URL is missing a host."))
        return EvidenceReport(
            InputType.URL, tuple(signals), ("A URL host was not available for inspection.",)
        )
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        signals.append(
            _signal("url_userinfo", "User information is embedded in the URL authority.")
        )
    if len(hostname) > LONG_HOST_CHARS:
        signals.append(_signal("url_long_host", "The hostname exceeds the usual DNS name length."))
    if port is not None and not 0 <= port <= 65535:
        # urllib.parse already rejects ports outside range; this is defensive.
        signals.append(_signal("url_malformed", "The URL port is outside the valid range."))

    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        signals.append(_signal("url_ip_literal", "The URL host is an IP address literal."))

    labels = hostname.split(".")
    if any(label.lower().startswith("xn--") for label in labels):
        signals.append(
            _signal("url_punycode_host", "The hostname contains an ASCII punycode label.")
        )
    if any(ord(char) > 127 for char in hostname):
        signals.append(_signal("url_unicode_host", "The hostname contains non-ASCII characters."))
    if parsed.fragment:
        signals.append(_signal("url_fragment_present", "The URL contains a fragment identifier."))

    missing: list[str] = []
    if scheme not in ("http", "https"):
        missing.append("This static check does not open unsupported schemes.")
    missing.append(
        "No DNS, page-content, TLS, ownership, reputation, or live scan checks were performed."
    )
    return EvidenceReport(InputType.URL, tuple(signals), tuple(missing))
