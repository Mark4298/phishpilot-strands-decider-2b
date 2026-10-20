"""Protocol/adapter tests against a local test server, not real model inference."""

from __future__ import annotations

import json
import threading
import time
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from phishpilot.domain.models import (
    DeciderDecision,
    EvidenceReport,
    EvidenceSignal,
    InputType,
    InvestigationInput,
)
from phishpilot.errors import (
    IntegrationUnavailableError,
    InvalidIntegrationResponseError,
    ValidationError,
)
from phishpilot.evidence.email_parser import extract_email_evidence
from phishpilot.integrations.decider_http import (
    _CATEGORY_CRITERIA,
    _QUESTION_INSTRUCTIONS,
    MAX_REQUEST_BYTES,
    DeciderHttpClient,
)


def response_payload(
    category: str = "suspicious",
    probabilities: dict[str, object] | None = None,
    confidence: object = 0.7,
) -> dict[str, object]:
    default_probabilities: dict[str, object] = {
        "likely_benign": 0.1,
        "suspicious": 0.8,
        "high_risk": 0.1,
    }
    return {
        "model": "local-protocol-test-model",
        "answers": {
            "risk_category": {
                "type": "choice",
                "choice": category,
                "probabilities": probabilities or default_probabilities,
                "confidence": confidence,
            }
        },
        "usage": {"input_tokens": 17, "output_tokens": 3},
        "latency_ms": 2.5,
    }


@contextmanager
def local_decider_server(
    *,
    status: int = 200,
    body: bytes | None = None,
    content_type: str = "application/json",
    delay_seconds: float = 0.0,
    location: str | None = None,
) -> Iterator[tuple[str, ThreadingHTTPServer]]:
    """Serve controlled protocol data on loopback for adapter tests only."""
    payload = body if body is not None else json.dumps(response_payload()).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.server.captured_path = self.path  # type: ignore[attr-defined]
            self.server.captured_method = self.command  # type: ignore[attr-defined]
            self.server.captured_headers = dict(self.headers.items())  # type: ignore[attr-defined]
            content_length = int(self.headers.get("Content-Length", "0"))
            self.server.captured_body = self.rfile.read(content_length)  # type: ignore[attr-defined]
            if delay_seconds:
                time.sleep(delay_seconds)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if location is not None:
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield endpoint, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def evidence_report() -> EvidenceReport:
    return EvidenceReport(
        input_type=InputType.EMAIL,
        signals=(
            EvidenceSignal(
                "email_urgency_language",
                "Urgency wording was found; this alone does not establish phishing.",
                "message body: matched wording",
            ),
        ),
        missing_information=("Sender authentication was not checked.",),
    )


class DeciderHttpProtocolAdapterTests(unittest.TestCase):
    """Local HTTP fixtures test wire contracts; none represents model inference."""

    def test_valid_response_maps_to_domain_and_request_matches_pattern(self) -> None:
        evidence = evidence_report()
        with local_decider_server() as (endpoint, server):
            client = DeciderHttpClient(endpoint, timeout_seconds=1.0, model="configured-test-model")
            decision = client.decide(evidence)

        self.assertIsInstance(decision, DeciderDecision)
        self.assertEqual(decision.category.value, "suspicious")
        self.assertEqual(
            dict(decision.option_distribution),
            {"likely_benign": 0.1, "suspicious": 0.8, "high_risk": 0.1},
        )
        self.assertEqual(decision.confidence, 0.7)
        self.assertEqual(decision.model_id, "local-protocol-test-model")
        self.assertEqual(dict(decision.usage or {}), {"input_tokens": 17, "output_tokens": 3})
        self.assertEqual(decision.server_latency_ms, 2.5)
        self.assertEqual(server.captured_method, "POST")  # type: ignore[attr-defined]
        self.assertEqual(server.captured_path, "/v1/systemone")  # type: ignore[attr-defined]
        headers = server.captured_headers  # type: ignore[attr-defined]
        self.assertEqual(headers["Content-Type"], "application/json")
        request_data = json.loads(server.captured_body)  # type: ignore[attr-defined]
        self.assertEqual(request_data["model"], "configured-test-model")
        self.assertEqual(
            set(request_data), {"model", "state", "questions"}
        )
        self.assertEqual(
            request_data["state"],
            {
                "input_type": "email",
                "signals": [
                    {
                        "code": "email_urgency_language",
                        "description": (
                            "Urgency wording was found; this alone does not establish phishing."
                        ),
                        "provenance": "message body: matched wording",
                    }
                ],
                "missing_information": ["Sender authentication was not checked."],
            },
        )
        question = request_data["questions"]["risk_category"]
        pattern_path = (
            Path(__file__).parents[1]
            / "decision_patterns"
            / "evidence_aware_risk_triage"
            / "question.json"
        )
        pattern_question = json.loads(pattern_path.read_text(encoding="utf-8"))
        self.assertEqual(question["type"], pattern_question["type"])
        self.assertEqual(question["instructions"], pattern_question["instructions"])
        self.assertEqual(question["criteria"], pattern_question["criteria"])
        self.assertEqual(question["instructions"], _QUESTION_INSTRUCTIONS)
        self.assertEqual(question["criteria"], _CATEGORY_CRITERIA)

    def test_decider_payload_excludes_raw_email_sender_subject_and_url(self) -> None:
        original = InvestigationInput(
            InputType.EMAIL,
            "PRIVATE_BODY_MARKER https://private-host-marker.example/path",
            sender="PRIVATE_SENDER_MARKER@example.test",
            subject="PRIVATE_SUBJECT_MARKER",
        )
        evidence = extract_email_evidence(original)
        with local_decider_server() as (endpoint, server):
            DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence)

        payload = json.loads(server.captured_body)  # type: ignore[attr-defined]
        serialized = json.dumps(payload)
        for marker in (
            "PRIVATE_BODY_MARKER",
            "private-host-marker.example",
            "PRIVATE_SENDER_MARKER",
            "PRIVATE_SUBJECT_MARKER",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, serialized)
        self.assertEqual(payload["state"]["input_type"], "email")
        self.assertIn("email_urls_present", {item["code"] for item in payload["state"]["signals"]})

    def test_all_supported_categories_are_preserved(self) -> None:
        distributions = {
            "likely_benign": {"likely_benign": 0.8, "suspicious": 0.1, "high_risk": 0.1},
            "suspicious": {"likely_benign": 0.1, "suspicious": 0.8, "high_risk": 0.1},
            "high_risk": {"likely_benign": 0.1, "suspicious": 0.1, "high_risk": 0.8},
        }
        for category, distribution in distributions.items():
            with self.subTest(category=category):
                body = json.dumps(
                    response_payload(category, distribution, 0.7)
                ).encode("utf-8")
                with local_decider_server(body=body) as (endpoint, _):
                    decision = DeciderHttpClient(endpoint, timeout_seconds=1).decide(
                        evidence_report()
                    )
                self.assertEqual(decision.category.value, category)
                self.assertEqual(dict(decision.option_distribution), distribution)

    def test_missing_required_choice_fields_are_rejected(self) -> None:
        for field in ("choice", "probabilities", "confidence"):
            with self.subTest(field=field):
                body_data = response_payload()
                del body_data["answers"]["risk_category"][field]  # type: ignore[index]
                with local_decider_server(body=json.dumps(body_data).encode()) as (endpoint, _):
                    with self.assertRaises(InvalidIntegrationResponseError):
                        DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())

    def test_missing_top_level_model_answers_or_usage_is_rejected(self) -> None:
        for field in ("model", "answers", "usage"):
            with self.subTest(field=field):
                body_data = response_payload()
                del body_data[field]
                with local_decider_server(body=json.dumps(body_data).encode()) as (endpoint, _):
                    with self.assertRaises(InvalidIntegrationResponseError):
                        DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())

    def test_unsupported_choice_and_probability_keys_are_rejected(self) -> None:
        invalid_values = [
            response_payload("unknown"),
            response_payload(
                probabilities={"likely_benign": 0.1, "suspicious": 0.8, "other": 0.1}
            ),
            response_payload(probabilities={"likely_benign": 0.1, "suspicious": 0.9}),
        ]
        for value in invalid_values:
            with self.subTest(value=value):
                with local_decider_server(body=json.dumps(value).encode()) as (endpoint, _):
                    with self.assertRaises(InvalidIntegrationResponseError):
                        DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())

    def test_non_finite_boolean_out_of_range_and_invalid_numbers_are_rejected(self) -> None:
        bad_cases = [
            response_payload(
                probabilities={
                    "likely_benign": float("nan"),
                    "suspicious": 0.8,
                    "high_risk": 0.1,
                }
            ),
            response_payload(
                probabilities={
                    "likely_benign": 0.1,
                    "suspicious": float("inf"),
                    "high_risk": 0.1,
                }
            ),
            response_payload(
                probabilities={"likely_benign": True, "suspicious": 0.8, "high_risk": 0.1}
            ),
            response_payload(confidence=float("nan")),
            response_payload(confidence=float("inf")),
            response_payload(confidence=True),
            response_payload(confidence=1.1),
        ]
        for value in bad_cases:
            with self.subTest(value=value):
                # json.dumps emits non-standard NaN/Infinity tokens; the adapter must reject them.
                with local_decider_server(body=json.dumps(value).encode()) as (endpoint, _):
                    with self.assertRaises(InvalidIntegrationResponseError):
                        DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())

    def test_invalid_json_and_non_json_content_type_are_rejected(self) -> None:
        with local_decider_server(body=b"not-json") as (endpoint, _):
            with self.assertRaises(InvalidIntegrationResponseError):
                DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())
        with local_decider_server(content_type="text/plain") as (endpoint, _):
            with self.assertRaises(InvalidIntegrationResponseError):
                DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())

    def test_invalid_usage_counts_and_latency_are_rejected(self) -> None:
        bad_responses = []
        for usage in (
            {"input_tokens": -1, "output_tokens": 2},
            {"input_tokens": True, "output_tokens": 2},
            {"input_tokens": 1.5, "output_tokens": 2},
        ):
            value = response_payload()
            value["usage"] = usage
            bad_responses.append(value)
        for latency in (-1, float("nan"), float("inf"), True):
            value = response_payload()
            value["latency_ms"] = latency
            bad_responses.append(value)
        for value in bad_responses:
            with self.subTest(value=value):
                with local_decider_server(body=json.dumps(value).encode()) as (endpoint, _):
                    with self.assertRaises(InvalidIntegrationResponseError):
                        DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())

    def test_http_422_and_server_errors_are_unavailable(self) -> None:
        for status in (422, 500):
            with self.subTest(status=status):
                with local_decider_server(
                    status=status, body=b'{"detail":"not exposed"}'
                ) as (endpoint, _):
                    with self.assertRaisesRegex(
                        IntegrationUnavailableError, rf"HTTP status {status}"
                    ) as raised:
                        DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())
                self.assertNotIn("not exposed", str(raised.exception))

    def test_loopback_timeout_and_connection_failures_are_typed(self) -> None:
        with local_decider_server(delay_seconds=0.2) as (endpoint, _):
            with self.assertRaisesRegex(
                IntegrationUnavailableError, "^Decider request timed out$"
            ):
                DeciderHttpClient(endpoint, timeout_seconds=0.05).decide(evidence_report())

        with ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler) as unused_server:
            unused_port = unused_server.server_address[1]
        with self.assertRaises(IntegrationUnavailableError):
            DeciderHttpClient(f"http://127.0.0.1:{unused_port}", timeout_seconds=0.2).decide(
                evidence_report()
            )

    def test_remote_and_malformed_endpoint_values_are_rejected(self) -> None:
        for endpoint in (
            "https://example.com",
            "http://127.0.0.1.evil.test:8000",
            "http://user:pass@127.0.0.1:8000",
            "http://127.0.0.1:8000/other",
            "http://127.0.0.1:99999",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValidationError):
                DeciderHttpClient(endpoint)

    def test_redirects_are_not_followed(self) -> None:
        with local_decider_server(status=302, location="http://example.com/") as (endpoint, server):
            with self.assertRaises(IntegrationUnavailableError):
                DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())
            self.assertEqual(server.captured_path, "/v1/systemone")  # type: ignore[attr-defined]

    def test_loopback_request_does_not_use_environment_proxy(self) -> None:
        from unittest.mock import patch

        with local_decider_server() as (endpoint, _):
            with patch.dict(
                "os.environ",
                {
                    "HTTP_PROXY": "http://192.0.2.1:9",
                    "HTTPS_PROXY": "http://192.0.2.1:9",
                    "ALL_PROXY": "http://192.0.2.1:9",
                    "NO_PROXY": "",
                    "http_proxy": "http://192.0.2.1:9",
                    "https_proxy": "http://192.0.2.1:9",
                    "all_proxy": "http://192.0.2.1:9",
                    "no_proxy": "",
                },
            ):
                decision = DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())
        self.assertEqual(decision.category.value, "suspicious")

    def test_evidence_count_field_and_request_size_limits_fail_without_truncation(self) -> None:
        oversized_signal = EvidenceReport(
            InputType.URL,
            tuple(
                EvidenceSignal(f"signal_{i}", "x" * 1024, "y" * 1024)
                for i in range(40)
            ),
        )
        with local_decider_server() as (endpoint, _):
            with self.assertRaises(ValidationError):
                DeciderHttpClient(endpoint, timeout_seconds=1).decide(oversized_signal)
        too_many = EvidenceReport(
            InputType.URL,
            tuple(EvidenceSignal(f"s{i}", "description", "source") for i in range(129)),
        )
        with self.assertRaises(ValidationError):
            DeciderHttpClient().decide(too_many)
        self.assertGreater(MAX_REQUEST_BYTES, 0)

    def test_environment_configuration_is_validated(self) -> None:
        from unittest.mock import patch

        with patch.dict(
            "os.environ",
            {
                "PHISHPILOT_DECIDER_URL": "http://localhost:8099/v1/systemone",
                "PHISHPILOT_DECIDER_TIMEOUT_SECONDS": "60",
                "PHISHPILOT_DECIDER_MODEL": "local-model",
            },
            clear=False,
        ):
            client = DeciderHttpClient()
        self.assertEqual(client.endpoint, "http://localhost:8099/v1/systemone")
        self.assertEqual(client.timeout_seconds, 60.0)
        self.assertEqual(client.model, "local-model")

    def test_default_timeout_is_sixty_seconds_and_configuration_is_bounded(self) -> None:
        from unittest.mock import patch

        with patch.dict("os.environ", {}, clear=True):
            client = DeciderHttpClient()
        self.assertEqual(client.timeout_seconds, 60.0)

        for invalid in ("0.04", "120.01", "NaN", "inf", "not-a-number", ""):
            with self.subTest(invalid=invalid), patch.dict(
                "os.environ", {"PHISHPILOT_DECIDER_TIMEOUT_SECONDS": invalid}, clear=True
            ), self.assertRaises(ValidationError):
                DeciderHttpClient()

    def test_model_is_omitted_when_server_default_is_requested(self) -> None:
        with local_decider_server() as (endpoint, server):
            DeciderHttpClient(endpoint, timeout_seconds=1).decide(evidence_report())
        request_data = json.loads(server.captured_body)  # type: ignore[attr-defined]
        self.assertNotIn("model", request_data)


if __name__ == "__main__":
    unittest.main()
