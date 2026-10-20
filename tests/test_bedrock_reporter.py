"""Offline protocol tests for the Strands/Bedrock report adapter.

Injected agents are test fixtures only and do not represent Bedrock inference.
"""

from __future__ import annotations

import os
import unittest
from inspect import signature
from typing import Any
from unittest.mock import patch

from phishpilot.domain.models import (
    DeciderDecision,
    EvidenceReport,
    EvidenceSignal,
    InputType,
    InvestigationInput,
    ReportResult,
    RiskCategory,
)
from phishpilot.evidence.email_parser import extract_email_evidence
from phishpilot.integrations.bedrock_reporter import (
    DEFAULT_MAX_OUTPUT_TOKENS,
    MAX_CONTEXT_BYTES,
    SYSTEM_PROMPT,
    BedrockReportClient,
    _create_strands_agent,
    _report_context,
)


def evidence(description: str = "An HTTPS URL was present.") -> EvidenceReport:
    return EvidenceReport(
        InputType.EMAIL,
        (EvidenceSignal("url.https", description, "email_body"),),
        ("Sender authentication was not checked.",),
    )


def decision() -> DeciderDecision:
    return DeciderDecision(
        RiskCategory.SUSPICIOUS,
        {"likely_benign": 0.1, "suspicious": 0.8, "high_risk": 0.1},
        0.7,
        "test-model-id",
    )


class _FixtureAgent:
    def __init__(self, response: Any = None) -> None:
        self.response = response or type(
            "Result",
            (),
            {
                "message": {
                    "content": [{"type": "text", "text": "Evidence suggests caution."}]
                }
            },
        )()
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> Any:
        self.prompts.append(prompt)
        return self.response


class BedrockReporterProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env_patcher = patch.dict(
            os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "unit-test-token-only"}
        )
        self._env_patcher.start()
        self.addCleanup(self._env_patcher.stop)

    def test_report_prompt_excludes_raw_email_sender_subject_and_url(self) -> None:
        investigation = InvestigationInput(
            InputType.EMAIL,
            "PRIVATE_BODY_MARKER https://private-host-marker.example/path",
            sender="PRIVATE_SENDER_MARKER@example.test",
            subject="PRIVATE_SUBJECT_MARKER",
        )
        extracted = extract_email_evidence(investigation)
        fixture = _FixtureAgent()
        result = BedrockReportClient(
            model_id="example-model",
            region="us-east-1",
            agent_factory=lambda *_args: fixture,
        ).generate(extracted, decision())

        self.assertTrue(result.available)
        prompt = fixture.prompts[0]
        for marker in (
            "PRIVATE_BODY_MARKER",
            "private-host-marker.example",
            "PRIVATE_SENDER_MARKER",
            "PRIVATE_SUBJECT_MARKER",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, prompt)

    def test_maps_plain_text_response_and_passes_only_structured_evidence(self) -> None:
        fixture = _FixtureAgent()
        factory_calls: list[tuple[str, str, float, int, str]] = []

        def factory(
            model_id: str,
            region: str,
            timeout: float,
            max_output_tokens: int,
            api_key: str,
        ) -> _FixtureAgent:
            factory_calls.append((model_id, region, timeout, max_output_tokens, api_key))
            return fixture

        client = BedrockReportClient(
            model_id="example-model",
            region="us-east-1",
            timeout_seconds=20,
            agent_factory=factory,
        )
        result = client.generate(evidence(), decision())

        self.assertEqual(result, ReportResult(True, text="Evidence suggests caution."))
        self.assertEqual(
            factory_calls,
            [
                (
                    "example-model",
                    "us-east-1",
                    20,
                    DEFAULT_MAX_OUTPUT_TOKENS,
                    "unit-test-token-only",
                )
            ],
        )
        self.assertEqual(len(fixture.prompts), 1)
        prompt = fixture.prompts[0]
        self.assertIn('"category":"suspicious"', prompt)
        self.assertIn('"code":"url.https"', prompt)
        self.assertNotIn("original email body", prompt)
        self.assertIn("untrusted evidence data", prompt)

    def test_system_prompt_sets_untrusted_and_immutable_decision_boundaries(self) -> None:
        self.assertIn("untrusted data", SYSTEM_PROMPT)
        self.assertIn("Do not change, reclassify, or contradict", SYSTEM_PROMPT)
        self.assertIn("Do not claim reputation", SYSTEM_PROMPT)
        self.assertIn("safe, non-destructive next steps", SYSTEM_PROMPT)

    def test_missing_configuration_does_not_construct_agent(self) -> None:
        calls: list[bool] = []
        client = BedrockReportClient(
            model_id="",
            region="us-east-1",
            agent_factory=lambda *_args: calls.append(True),
        )
        result = client.generate(evidence(), decision())
        self.assertFalse(result.available)
        self.assertEqual(result.error_code, "report_configuration_missing")
        self.assertEqual(calls, [])

    def test_missing_bearer_token_fails_before_agent_construction(self) -> None:
        calls: list[bool] = []
        with patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": ""}):
            result = BedrockReportClient(
                model_id="example-model",
                region="ap-southeast-2",
                agent_factory=lambda *_args: calls.append(True),
            ).generate(evidence(), decision())
        self.assertFalse(result.available)
        self.assertEqual(result.error_code, "report_credentials_missing")
        self.assertIn("AWS_BEARER_TOKEN_BEDROCK", result.error_message or "")
        self.assertEqual(calls, [])

    def test_model_region_timeout_and_output_limit_configuration_is_validated(self) -> None:
        invalid_configurations = (
            {"model_id": "model id with spaces"},
            {"region": "not a region"},
            {"timeout_seconds": float("inf")},
            {"timeout_seconds": 121},
            {"max_output_tokens": 0},
            {"max_output_tokens": 4097},
            {"max_output_tokens": True},
        )
        for config in invalid_configurations:
            with self.subTest(config=config), self.assertRaises(ValueError):
                options = {"model_id": "example-model", "region": "ap-southeast-2"}
                options.update(config)
                BedrockReportClient(**options)

    def test_invalid_environment_timeout_and_output_limit_are_rejected(self) -> None:
        invalid_environment = (
            {"PHISHPILOT_BEDROCK_TIMEOUT_SECONDS": "nan"},
            {"PHISHPILOT_BEDROCK_TIMEOUT_SECONDS": "121"},
            {"PHISHPILOT_BEDROCK_MAX_TOKENS": "many"},
            {"PHISHPILOT_BEDROCK_MAX_TOKENS": "4097"},
        )
        for values in invalid_environment:
            with self.subTest(values=values), patch.dict(os.environ, values):
                with self.assertRaises(ValueError):
                    BedrockReportClient(model_id="example-model", region="ap-southeast-2")

    def test_output_limit_can_be_configured_and_is_passed_to_agent_factory(self) -> None:
        fixture = _FixtureAgent()
        received: list[int] = []

        def factory(
            _model_id: str,
            _region: str,
            _timeout: float,
            max_output_tokens: int,
            _api_key: str,
        ) -> _FixtureAgent:
            received.append(max_output_tokens)
            return fixture

        result = BedrockReportClient(
            model_id="example-model",
            region="ap-southeast-2",
            max_output_tokens=120,
            agent_factory=factory,
        ).generate(evidence(), decision())
        self.assertTrue(result.available)
        self.assertEqual(received, [120])

    def test_short_lived_key_is_re_read_for_each_report_without_agent_cache(self) -> None:
        observed_keys: list[str] = []

        def factory(
            _model_id: str,
            _region: str,
            _timeout: float,
            _max_output_tokens: int,
            api_key: str,
        ) -> _FixtureAgent:
            observed_keys.append(api_key)
            return _FixtureAgent()

        client = BedrockReportClient(
            model_id="example-model",
            region="ap-southeast-2",
            agent_factory=factory,
        )
        with patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "first-fixture-key"}):
            first = client.generate(evidence(), decision())
        with patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "second-fixture-key"}):
            second = client.generate(evidence(), decision())

        self.assertTrue(first.available)
        self.assertTrue(second.available)
        self.assertEqual(observed_keys, ["first-fixture-key", "second-fixture-key"])
        self.assertFalse(hasattr(client, "_agent"))

    def test_strands_model_receives_api_key_without_network_call(self) -> None:
        from strands.models import BedrockModel

        self.assertIn("api_key", signature(BedrockModel).parameters)
        with (
            patch("strands.models.BedrockModel") as bedrock_model,
            patch("strands.Agent") as agent_class,
        ):
            _create_strands_agent(
                "amazon.nova-micro-v1:0",
                "ap-southeast-2",
                45.0,
                150,
                "test-only-api-key",
            )
        bedrock_model.assert_called_once()
        kwargs = bedrock_model.call_args.kwargs
        self.assertEqual(kwargs["api_key"], "test-only-api-key")
        self.assertEqual(kwargs["model_id"], "amazon.nova-micro-v1:0")
        self.assertEqual(kwargs["region_name"], "ap-southeast-2")
        self.assertEqual(kwargs["max_tokens"], 150)
        self.assertEqual(agent_class.call_args.kwargs["tools"], [])
        self.assertFalse(agent_class.call_args.kwargs["load_tools_from_directory"])

    def test_provider_failure_returns_unavailable_without_provider_details(self) -> None:
        def failed_factory(*args: Any) -> _FixtureAgent:
            raise RuntimeError(f"provider details included key {args[-1]}")

        result = BedrockReportClient(
            model_id="m", region="us-east-1", agent_factory=failed_factory
        ).generate(evidence(), decision())
        self.assertFalse(result.available)
        self.assertEqual(result.error_code, "report_unavailable")
        self.assertNotIn("sensitive", result.error_message or "")
        self.assertNotIn("unit-test-only-token", result.error_message or "")

    def test_malformed_or_oversized_response_fails_closed(self) -> None:
        for response in (
            object(),
            type("Result", (), {"message": {"content": [{"type": "image"}]}})(),
            type(
                "Result",
                (),
                {"message": {"content": [{"type": "text", "text": "x" * 8001}]}},
            )(),
        ):
            with self.subTest(response=response):
                result = BedrockReportClient(
                    model_id="m",
                    region="us-east-1",
                    agent_factory=lambda *_args, response=response: _FixtureAgent(response),
                ).generate(evidence(), decision())
                self.assertFalse(result.available)
                self.assertEqual(result.error_code, "report_unavailable")

    def test_context_is_bounded_and_does_not_include_raw_message(self) -> None:
        oversized = EvidenceReport(
            InputType.EMAIL,
            (EvidenceSignal("test", "x" * MAX_CONTEXT_BYTES, "test"),),
        )
        with self.assertRaises(ValueError):
            _report_context(oversized, decision())


if __name__ == "__main__":
    unittest.main()
