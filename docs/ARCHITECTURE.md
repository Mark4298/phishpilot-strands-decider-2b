# Architecture — PhishPilot

## Design target
Keep a short, observable, fail-closed pipeline with a single decision point and one generative report call. Do not add services unless a requirement or benchmark justifies them.

## Request flow
1. Streamlit validates the user input and size limit.
2. Input parser extracts URLs and basic metadata without fetching anything.
3. Evidence extractor creates a typed `EvidenceReport` with signals and provenance. Use deterministic parsers for deterministic facts; heuristic indicators should be labeled as heuristics.
4. `DeciderClient` sends one bounded state and a typed `choice` question to the local Strands Decider endpoint (`POST /v1/systemone`). Validate response shape with an adapter tied to the installed upstream version. Preserve answer, option probabilities, confidence, model metadata if present, and raw response only in the test/debug layer—not user-visible by default.
5. `RiskPolicy` maps the supported Decider result into `assessed` or `needs_review`. Thresholds are configuration, not universal truth. Treat model confidence as preference/confidence, not P(phishing).
6. `ReportAgent` is a Strands `Agent` configured with a verified `BedrockModel` and `BEDROCK_MODEL_ID`; it receives only the bounded evidence report and immutable Decider decision. It creates an explanation and safe actions. It must not be permitted to call arbitrary tools or change the outcome.
7. Streamlit renders structured data and the report; errors are surfaced without exposing secrets or stack traces.
8. Optional evaluation instrumentation records durations/counts but not message bodies.

## Component boundaries
- `domain/models.py`: Pydantic or dataclass schemas for input, evidence, decision, report and pipeline result.
- `evidence/url_parser.py`: safe URL parsing, scheme/host/IP/credential/punycode/length signals; no I/O.
- `evidence/email_parser.py`: standard-library email parsing and bounded extraction; no I/O.
- `evidence/heuristics.py`: deterministic indicator rules with reason codes and source locations; no final classifier.
- `decider/client.py`: HTTP client, endpoint, timeout, response schema validation, no silent fallback.
- `decider/policy.py`: confidence/uncertainty routing policy; explicit configurable thresholds with a rationale.
- `report/agent.py`: Strands Agents + Bedrock report generation. Prompt injection resistant instructions, no tools.
- `pipeline.py`: orchestration and timings.
- `app.py`: Streamlit presentation only; no model logic in UI.
- `evaluation/`: labelled synthetic fixtures and reproducible metrics.

Adapt the filenames if the current repo already has a different clean structure, but preserve the module boundaries.

## State/data contract
All input fields are untrusted. Keep the model state under a configured size. Recommended state keys: `input_type`, `subject` if any, `sender` if any, `body_or_url`, `signals` (`code`, `description`, `source_span` if safely available), and `missing_information`. The state should not be a giant HTML blob or complete hidden document.

## Decision contract
- Type: `choice`.
- Options: `likely_benign`, `suspicious`, `high_risk` with clear criteria.
- Every category criterion must avoid overclaiming. `likely_benign` means no meaningful indicators were found in the supplied evidence, not that the message is proven safe.
- Parse the exact return schema using tests based on upstream docs / example. Never guess at `answers`, `confidence`, or score field names without checking the response of installed API version.
- Confidence comes from Decider; the app policy uses it only to decide whether to request human review. It does not transform confidence into a phishing probability.
- Keep option labels and ordering stable across benchmark and production unless a version change is explicitly recorded.

## Reliability and time budget
- Validation and evidence extraction should be O(n) in input length and bounded by maximum input length / URL count.
- Use `time.perf_counter()` for component timings; measure cold start separately from warm decisions.
- Use one Decider HTTP round trip for the `choice` decision. If multiple typed questions are used, confirm that they genuinely improve the result and fit the documented API; don't add them by default.
- One Bedrock report call per successful assessment. Don't generate multiple drafts behind the scenes.
- Cache initialized model/agent objects if the framework safely permits it, not user content.
- Use explicit HTTP connect/read timeouts, bounded retry behavior (at most one retry for transient failures if safe) and no unbounded loops.
- The Decider server defaults to loopback and no auth. Keep it private; don't expose it to the internet.

## Deployment stages
MVP: Streamlit + Python process locally; Decider server on localhost/WSL2 where applicable; Bedrock over AWS API. Only consider AWS-hosted deployment after functionality and hardware/resource checks pass. Cloud deployment is not worth compromising the core demo.
