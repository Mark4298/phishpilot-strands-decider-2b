# Evidence-Aware Risk Triage

**Pattern:** Policy classification (`#policy`)\
**Common hackathon tag:** `#strands-decider-2b`

This reusable pattern makes a typed policy choice from bounded, structured evidence. The
Decider result is validated and remains the authoritative category; an optional generative
report is called afterward and may explain the decision but cannot replace it.

## Typed question and options

[`question.json`](question.json) is the canonical `choice` question. The HTTP adapter
contains the same question definition, and
[`tests/test_decider_http_protocol.py`](../../tests/test_decider_http_protocol.py) checks
that the two stay aligned.

The options are:

- `likely_benign`: no meaningful phishing indicator appears in the supplied evidence;
  this does not prove the message or URL is safe.
- `suspicious`: concerning indicators exist, or important context is missing; further
  verification is warranted.
- `high_risk`: multiple strong indicators or a supported credential-stealing/social-
  engineering pattern appear in the supplied evidence.

Urgency or HTTP alone does not establish maliciousness. The model is instructed to treat
user-controlled content as untrusted data rather than instructions.

## Evidence and data boundary

The application validates the input and runs its deterministic email or URL parser once.
The resulting `EvidenceReport` contains the input type, signal codes/descriptions and
provenance, plus missing information. `DeciderHttpClient` serializes bounded structured
evidence only; it does not send the original email body, sender, subject, submitted URL,
or fetched page. No URL is fetched, opened, or resolved. The example uses explicitly
synthetic `EvidenceReport` data and contains no real message or URL.

## Where the decision controls behavior

`phishpilot.pipeline.investigate` receives a `DeciderClient`, extracts evidence, calls
the Decider once, requires a validated `DeciderDecision`, applies the explicit
`DecisionReviewPolicy`, and only then calls the report client with that evidence and
decision. An unavailable or invalid Decider response produces `analysis_unavailable`
with no category; it never falls back to a guessed result. A low-confidence or ambiguous
valid result is routed to `needs_review`. Report failure leaves a valid decision intact
and marks the report unavailable. The UI renders the typed category separately from
generated prose.

The decision distribution and confidence are values returned by Decider. Confidence is
not a calibrated probability that a message is phishing, and the policy thresholds are
routing settings rather than validated accuracy thresholds.

## Run the reusable example

From the project root, with the project dependencies already installed and a real
Decider server already running on loopback:

```powershell
.\.venv\Scripts\python.exe -m decision_patterns.evidence_aware_risk_triage.example
```

The example's default path constructs the existing `DeciderHttpClient`, which posts to
`http://127.0.0.1:8000/v1/systemone`. It prints the selected category, actual returned
option distribution, Decider preference confidence, and model identifier. If the service
is unavailable or its response is invalid, it prints an error and exits without a
decision. It never fabricates sample output. Running this command contacts the configured
local Decider server and therefore is not an offline test.

Configuration is read by the existing adapter:

- `PHISHPILOT_DECIDER_URL`: loopback URL only; defaults to `http://127.0.0.1:8000`.
- `PHISHPILOT_DECIDER_TIMEOUT_SECONDS`: finite timeout from 0.05 to 120 seconds; defaults
  to 60 seconds. The timeout is configurable; 60 seconds has not been verified as
  sufficient for CPU inference on the project laptop.
- `PHISHPILOT_DECIDER_MODEL`: optional server model name; omitted by default.

The server has no authentication by default. Keep it bound to loopback and do not expose
it publicly. Real model weights and a running service are prerequisites. In one user-
reported run on October 20, 2026, this reusable example submitted synthetic evidence to
`strands-decider-2B-hobson-v19`; `/health` returned `ok`, the choice request returned HTTP
200, and the validated choice was `suspicious`. The returned distribution was
`likely_benign=0.257800`, `suspicious=0.697500`, `high_risk=0.044600`; preference confidence
was `0.546300`. This confidence is not a calibrated phishing probability. Memory fell to
approximately 1.04 GiB available at 93.5% load during the run; the server was stopped and
no listener remained. Do not treat the successful response as evidence that another
startup is safe, or as verification of the full Streamlit-to-Decider-to-Bedrock flow.

## Reuse in another application

1. Replace the options and criteria in `question.json` with the target domain's policy,
   then keep the adapter's typed request definition and contract test synchronized.
2. Produce a bounded `EvidenceReport` with stable signal codes and source provenance.
3. Inject a `DeciderClient` into the existing pipeline (or call
   `classify_evidence` with an injected client for a decision-only boundary).
4. Preserve the returned immutable `DeciderDecision`; configure review routing explicitly.
5. If a generative explanation is needed, call the report client only after a validated
   decision and display prose separately from that decision.
6. Add domain-labeled evaluation before interpreting confidence thresholds as useful.

The example's injectable client exists for isolated tests and reuse. Test doubles are
not used by the default executable path and must never be described as actual inference.

## Verification status

Offline adapter, domain, and pipeline tests validate contracts and failure handling using
local test fixtures/test doubles. They are not Decider inference results. One real typed
Decider inference through this example is verified as described above. The Streamlit UI
has not been verified against that live service, and Bedrock report generation remains
unverified.
