# Acceptance Criteria / Definition of Done

## Gate A — environment and API discovery
- [ ] Python version and OS/device recorded.
- [ ] Current official Strands Decider install method determined; a pinned version/commit is recorded after it passes a smoke test.
- [ ] Decider model starts and `/health` can be read locally; no network exposure.
- [ ] A real `/v1/systemone` choice call returns data; request/response schema is verified and captured as a sanitized fixture.
- [ ] Amazon Bedrock region and model ID are verified in the account; a minimal Strands Agent call succeeds.
- [ ] Failure in any dependency stops further app work until root cause is known.

## Gate B — deterministic core
- [ ] Empty, malformed and oversized input are rejected before model calls.
- [ ] URL/email parsers do not do network I/O.
- [ ] Evidence signals have stable reason codes and provenance.
- [ ] Unit tests cover malformed URLs, host IP literals, userinfo, punycode/IDN edge cases, Unicode/control characters, multiple links, no link, benign urgency, false positives and prompt-injection text.
- [ ] No regex catastrophic-backtracking pattern; input and URL counts are bounded.

## Gate C — Decider policy pattern
- [ ] Real Decider 2B output supplies the selected category; no mocked/fallback category is used in the live path.
- [ ] All returned option scores/distribution and confidence are preserved if the API exposes them.
- [ ] Confidence semantics are documented; the UI never describes confidence as P(phishing).
- [ ] Low-confidence or ambiguous cases become `needs_review`; model/network errors become `analysis_unavailable`, not a guessed verdict.
- [ ] The exact typed question/options and wiring are documented in `decision_patterns/evidence_aware_risk_triage/`.

## Gate D — Bedrock reporter
- [ ] A Strands Agent configured with Amazon Bedrock generates the report.
- [ ] The report receives evidence and the immutable Decider decision as data.
- [ ] Prompt injection inside sample input does not alter system instructions or cause actions.
- [ ] The reporter does not invent external scans/reputation facts or silently change the risk category.
- [ ] Bedrock failure leaves the valid evidence/Decider result visible with report status unavailable.

## Gate E — UI and quality
- [ ] End-to-end email and URL flows work.
- [ ] User sees decision source, confidence/distribution (if available), signals, report, limitations and safe actions.
- [ ] User data is not persisted or logged by default.
- [ ] Streamlit UI does not render unsafe HTML.
- [ ] Unit tests run offline and pass; integration tests are separately marked.
- [ ] Lint passes; no committed secrets or private data.

## Gate F — evaluation and submission
- [ ] A labelled, synthetic test set with benign, suspicious, high-risk and ambiguous samples exists; labels are documented and held-out examples are not used to tune rules.
- [ ] Precision, recall, F1, confusion matrix, false-negative/false-positive rates and review/defer rate are computed.
- [ ] Latency reports warm p50/p95 for evidence, Decider, Bedrock report, and total path; cold/model-load time is reported separately.
- [ ] Any baseline comparison uses the same cases/task and reports limits; no unsupported performance claims.
- [ ] Public repo includes reusable decision pattern, instructions, license and environment setup.
- [ ] Builder Center article and public demo video under three minutes are prepared.
- [ ] Tags include `#strands-decider-2b` and `#policy`.
- [ ] Deadline checked against the latest official rules, including the October 23 vs October 30 page discrepancy.
