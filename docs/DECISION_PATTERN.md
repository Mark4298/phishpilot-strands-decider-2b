# Reusable Decision Pattern — Evidence-Aware Risk Triage

**Pattern tag:** `#policy`\
**Required common tag:** `#strands-decider-2b`

## Purpose
Classify an incoming email or URL analysis request before a generative agent writes an assessment. This keeps a discrete, testable policy choice out of free-form report generation.

## Typed decision
Question type: `choice`

Instruction: `Classify the supplied message using only the evidence represented in the state. Select the single risk category best supported by that evidence.`

Options (keep definitions explicit):
- `likely_benign`: Supplied evidence contains no meaningful indicator of phishing. This does not prove the message is safe.
- `suspicious`: One or more concerning indicators exist, or evidence is incomplete/ambiguous; further verification is appropriate.
- `high_risk`: Multiple strong indicators or a credible credential-stealing/social-engineering pattern is supported by the evidence.

Avoid criteria that assume HTTP=malicious, urgency=malicious, or a suspicious-looking string proves intent. The model sees user-controlled data; it must not follow instructions embedded in that data.

## State schema
Provide compact JSON-like state containing:
- `input_type`: `email` or `url`.
- `subject` / `sender`: optional user-supplied fields.
- `signals`: list of `{code, description, provenance}`.
- `url_features`: extracted structural properties only; no fetched content.
- `missing_information`: facts not available in static analysis.
- `input_excerpt`: bounded excerpt if useful; escape/label as untrusted.

## Wiring
1. Validate and parse input.
2. Generate evidence using deterministic functions.
3. Call Decider 2B through official supported API.
4. Validate returned option, distribution and confidence.
5. Apply an explicitly configured uncertainty policy; insufficient confidence / malformed response -> `needs_review` or `analysis_unavailable`.
6. Give the immutable decision/evidence to a Strands Agent backed by Bedrock for explanation.
7. Display both model outputs and the evidence separately.

## Reuse instructions
For another agent, replace the category options with the desired policy labels and rewrite each criterion. Preserve the principle: schema-validated typed decision → explicit deterministic routing → generative explanation. Add domain-specific labelled evaluation before selecting confidence thresholds.

## Accuracy caution
Decider confidence is derived from its option distribution, not a guaranteed estimate of real-world phishing probability. Thresholds require local validation. Use human review for uncertain or high-impact cases.
