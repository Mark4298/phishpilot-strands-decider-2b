# Evaluation Plan

## Objective
Demonstrate that the complete app works and measure its limitations. Evaluation is separate from code correctness.

## Dataset
- Start with 40–80 synthetic or safely public/licensed examples if time permits.
- Include benign newsletters/receipts/normal notifications, urgent-but-legitimate messages, obvious phishing, ambiguous marketing emails, URL-only examples, malformed input and adversarial prompt-injection text.
- Keep a `case_id`, `input_type`, expected label, reason/label rationale, and split. No real private data.
- Split by template/campaign so near-duplicate messages do not leak across train/validation/test. Do not tune parser rules against held-out test examples.
- Label “expected category” as a human-defined benchmark label, not objective ground truth.

## Classification metrics
For the 3-category output, report per-class precision/recall/F1, macro-F1, confusion matrix, false-benign rate on high-risk cases, false-positive rate on benign cases, and review/defer rate. Include denominator/counts.

## Confidence analysis
Report accuracy by Decider confidence band and number of samples per band. Do not equate confidence with phishing probability. If the held-out set is too small to assess calibration, say “insufficient sample size.”

## Timing
Measure with `time.perf_counter()`:
- input validation + evidence extraction
- Decider HTTP request (warm inference; include HTTP round trip)
- Bedrock report call
- total end-to-end time
- cold start/model loading separately
Report p50, p95, sample count, machine/device, model IDs and version pins. Redact inputs from logs.

## Optional baseline
Compare Decider triage to a Bedrock-only classifier on the same labelled set, with identical category definitions. Compare classification metrics and latency separately. Include number of calls and method for cost estimation; do not imply equivalence unless prompts and tasks are comparable.

## Acceptance
The report is reproducible from committed commands/scripts and fixture version. Never fabricate data or hardcode a claimed improvement. Negative/noisy results are valid findings.
