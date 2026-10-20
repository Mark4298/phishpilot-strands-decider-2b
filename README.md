# PhishPilot

PhishPilot is an experimental, local-first phishing-triage demo. It extracts static evidence from pasted email text or a URL, sends the structured evidence to a local Strands Decider service for a typed choice, then can request a grounded explanation from Strands Agents on Amazon Bedrock.

The interface is wired to the real integrations. It displays a category only after the local Decider returns a validated decision; Bedrock report generation is attempted afterward. If report generation is unavailable, the valid typed decision remains visible and the report is marked unavailable. The complete Streamlit-to-Decider-to-Bedrock flow has not yet been verified. Decider confidence is not a probability that content is phishing.

## Current status

- Offline domain, parser, pipeline, adapter, and UI tests run with the existing Python 3.14.4 environment.
- A real local Decider inference was reported successful on October 20 through the reusable example using synthetic evidence: `/health` returned `ok`, `POST /v1/systemone` returned HTTP 200, and the typed choice was `suspicious`. Available RAM fell to about 1.04 GiB at 93.5% load; the server was then stopped and no listener remained. This verifies the example's Decider call, not another safe startup or the complete UI flow. Do not restart without a fresh resource review and explicit approval.
- The real Bedrock report and complete Streamlit-to-Decider-to-Bedrock flow remain unverified. Bedrock use may incur charges. Under the current zero-budget constraint, do not submit an analysis that invokes Bedrock unless a cost-free entitlement with a hard zero-cost limit is confirmed and a live call is separately authorized. The hackathon terms list AWS credits as winner prizes, not participant compute credits or a participant sandbox.
- Public source repository: [Mark4298/phishpilot-strands-decider-2b](https://github.com/Mark4298/phishpilot-strands-decider-2b). The reviewed 41-file source snapshot was published at commit `fe3980c6725270c095281c7a9df712300b9c1e13`. The standalone real Decider inference is verified; the complete Streamlit-to-Decider-to-Bedrock flow remains unverified.

## Local launch

This command only launches the UI; it does not start or download the Decider model. A real
local Decider server must already be running on loopback, and Bedrock must be available in
the configured AWS account and region. Missing/unavailable Decider service produces no
category. If Bedrock is unconfigured or the report call fails, the app keeps a valid
Decider decision visible and marks the report unavailable. These calls are not made by
automated tests. The report call may incur usage-based AWS charges.

Launching the UI does not call AWS. Clicking Analyze can invoke Bedrock after a real
Decider choice; under a zero-budget constraint, use the live path only after confirming
an eligible no-cost account/credit route and a cost ceiling that cannot exceed $0. The
current hackathon terms promise AWS Promotional Credits to winners only and do not state
that entrants receive a compute sandbox or universal credits. Ask the organizers whether
participant resources exist; this has not been done.

Use the existing virtual environment; no package installation is part of this launch
procedure. From PowerShell at the project root, set the values for your own permitted environment:

```powershell
$env:PHISHPILOT_DECIDER_URL = "http://127.0.0.1:8000"
$env:BEDROCK_MODEL_ID = "amazon.nova-micro-v1:0"
$env:AWS_REGION = "ap-southeast-2"
$env:PHISHPILOT_MAX_TEXT_CHARS = "20000"
$env:PHISHPILOT_DECIDER_TIMEOUT_SECONDS = "60"
$env:PHISHPILOT_BEDROCK_TIMEOUT_SECONDS = "45"
$env:PHISHPILOT_BEDROCK_MAX_TOKENS = "150"
$env:PHISHPILOT_MIN_DECIDER_CONFIDENCE = "0.55"
$env:PHISHPILOT_MIN_DECIDER_MARGIN = "0.05"
& .\.venv\Scripts\streamlit.exe run app.py --server.address 127.0.0.1
```

For a fresh checkout, the project metadata accepts Python 3.12 through 3.14. The current
requirement inputs are not pinned and no lock file is present, so a fresh install is not
reproducible or verified by this project. If you choose to resolve them in a new
environment, use:

```powershell
py -3.14 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.in
```

The test and lint results recorded here came from the existing Python 3.14.4 environment;
they do not establish that a fresh dependency resolution will reproduce it.

`PHISHPILOT_DECIDER_URL` must point to a loopback service. Optional `PHISHPILOT_DECIDER_MODEL` selects a server model; omitted means the service default. The overall input cap is 20,000 characters by default and `PHISHPILOT_MAX_TEXT_CHARS` can lower it, not raise it. URL mode and each URL extracted from email are separately capped at 4,096 characters; email extraction accepts at most 10 URLs. Inputs over any applicable limit are rejected without truncation. The confidence and option-margin thresholds above are demonstration routing settings only and are not validated phishing-performance thresholds.

`PHISHPILOT_DECIDER_TIMEOUT_SECONDS` configures the bounded Decider socket timeout (default 60 seconds; accepted range 0.05–120 seconds). The 60-second value is a candidate for slow local CPU inference, not a measured guarantee. Both the Streamlit app and reusable pattern example use the same `DeciderHttpClient` environment setting; an invalid value is rejected rather than treated as unlimited.

The reporter uses the short-term Amazon Bedrock API key supplied to the running process as `AWS_BEARER_TOKEN_BEDROCK`; the installed Strands `BedrockModel(api_key=...)` path sends it as bearer authentication. The reporter does not accept the standard AWS credential chain as a substitute when this API-key mode is selected. Never put the key in `.env`, `.env.example`, source, command history, or documentation. Supply it through a secure method to the same process that runs the application. Short-term keys are region-bound and expire with the session (up to 12 hours); generate/use one for `ap-southeast-2`. The app asks for acknowledgement before each analysis because Bedrock usage may consume AWS credits or incur charges. No credentials or AWS settings are created by project setup.

`PHISHPILOT_BEDROCK_TIMEOUT_SECONDS` accepts 1–120 seconds (default 45). `PHISHPILOT_BEDROCK_MAX_TOKENS` accepts 1–4096 output tokens (default 150). Both settings are validated; invalid values fail closed. The report agent has no tools, and each report call constructs a fresh agent so an expiring bearer key is not cached across reports.

### One-shot reporter smoke test

This separate command makes one report request directly through the existing reporter with synthetic evidence and a synthetic typed-decision fixture. It never runs Decider, and the fixture is not a real inference result. It requires the explicit `--confirm-live-call` flag. A live request consumes available AWS credits and may incur charges if credits do not cover it; execute this smoke test only once and only after confirming the account's billing route is acceptable. Do not run it during offline tests.

In PowerShell, the bearer token must already be supplied to this same process through your approved secret-handling method; the check below does not print it. This command sets the requested region/model and removes the token from the current process after the one attempt:

```powershell
if ([string]::IsNullOrWhiteSpace($env:AWS_BEARER_TOKEN_BEDROCK)) { throw "AWS_BEARER_TOKEN_BEDROCK is not set in this PowerShell process." }
$env:AWS_REGION = "ap-southeast-2"
$env:BEDROCK_MODEL_ID = "amazon.nova-micro-v1:0"
$env:PHISHPILOT_BEDROCK_TIMEOUT_SECONDS = "45"
$env:PHISHPILOT_BEDROCK_MAX_TOKENS = "150"
try {
    & .\.venv\Scripts\python.exe -m phishpilot.bedrock_report_smoke --confirm-live-call
    $smokeExitCode = $LASTEXITCODE
} finally {
    Remove-Item Env:AWS_BEARER_TOKEN_BEDROCK -ErrorAction SilentlyContinue
}
if ($smokeExitCode -ne 0) { throw "Bedrock reporter smoke test failed with exit code $smokeExitCode." }
```

The synthetic decision in this smoke command validates only the reporter call; it does not verify Decider inference or full-agent qualification.

## Read-only environment diagnostics

From the project root, run:

```powershell
& .\.venv\Scripts\python.exe -m phishpilot.diagnostics
```

The default command is offline. It reads the Python constraint, installed package
metadata, whether selected settings are present, the effective loopback Decider URL
and validated timeout, expected Hugging Face cache-directory existence, and physical
RAM counters. It never prints environment-variable values, reads model weights, starts
a service, loads a model, calls AWS, or checks a network endpoint. The 10 GiB RAM
headroom threshold is a conservative project startup gate, not a Decider requirement
or a promise that the model will load successfully.

To explicitly check an already-running Decider health endpoint only:

```powershell
& .\.venv\Scripts\python.exe -m phishpilot.diagnostics --check-decider-health
```

This optional command makes a bounded `GET /health` request to a validated IP-literal
loopback endpoint, disables proxy use and redirects, and never submits inference. A
passing health check does not verify a typed decision. The report always states that
live Decider inference and Bedrock were not checked. Readiness applies only to the
local preflight; it is not end-to-end readiness.

## Privacy and safety

Submitted content is held in Streamlit's in-memory session while the page is open; it is not saved to disk or logged by the app. URL analysis is static: the app never visits, resolves, or fetches submitted URLs. The Decider and reporter receive structured evidence, not the original email body or supplied URL. If configured, the structured evidence and validated decision are sent to Amazon Bedrock for report generation. Do not paste real personal or confidential messages into the demo.

The report is generated prose and may be wrong. It cannot replace or override the separate typed Decider category. This experimental project is not a security product or a substitute for incident-response procedures.

## Reuse the `#policy` decision pattern

The independently documented example is in
[`decision_patterns/evidence_aware_risk_triage/`](decision_patterns/evidence_aware_risk_triage/).
It contains the typed `choice` question, category criteria, bounded evidence contract,
reusable client boundary, and a runnable example that defaults to the real loopback
Decider adapter. To try that decision-only example after a local server is already
running, use:

```powershell
& .\.venv\Scripts\python.exe -m decision_patterns.evidence_aware_risk_triage.example
```

That command submits one synthetic evidence report to the configured Decider service; it
is a live request, not an offline test. The example does not call Bedrock. See the pattern
README for adapting its options, criteria, and typed `DeciderClient` boundary to another
policy. The single successful synthetic inference recorded in the project history does
not verify the Streamlit-to-Decider-to-Bedrock flow.

## Offline verification

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
& .\.venv\Scripts\ruff.exe check .
```

UI, diagnostics, pipeline, and adapter tests use explicitly test-only doubles or local protocol fixtures; they do not call AWS Bedrock or demonstrate model inference. Python 3.14.4 results verify only that interpreter run, not real model compatibility.
