# Security, Privacy and Safe Operation Rules

## Threat model
The submitted email or URL may contain malicious content, misleading strings, prompt injections, HTML, Unicode/IDN tricks, or huge inputs. The AI model output may be inaccurate. The app and local model service may be misconfigured. AWS credentials must remain private.

## Must-do controls
- Static-only analysis in the MVP: do not dereference URLs, follow redirects, resolve DNS, download pages, open attachments, execute content, or run input through a shell/browser.
- Limit request size and number of extracted URLs before expensive operations.
- Parse using standard libraries and explicit allow-listed schemes (`http`, `https` for analysis only); non-HTTP schemes are not opened, and should be described as unsupported/suspicious by policy rather than executed.
- Defend against malformed URLs, embedded credentials, control characters, long hosts, Unicode/IDN confusion and IP-literal hosts. Preserve original input safely for display; use normalized parse results for analysis.
- Avoid simplistic “last two labels” registrable-domain logic. Do not assert lookalike-domain or brand impersonation unless the evidence genuinely supports it and the algorithm has tests.
- Do not fetch a public suffix list on a user request. Any optional public-suffix dependency must be pinned, local/offline, and justified.
- Render plain text only; never pass raw untrusted HTML to `unsafe_allow_html=True` or a browser DOM.
- Mark user content as quoted untrusted evidence in the Bedrock prompt; explicit instruction-in-content is not an application instruction.
- Report only evidence actually extracted. No invented domain reputation, TLS validation, blacklist status, WHOIS data, current URL content or “scan results”.
- The agent has no tools that can perform arbitrary network/OS actions. If tools are added later, make a separate security review and require explicit policy gating.
- Secrets: use environment variables/AWS credential chain. Never print credentials; scrub exceptions that might contain secrets; `.env` stays ignored.
- Keep message content in memory for the request only. Do not persist full body or URL in logs. If telemetry exists, opt-in and metadata-only.
- Timeout every network request and fail visibly. Do not force a guessed decision after a model failure.

## Language in the UI
Prefer “AI assessment”, “signals”, “evidence”, “confidence”, “inconclusive”, and “manual review”. Avoid “confirmed malware”, “100% safe”, “guaranteed phishing”, “blocked”, “reported”, or “scanned externally” unless a real corresponding action/data source exists.

## Responsible demo
Use synthetic examples and reserved/example domains such as `example.test`; never demonstrate credential theft, live malicious payloads, or real people's private emails. Mention that the tool is an experimental learning demo and doesn't replace incident response procedures.
