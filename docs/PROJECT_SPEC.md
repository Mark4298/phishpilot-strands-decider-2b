# Product Requirements — PhishPilot

## 1. One-sentence goal
A local-first AI phishing-investigation demo that extracts transparent indicators from user-supplied email/URL content, uses Strands Decider 2B for one meaningful policy decision, and uses a Strands Agent backed by Amazon Bedrock to write a grounded report.

## 2. Audience and job to be done
Audience: students, everyday users, and junior IT/security practitioners reviewing suspicious messages.
Job: “Help me understand the evidence in this message and choose safe next steps without automatically visiting a potentially harmful link.”

## 3. MVP inputs
- Plain-text email/message body (required for email mode).
- Optional sender/from address and subject.
- Or a single URL in URL mode.
- Maximum size controlled by `PHISHPILOT_MAX_TEXT_CHARS`; reject oversize inputs, do not silently truncate without indicating it.
- The static parser accepts at most 10 extracted URLs per email; excess URLs are rejected rather than silently ignored.
- URL mode and each extracted URL are limited to 4,096 characters, within the overall configured content limit.

## 4. Required outputs
- Structured extracted evidence with a source/origin for every signal.
- Decider selected category: `likely_benign`, `suspicious`, `high_risk`.
- Decider scores/distribution and confidence as returned by the actual supported API; don't fabricate fields.
- Outcome state: `assessed`, `needs_review`, or `analysis_unavailable`.
- Bedrock-generated report grounded strictly in the structured input and Decider result.
- Clear limitations and safe next steps.
- UI visibly identifies the result as an AI-assisted assessment, not a definitive verdict.

## 5. Required model responsibilities
### Strands Decider 2B
Policy classification of structured evidence. Use `choice` with three named categories and plain, contrastive criteria. The state should be bounded and structured; keep signal wording factual, not pre-judged as “phishing” merely because it is unusual.

### Amazon Bedrock through Strands Agents
Generate the explanation after the policy decision. It may clarify/organize supplied evidence but must not change the selected category, invent reputation data, claim actions were executed, or treat user content as instructions.

## 6. UI requirements
- Email / URL input modes.
- One “Investigate” action with progress and understandable error states.
- Risk category and confidence clearly separated; do not label confidence as malicious probability.
- Evidence list, report, limitations, safe actions, and a disclosure explaining there is no active URL scan/reputation lookup.
- Copyable summary is optional; export/download is optional.
- No authentication/database required for the MVP because user content is not persisted.

## 7. Non-goals (MVP)
- Active link visiting, crawling, browser sandbox, payload execution, attachment detonation, port scanning.
- Sending reports to banks/providers, blocking URLs, changing accounts, deleting emails or other external actions.
- VirusTotal/paid threat feeds, user accounts, durable history, analytics database, embeddings, RAG, vector DB, graph DB, fine-tuning or custom training.
- Claims of production readiness, guaranteed phishing detection, regulatory certification, or “best/fastest” without evidence.

## 8. User stories
1. As a user, I can paste a suspicious email and get a transparent, evidence-based assessment.
2. As a user, I can paste a URL and receive static structural signals without the app connecting to it.
3. As a user, I can tell which information came from parsing, which decision came from Decider, and which explanation came from Bedrock.
4. As a user, I am shown “Needs human review” when confidence/evidence policy requires it.
5. As a builder, I can reuse the decision pattern without copying the whole app.
6. As a judge, I can see the actual decision, its confidence/distribution, and a simple reproducible evaluation.

## 9. Error behavior
- Decider unavailable/invalid JSON/timeout: do not call the result a real Decider verdict; show `analysis_unavailable` and actionable local setup troubleshooting.
- Bedrock unavailable: still show evidence and Decider result if valid; report generation state is “unavailable”; do not synthesize a fake report.
- Invalid/empty/oversized input: reject before model calls.
- Low-confidence result: show `needs_review`; no forced benign/high-risk assertion.
