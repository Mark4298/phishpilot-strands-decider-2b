# Efficiency / DSA Strategy

## Principle
The fastest implementation is the one that avoids unnecessary work while remaining correct. “Advanced DSA” is not inherently faster for a bounded phishing-triage request. Use an algorithm only when its cost and benefits match the workload.

## Proposed complexity budget
- Input validation: O(n) in input chars; reject past max length.
- URL extraction: O(n), single pass/one bounded regex or parser pass.
- URL parsing: O(u), where `u` is number of extracted URLs, capped by config; each URL bounded length.
- Signal aggregation: O(s) over extracted signals, with deterministic sets/dicts for deduplication.
- Decision call: dominated by model inference / HTTP round-trip, not data structures.
- Report: dominated by Bedrock network latency/tokens.

## Useful optimizations
1. Bound input size, URL count and output tokens; this is both a security control and a performance control.
2. Extract all evidence in one pass and pass one concise structured state to Decider.
3. Keep report context compact: use signal codes/descriptions and short source excerpts, not full HTML or duplicate text.
4. Reuse the loaded Decider server and initialized report agent/model in process where supported.
5. Avoid model call for invalid input. Do not skip Decider or Bedrock in a successful path.
6. Use bounded timeouts and no infinite retries.
7. Benchmark each stage separately before optimizing.
8. Measure cold model load separately from warm inference; report p50 and p95 across repeated runs.

## Not recommended for MVP
- Vector DB/embeddings: no retrieval use case.
- Graph DB: no entity graph use case.
- Bloom filters: no large membership-check workload with acceptable false positives.
- Trie: URL prefix scanning can be handled by clear bounded parsers/sets at this scale; add a trie only if measured need emerges.
- Multiprocessing per message: large model process duplication wastes RAM and can increase latency.
- Asynchronous orchestration without concurrent independent I/O: adds complexity without reducing serial Decider→report latency.
- Caching user messages/decisions: privacy and cache invalidation costs outweigh benefits for this demo.

## Benchmark protocol
- Capture CPU, RAM, OS, Python version, selected device, model IDs/revisions, network, region, versions, input corpus size and run date.
- Run warm-up requests, then at least 30 repeated cases where feasible.
- Use `time.perf_counter()` and `statistics.quantiles` or NumPy only if already installed.
- Report p50/p95 and sample count, never only the best run.
- Separate local evidence extraction, Decider inference, Bedrock report latency and end-to-end latency.
- If comparing with Bedrock-only classification, use the same labelled inputs and classification prompt; report class metrics, request counts and estimated/actual cost method.
- Keep accuracy separate from latency. The model's generic confidence calibration does not establish calibration for phishing.
- If results are noisy or too few, say so. Do not fabricate a speedup.
