---
name: javascript-file-audit
description: Build a complete in-scope JavaScript asset inventory after crawling, inspect every discovered file individually, and preserve auditable coverage and validation evidence
---

# JavaScript File Audit

Use this skill after web crawling and whenever source files, script URLs, source maps, or JavaScript bundles are discovered. The goal is complete, reproducible coverage of the JavaScript files actually discovered within the authorized scope—not a search for a predetermined secret, endpoint, or vulnerability.

## 1. Build the inventory

- Preserve the raw crawler output (Katana JSONL and any headless/XHR output) as evidence.
- Immediately parse each crawler pass and submit all in-scope JavaScript URLs to `record_javascript_assets` in batches (up to 5000 URLs per call), with a source label identifying the crawler/output. Repeat after each recursive import/chunk-discovery pass; this makes the live ledger reflect crawler discoveries rather than relying on a final manual summary.

For Katana JSONL, first inspect one record to confirm the schema, then extract absolute candidate URLs from JSON string fields, filter JavaScript extensions, verify each candidate against the active scope, and submit the in-scope list:

```bash
jq -r '.. | strings | select(test("^https?://"; "i"))' crawl/katana.jsonl \
  | grep -Ei '\\.(js|mjs|cjs)([?#]|$)' \
  | sort -u > crawl/javascript-candidates.txt
```

Do not bulk-register every string blindly: URLs found inside bundles may point to third parties. Apply the active scope rules before calling the ledger tool. Parse referenced `.map` URLs separately and include only same-scope source maps.
- Extract every unique absolute HTTP(S) URL whose path has a JavaScript extension, including `.js`, `.mjs`, and `.cjs`; also inspect HTML script references and JavaScript module imports found in fetched responses.
- Include versioned bundles, chunk files, dynamically loaded scripts, and same-origin source maps when their URLs are explicitly referenced by in-scope responses.
- Resolve relative references against the response URL. Do not invent hostnames or follow references outside the system-verified scope.
- Normalize URLs for deduplication without dropping meaningful query strings. Keep the original URL and normalized key.
- Save a machine-readable inventory (JSONL preferred) with: URL, source page, discovery method, in-scope decision, fetch status, content type, byte count, SHA-256, local artifact path, and processing status.
- Do not silently discard a discovered URL because it is large, minified, duplicated by content, or has an unusual extension. Deduplicate downloads by content hash, but retain every source URL as an inventory entry.

## 2. Fetch and preserve each file

- Fetch only URLs confirmed in scope, using the engagement's configured proxy, rate limits, and request timeout.
- Follow redirects only while every redirect destination remains in scope. Record blocked/out-of-scope redirects as skipped with a reason.
- Store each response separately under a deterministic path derived from its URL hash. Preserve response metadata and compute SHA-256.
- Retry transient failures with bounded backoff. Permanent failures remain visible as failed inventory records; never mark them as analyzed.
- Treat content-type and extension as hints, not truth. If a response is JavaScript or contains a script bundle despite a nonstandard extension, classify and inspect it.
- Apply configurable size limits only as an explicit operational constraint. Mark truncated files as partial and do not count them as fully analyzed.

## 3. Inspect every file individually

For each unique fetched JavaScript content hash, create a processing record and perform:
- Syntax-aware parsing where a compatible parser is available; otherwise record the parser limitation and use a clearly labeled fallback.
- Static review for routes, API paths, HTTP methods, parameter names, request/response shapes, authentication and authorization assumptions, client-side security controls, DOM sinks/sources, dynamic code execution, message handlers, WebSocket usage, GraphQL operations, storage usage, and externally loaded dependencies.
- Secret scanning with context and validation of whether a value is actually sensitive. Never report public identifiers or placeholders as credentials.
- Extraction of imports, dynamic imports, workers, chunk references, source-map references, and additional same-scope script URLs. Newly discovered files are appended to the same inventory and queue.
- Cross-reference extracted endpoints and behavior with observed in-scope traffic. Keep static candidates distinct from traffic-confirmed behavior; never claim an HTTP method or behavior was observed if it came only from static code.

Record per-file findings, tool/version, hash, analysis timestamp, parser status, and any follow-up URLs. A file is complete only when all required checks ran or an explicit reason for each unavailable check is recorded.

## 4. Coverage and completion gate

Maintain a durable manifest with statuses such as `discovered`, `queued`, `fetching`, `fetched`, `analyzing`, `complete`, `partial`, `failed`, and `skipped_out_of_scope`.

Before declaring the JavaScript phase complete:
- Reconcile crawler URLs, HTML script references, imports, and recursively discovered chunks against the manifest.
- Ensure every in-scope discovered URL has a terminal status and every successfully fetched unique file has a completed per-file analysis record.
- Requeue interrupted or retryable work. Do not turn failures, truncation, or parser errors into successful completion.
- Report counts for discovered URLs, unique content hashes, fully analyzed files, partial files, failures, and out-of-scope skips.
- Include unresolved gaps and reasons. A phase with failures or partial files must be reported as incomplete, not complete.

## 5. Dynamic validation and evidence

Static code observations are hypotheses, not proof of exploitability. Validate a candidate only against an explicitly in-scope live endpoint and with a minimal, controlled test. A payload is confirmed working only when the response or resulting behavior demonstrates the claimed effect; preserve the exact request, response, relevant status/body markers, and reproduction conditions. A reflected string, scanner label, HTTP 200, or lack of an error is not sufficient by itself.

Do not bypass scope controls, expand to third-party hosts, or perform destructive tests. If a WAF or encoding changes behavior, document the observed transformation and test result rather than claiming a bypass without evidence.

## 6. Reporting

Keep three evidence classes separate:
- **Static candidate:** derived from source code only.
- **Traffic observed:** present in captured in-scope requests/responses.
- **Dynamically validated:** reproduced with evidence on an in-scope endpoint.

Report file coverage and unresolved gaps alongside findings. Never imply that all JavaScript was audited if any in-scope discovered file remains unprocessed.
