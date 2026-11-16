---
name: javascript_attack_surface
description: Exhaustive file-by-file analysis of every discovered in-scope JavaScript asset with incremental synchronization to recon and downstream validation
---

# JavaScript Asset Analysis

## Mission

Perform a complete, systematic analysis of the collected JavaScript corpus. This is an asset-coverage task, not a hunt for a predefined endpoint, filename, framework, vulnerability class, or scenario.

**EVERY discovered in-scope JavaScript asset must be accounted for and reviewed individually.** Do not choose files based on names such as login, auth, admin, api, or on whether an initial scan considers them interesting. Do not stop after finding a few useful endpoints or likely vulnerabilities. Names, folder locations, bundle size, and apparent business purpose must not determine whether a file is analyzed.

The analyst is responsible for analysis and durable evidence. It does not own or pause the crawler, root agent, or unrelated reconnaissance/testing work.

## Complete asset inventory and file-by-file processing

Consume the complete crawl asset manifest and all discovered in-scope first-party JavaScript. If the crawler has not produced a manifest yet, request the current crawl inventory and initialize the canonical manifest from every discovered script candidate; do not wait for the crawl to finish. The crawler remains the sole owner of discovery records, while the analyst owns per-asset analysis status and analysis artifacts. Publish updates incrementally with stable IDs and atomic file replacement where supported:

- External scripts and bundles, including minified files and versioned/chunked bundles.
- Inline scripts and script blocks extracted from HTML.
- ES modules, dynamic imports, lazy-loaded route chunks, workers and service workers.
- JavaScript loaded after page navigation or UI state changes, including authenticated pages where available.
- Source maps and original sources when accessible and in scope.
- JavaScript-like assets embedded in HTML, JSON bootstrap/hydration data, or downloaded application resources where they contain executable client logic.

Create one manifest entry for every discovered asset. Deduplicate exact duplicates by canonical URL and content hash, but preserve all discovery locations and aliases. Do not silently discard a duplicate URL with different content: treat each distinct content hash/version as a separate revision. Record non-JavaScript or unreadable candidates as skipped with a precise reason.

Process the manifest deterministically, one asset at a time, and mark each entry PENDING, IN_PROGRESS, ANALYZED, PARTIAL, FAILED, or SKIPPED with reason. Record the content hash, source URL/path, size, type, discovery page, auth state, source-map relation, analysis timestamp, and artifact references. Resume from unfinished entries after interruption; never restart completed work unnecessarily. If the corpus is too large for one context, process bounded batches and continue until every entry has a terminal status. Batching is a context/runtime technique only: it must not become a relevance filter or cause assets to be omitted.

When new scripts arrive from continued crawling, append them to the same manifest and process them without redoing unchanged assets. If an asset changes, analyze the new hash as a new revision and link it to the prior revision.

## Per-file analysis contract

For each asset, inspect its complete available content. Use an AST/parser when available and suitable; otherwise perform structured source review and record the limitation. Do not rely on filename heuristics or regex-only extraction. Trace imports, exports, module relationships, call sites, wrappers, interceptors, state stores, route registration, data flow, and source-to-sink paths where feasible.

For every file, record:
- What the file does, its module role, imports/exports, callers/callees, routes/pages that load it, and related assets.
- Every endpoint/API reference, each separate HTTP method when evidenced, path/query/body/form parameters, hidden or derived values, request construction, actual client-set headers, auth/session assumptions, request/response/error handling, and callsite/source locations.
- Validation, authorization-related client checks, normalization, encoding, escaping, sanitization, parsing, and rendering behavior, including the exact function/condition and data affected.
- Inputs and outputs, user-controlled sources, sensitive data handling, storage mechanisms, trust boundaries, feature/role/tenant state, and security-relevant side effects.
- Dynamic/runtime traffic correlation when available, clearly distinguishing STATIC_ONLY, OBSERVED_ONLY, and STATIC_AND_OBSERVED evidence.
- Functions and code paths that are unclear, unreachable, generated, obfuscated, or only partially understood, with explicit follow-up needs.

Do not infer an HTTP method, header, parameter, server-side control, or runtime behavior without evidence. Client-side validation is not proof of server enforcement. Do not treat a string, route, or endpoint reference as a confirmed vulnerability.

## Corpus-wide correlation after per-file review

After processing files, correlate findings across the complete corpus:
- Merge repeated endpoint references while retaining every file, callsite, method variant, and evidence source.
- Connect client wrappers/interceptors, token/session handling, shared validation helpers, route guards, state stores, and API clients to their consumers.
- Identify where one file constructs values that another file validates, transforms, stores, or sends.
- Correlate static endpoint declarations with captured network traffic without erasing static-only or observed-only distinctions.
- Identify inconsistencies or missing evidence across modules; describe uncertainty rather than filling gaps with assumptions.

Do not limit correlation to a predefined list of application features. Review all discovered modules and record the security-relevant behavior that is actually present.

## Attack Survey

Populate the shared Attack Survey from evidence discovered during the complete review. Scenarios are generated from the code and traffic; they are not a fixed checklist and must not constrain what files or behaviors are examined.

Each hypothesis must reference exact assets, functions/callsites, endpoint and method where applicable, parameters, relevant trust boundary, evidence, assumptions, prerequisites, safe validation approach, and proof/refutation criteria. Label it as a hypothesis, not a finding. Preserve low-confidence leads, counterevidence, negative results, and items that need runtime or server-side verification. Do not invent an issue merely to fill the survey.

The Attack Survey is a handoff queue for downstream agents. Other agents may begin work on independently ready hypotheses while analysis continues; they must read existing evidence and avoid duplicating the analyst's file-by-file work. As additional evidence appears, update the existing item rather than creating duplicate entries.

## Shared artifacts

Use one canonical shared workspace location, merging with existing scan artifacts instead of creating parallel ledgers:
- `/workspace/recon/javascript/manifest.json` — complete asset inventory and per-file status.
- `/workspace/recon/javascript/assets.jsonl` — per-file analysis records and provenance.
- `/workspace/recon/javascript/endpoints.jsonl` — canonical endpoint/method records with all callsites and evidence.
- `/workspace/recon/javascript/functions.md` — function, module, call-graph, and data-flow analysis.
- `/workspace/recon/javascript/attack-survey.md` — evidence-backed hypotheses and validation state.

Keep large raw bundles and source maps in their original workspace locations; reference paths and hashes instead of duplicating them into reports. Redact API keys, tokens, cookies, and other secrets. Never store raw credentials in the ledger.

Use stable IDs. Writes must be incremental and idempotent: append new records, merge evidence into existing IDs, and preserve history. Never replace a completed record with a less complete one. Store partial progress frequently enough that interruption does not lose the entire corpus analysis.

## Synchronization and concurrency

- The crawler owns discovery and continues its normal work. The JavaScript analyst is a child/subtask that consumes the shared asset manifest; spawning it must not pause or replace the crawler.
- The analyst works asynchronously. The crawler, root, and unrelated subagents continue independent tasks; do not call a blocking wait merely to make JavaScript analysis finish before those tasks can proceed.
- The crawler publishes newly discovered assets incrementally. The analyst consumes those additions through shared files or concise batched handoffs and acknowledges them in the same manifest. Avoid noisy per-file inter-agent messages.
- Downstream agents may consume already analyzed records and ready hypotheses while the remaining corpus is being processed. They must mark which evidence revision they used and refresh it when material updates arrive.
- The root tracks the analyst as active work and must not declare the overall scan complete while assets remain PENDING, IN_PROGRESS, PARTIAL, or FAILED without an explicit disposition. This final completion check must not block unrelated work during the scan.
- Use bounded batches and existing agent/runtime limits. Do not spawn one child per file by default. If parallel analysis is necessary, split into deterministic, non-overlapping batches and keep a single parent-owned manifest and deduplication authority.
- If the analysis child fails or stops, preserve its progress and let the parent resume the unfinished manifest with a replacement child. Do not rerun completed assets or lose the crawler's progress.

## Handoff

Report total discovered assets, unique content revisions, analyzed/partial/failed/skipped/pending counts, coverage by source type, endpoints and method variants with provenance, functions/modules reviewed, hypotheses created, and unresolved gaps. Include canonical artifact paths. A completion claim is valid only when every manifest entry has a terminal status and every skipped/failed item has a reason.