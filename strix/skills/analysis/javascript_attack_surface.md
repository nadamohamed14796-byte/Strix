---
name: javascript-attack-surface
description: Deep JavaScript asset analysis for API contracts, security-sensitive functions, authorization boundaries, and evidence-backed test hypotheses
---

# JavaScript Attack Surface Analysis

## Mission and sequencing

Run as a dedicated child of the web-crawling/reconnaissance agent immediately after the initial crawl and technology fingerprinting. The parent owns crawling and asset collection; this child owns deep JavaScript analysis. Analyze all discovered in-scope first-party assets, then revisit when new chunks/routes are discovered.

Collect and deduplicate JavaScript from HTML script/modulepreload/preload links, dynamic imports, lazy route chunks, workers/service workers, inline scripts and hydration data, authenticated pages, and available source maps/original sources. Include scripts discovered through login, signup, recovery, profile, billing, organization/team, member, admin, integration, upload and file flows. Do not assume a filename such as login.js contains the entire flow; trace imports and API calls.

## Endpoint and API contract inventory

For every endpoint reference, correlate static declarations with observed proxy/network traffic. Record:
- Canonical URL/path template, origin/base URL, API version, and each distinct HTTP method variant.
- Every path/query/body/form parameter, including hidden, derived, defaulted and optional values; source of value and type/format when evidenced.
- Actual client-set headers: content-type, accept, auth scheme, CSRF/XSRF, tenant/org/workspace identifiers, version/custom headers, idempotency and tracing. Record header names and schemes, never raw secrets.
- Cookie/session assumptions, token source/refresh behavior, credential inclusion mode, role/state prerequisites, request body and response/error shapes where observed.
- Callsite, function/symbol, source file and line/range, page/route, and provenance.
- Client-side validation, normalization, encoding, escaping and sanitization conditions, with exact code location. Clearly distinguish UX/client validation from server-side enforcement.
- Evidence class: STATIC_ONLY, OBSERVED_ONLY, or STATIC_AND_OBSERVED; confidence and unresolved assumptions.

Do not merge different methods into a generic endpoint. Preserve observed-only methods and mark static declarations unobserved until traffic confirms them. Never invent methods, headers, parameters, or schemas.

## Deep function and flow analysis

Use AST/parser tooling where available; otherwise perform structured source review and state limitations. Trace imports, call graphs, request wrappers/interceptors, state stores, route guards and source-to-sink/data flows.

Prioritize:
- Login, signup, password reset/recovery, MFA, SSO, session refresh/logout, invitations and redirects.
- Organization, tenant, workspace, project, team, member, role, permission, owner and account identifiers.
- Authorization/ownership checks, feature gates, object scoping and state transitions.
- Input validation, normalization, encoding, sanitization, deserialization and rendering.
- Upload/download, export/import, GraphQL, WebSocket, payment/billing, integrations, webhooks and admin operations.
- Hidden parameters, debug flags, alternate API versions, client-only checks and fallback paths.

For each important function record file/line, inputs/outputs, callers/callees, relevant state, network calls, security checks, and unknowns. Do not label a function vulnerable just because one client-side check is absent; server-side enforcement may exist and must be validated.

## Evidence-backed Attack Survey scenarios

Create hypotheses, not findings. Each item identifies exact page/flow, endpoint and method, relevant parameters, source/function evidence, expected security boundary, reason for suspicion, prerequisites, confidence/priority, minimal safe validation plan, and proof/refutation criteria.

Examples:
- A request carries both object ID and organization/tenant ID, while a client helper appears to check only the user or object ID: add a cross-tenant authorization hypothesis for server-side verification, not an assumed IDOR.
- A hidden/derived parameter affects a request but appears to miss the client validation applied to visible fields: add a validation-consistency hypothesis.
- A role/permission decision appears only in client state or a route guard: verify server-side authorization.
- Login/recovery flows contain alternate endpoints, redirect/state flags or MFA transitions: map authentication logic hypotheses.
- A value reaches a rendering sink after transformations or without an evident contextual control: link it to the XSS validation workflow; reflection alone is not proof.

Use only authorized test accounts and non-sensitive canary objects. Do not perform destructive operations, mass enumeration, credential/session theft, or cross-tenant data extraction. Stop once the relevant boundary is established.

## Canonical artifacts and persistence

Maintain one shared Attack Survey ledger, merging into an existing scan ledger if present. Otherwise create:
- `/workspace/recon/javascript/manifest.json`
- `/workspace/recon/javascript/assets.jsonl`
- `/workspace/recon/javascript/endpoints.jsonl`
- `/workspace/recon/javascript/functions.md`
- `/workspace/recon/javascript/attack-survey.md`

Deduplicate assets by canonical URL plus content hash and endpoints by canonical path/method while preserving source/callsite variants. Keep raw bundles/source maps out of the ledger; retain references, hashes and bounded excerpts. Never store raw API keys, tokens, cookies or secrets; use redaction and fingerprints only.

Each Attack Survey item requires stable ID, category, title, page/endpoint/method, source evidence, parameters, security boundary, hypothesis, minimal validation steps, expected proof/refutation, prerequisites, confidence, priority, status (UNTESTED / IN_PROGRESS / CONFIRMED / REFUTED / NEEDS_SOURCE_OR_RUNTIME_EVIDENCE), and artifact references. Persist shared workspace files and create/update one concise scan note pointing to them. Keep negative results and counterevidence.

## Handoff

Send the parent counts of JS assets analyzed/skipped, source-map coverage, unique endpoint/method variants split by provenance, important functions/flows, top hypotheses, artifact paths and coverage gaps. The parent and later agents must read the ledger. Spawn focused validation agents from prioritized hypotheses rather than rediscovering endpoints or blindly fuzzing parameters. Update the same records as runtime evidence arrives; preserve provenance and history.
