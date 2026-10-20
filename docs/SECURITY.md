# Security model and limitations

**Current scope (v0.8):** I maintain Agent Black Box as a local educational security-engineering prototype, **not** a hardened, independently audited product. My original Node policy and MCP demo remain routing-dependent; the separately installed macOS App Sandbox XPC worker is a narrower OS enforcement boundary for fixed synthetic note operations only. See [the native acceptance record](v0.8-final-native-acceptance.md).

## Enforcement boundary

`guardedToolCall` evaluates each request before it invokes the supplied `execute` callback. It protects **only callbacks routed through this function** and assumes that trusted adapters actually perform the operation described by the tool name. An untrusted or miswired adapter could violate policy even when metadata is approved. v0.4 additionally monitors tool traffic **explicitly routed through the bundled local MCP stdio gateway**; it does not intercept other MCP connections, sandbox host processes, or stop agents from bypassing the gateway. The demo can perform a read of a harmless file in `demo-workspace`; its HTTP tool is **entirely simulated** and its shell tool is **always denied**. v0.3 can create a new top-level `.txt` file with exclusive creation **only after a single-use human authorization**.

## Audit logging

Events are written to `data/audit.jsonl`; no file contents or full URL query strings are intentionally logged. Only abbreviated tool names, argument summaries, policy decisions and result summaries are stored. Pattern-based redaction is best-effort; **never run on real secrets or untrusted production inputs**. Storage is local but not encrypted, authenticated or tamper-evident. A malicious host user can edit the log.

## Human approval boundaries (v0.3)

An operation is never executed merely because the agent requests approval. The guard logs a `review` event, pauses for a unique approval ID, and executes only the **already-evaluated, immutable filename and content** after an explicit one-time local decision. The approval expires after 90 seconds, or is denied on shutdown/error/missing approval service. The review request and its resolution are separate audit records with the same `approvalId`. Approval only applies to a new, small, top-level `.txt` note. No shell, arbitrary paths, `.env`, network egress, or file overwrite permission is granted. Writes are opened with `O_EXCL | O_NOFOLLOW` and mode `0600`.

Pending approval payloads are **in volatile memory**, including the proposed note content. The local GET `/api/approvals` exposes that content to the person reviewing it; the JSONL audit records retain only a filename summary. Approval status is not durable across process restarts; orphaned `review` log records may remain after a crash and are historical, not active requests. An `ALLOW` audit record means a policy or approval permitted attempted execution; always inspect `outcome` to confirm whether it actually succeeded.

This single-user localhost prototype has no user login or operator authentication. Same-origin JSON checks and loopback binding are not a secure substitute for authenticated approvals in a deployed product.

## Web interface

The server listens on loopback only, validates Host, requires a same-origin JSON request to start demos, limits SSE clients and uses CSP. This is not an authenticated multi-user dashboard; do not reverse-proxy it onto the public internet.

## Filesystem / race limitations

Reads are confined to a workspace using canonical path checks before execution, including symlink boundary checks. A write-capable adversary racing filesystem changes could undermine simple path checks. Real production containment needs an OS sandbox, file descriptor based confinement, privileges dropped, mount isolation, and resource limits.

## MCP v0.4 security boundary

The supported MCP gateway is narrow: it permits two allowlisted tools on a single bundled local downstream subprocess, validates all forwarded calls through the existing guard, reuses the local time-limited approval queue for note writes, and records the lifecycle in the JSONL log. Unsupported methods, tools, malformed frames, unavailable approvals, and out-of-bound data fail closed. The gateway-to-dashboard bearer token is local and mode-0600, but **not protection from processes with the same operating-system identity**. The manual JSON-RPC subset is **not complete MCP 2026 interoperability**; see [MCP_GATEWAY.md](MCP_GATEWAY.md).

## Next steps toward production readiness

1. Introduce a single enforced tool dispatcher for a supported framework (e.g. OpenAI Agents SDK), including unique run IDs, schemas, and centrally enforced human approval.
2. Upgrade the narrow MCP 2025 stdio adapter to the official MCP TypeScript SDK v2 for broad 2026-era negotiation, capability handling, full message semantics, interoperability tests and remote server support; do not claim production MCP support until then.
3. Add schema validation, per-tool configurable policies, encrypted/tamper-evident storage, robust identity and authentication, rate limiting, durable ingestion, redaction filters, and observability telemetry.
4. Add a process sandbox for commands and network restrictions at OS/proxy level, not just application policy.

## Model-driven integration (v0.2+)

The `src/agent.mjs` Ollama client sends task prompts, tool definitions and tool results to a **loopback-only** Ollama HTTP address. It accepts only explicit localhost/127.0.0.1/[::1] HTTP endpoints set by the local operator; users cannot point it at arbitrary network services from the web UI. Ollama is a separate process outside this project's control and may have its own logging or configuration. **Do not include confidential information in the workspace.**

The agent loop permits at most 6 model rounds and 12 requested tool calls; malformed arguments are passed through the fail-closed guard. Only a small fixed set of trusted adapter functions is available, including an approval-gated, exclusive-create note adapter. The shell tool exists to demonstrate **denial**, not to execute commands. Network documentation responses are simulated. These are application-level restrictions, not operating system sandboxing or privilege separation.

Prompts and file contents might contain prompt injection; the system prompt tells the model to ignore instructions from files, but that text is not a sufficient defense by itself. Safety is enforced by the tool dispatcher and its trusted adapters. Logs deliberately omit file contents and model answers, but pattern-based data redaction is not comprehensive, and file contents are returned to the local model for reasoning. Use only benign demo data.

The UI is designed for a single trusted local operator. It is not authenticated, so never publish the port, embed the dashboard in other sites, or expose it via a reverse proxy. The Ollama endpoint should likewise remain local. Browser requests to start the agent require a matching `Origin` and JSON content type; network threats and local malware are not fully addressed by these checks.


## v0.8 macOS required-mode and operator-only acceptance

On October 19, 2026, I completed **real-Mac native acceptance** of my explicitly installed, Apple Development-signed required-mode host/XPC worker. I verified the canonical worker-owned workspace, independently pinned local Team identity and both peer-requirement directions; a disposable signed diagnostic build of the required-worker source was denied access to a host-private file and a reachable loopback listener but could write/fsync in its sandbox Documents root. I then exercised both legacy and modern **real MCP gateway** paths with policy traversal denial, human approval/denial, native XPC read/write, no-clobber and fresh HMAC audit checks.

I separately tested native operator-only file selection, fresh Touch ID, bounded bytes and independent SHA-256 readback/export, with explicit cancellation, oversize, existing-destination, symlink-source and wrong-file denials. **Neither legacy nor modern MCP exposes that real-file operation.** The standalone synthetic Keychain RSA integrated suite also passed durable nonce replay/restart and pre-/post-reservation uncertain-crash tests. I did not interpret crash markers as real-document commits.

**My remaining threat limits:** the Node process/controller is outside the worker's OS sandbox; same-user access to HMAC/audit and Keychain/trust records can undermine provenance; native signing uses local Apple Development identity, not Developer ID/notarized distribution. The installed XPC worker accepts only a bounded synthetic test-note grammar, not arbitrary tools or paths. I have not established atomic real-document recovery, exhaustive malicious filesystem races, or independent human/controller authorization against same-user compromise. The diagnostic source build is not a byte-identical installed binary; the installed signatures and entitlements are verified separately.

This v0.8 mode **fails closed** when the signed installation, pin, entitlements, expected workspace, native handshake or peer verification is invalid. `MCP_SANDBOX=off` is still an unsandboxed demo setting, not a security claim. The following v0.5 and v0.6 sections document historical design boundaries and should not be read as a claim that the current v0.8 required-mode XPC worker is absent.

## v0.5 MCP compatibility/hardening limits

The gateway now serves the documented 2026-07-28 modern MCP tool subset as well as the 2025-11-25 legacy subset; unknown protocol revisions and missing modern metadata are rejected. Downstream initialization now follows the legacy notification order. A cancelled forwarded request terminates the downstream process, but an earlier side effect remains possible and must be considered **outcome uncertain**. Do not interpret cancellation as atomic rollback. **In that v0.5 release**, the downstream was an unsandboxed executable with the invoking user's OS privileges and the audit file lacked keyed integrity. I later added v0.6 HMAC journaling and, on the v0.8 feature branch, a separately signed/sandboxed macOS required-mode XPC worker for synthetic notes. These improvements do not establish multi-user or independently trusted production security.


## v0.6 OS sandbox and audit integrity

See [SANDBOX_AUDIT.md](SANDBOX_AUDIT.md). Linux `MCP_SANDBOX=required` uses Bubblewrap and refuses to run without a functioning sandbox. On macOS the standard **Node controller** remains **not OS-sandboxed**; my v0.8 feature branch instead requires an explicitly installed and verified signed/entitled App Sandbox XPC worker for the narrow `required` synthetic note operations. New audit entries are checked with keyed HMAC-SHA256 and a local checkpoint. These local artifacts are tamper-evident against accidental/unauthorized edits *without the key* but are not independently immutable or safe from a same-user attacker. Legacy history requires explicit trust-on-first-use sealing before v0.6 begins.
