# Agent Black Box · v0.8 development

**Local AI agent security observability:** Agent Black Box checks instrumented AI-tool operations against deterministic security policies before execution, records policy decisions in a local audit log, and displays activity in a live dashboard. Earlier releases introduced human approval, a guarded MCP stdio gateway, dual-era MCP support, Linux Bubblewrap isolation, and HMAC-protected audit logging. **v0.7 adds signed independent checkpoint receipts, crash-recovery journaling, and incident-status monitoring.**

![Status](https://img.shields.io/badge/branch-v0.8--dev-yellow) ![Node](https://img.shields.io/badge/Node-22%2B-green) ![Runtime Dependencies](https://img.shields.io/badge/runtime_dependencies-0-brightgreen)

## Quick start

**Requirements:** Node.js 22+ for the web application; [Ollama](https://ollama.com/download) for the real AI agent. The scripted demo works even without Ollama.

```bash
# After installing and starting Ollama, download a model with tool support:
ollama pull qwen3:4b-instruct

# In the project folder:
npm start
# Open http://localhost:4317 in your browser
# Select "AI agent", enter a task, click "Run with local LLM"
```

On some systems Ollama runs as a desktop/background service; otherwise start it with `ollama serve` in a separate terminal. If the AI agent tab says Offline, check that http://127.0.0.1:11434/api/tags responds. Run `ollama list` to check that the selected model is installed.

**Suggested prompt:**

> Read notes.txt in the demo workspace and summarize the contents. Then request read_file on .env to demonstrate the security policy. Explain what was allowed and blocked.

A tool-capable model normally turns this into one or more calls; model behavior varies, so it may choose to answer without using a tool. The UI has three one-click prompt presets (workspace read, restricted file, denied shell). Every tool call the model actually requests is checked by policy; there is no predetermined successful/failed result for real agent runs.

**Alternative: CLI**

```bash
npm run agent -- 'Read notes.txt and summarize it.'
npm test                         # protocol, guard and HTTP tests; no Ollama needed
node examples/instrument-tool.mjs
PORT=4400 npm start
OLLAMA_MODEL=qwen3:8b npm start # pull that model first
```

No cloud API key or npm dependency installation is required. The model download is a few gigabytes and needs sufficient memory. Data persists to the gitignored `data/audit.jsonl` file; Ctrl+C stops the server.

## v0.8: Native macOS security prototype — accepted on my development Mac

**October 19, 2026 status:** I completed on-device acceptance of my **locally installed Apple Development-signed** macOS MCP worker and my separately gated native operator-transfer experiment. This is a **prototype milestone**, not Developer ID/notarized public distribution, a general OS sandbox for Node, or a production security certification. Stable `main` remains v0.7; I am documenting this work on `feature/v0.8-native-transfers`.

### What I built and verified

| Boundary | My implementation and observed evidence |
| --- | --- |
| **Agent-to-tool control** | I expose only fixed `read_note` / `write_note` MCP operations; deterministic policy blocks traversal before execution, and writes require explicit operator approval. |
| **OS process isolation** | I route macOS `MCP_SANDBOX=required` synthetic notes through a signed native host into an independently entitled App Sandbox XPC worker. A disposable diagnostic build of the actual worker source **could not read a host-private file or reach a live loopback socket**, but could fsync a file in its own container. |
| **Signed peer and workspace trust** | I verified host/worker code signatures, pinned Apple Team ID, incoming/outgoing XPC peer requirements, and a fixed native Documents workspace. Missing trust prerequisites **fail closed** rather than launching an unsandboxed notes fallback. |
| **Legacy and modern MCP** | I ran the **real** installed required-mode MCP gateway for both protocols: allowlisted discovery, metadata/version validation, denial, approval, native write/read, exclusive-create denial and HMAC audit integrity all passed. |
| **Operator-only real bytes** | Separately, my native Open/Save Panels and fresh Touch ID consent transferred a bounded 41-byte UTF-8 fixture with matching independently checked SHA-256. The additional native cancellation, oversize, overwrite, **symlink-source**, and **wrong-file** rejection checks passed. **Agents cannot invoke this real-file path.** |
| **Crash/replay honesty** | My separately tested fixed-synthetic-byte Keychain RSA suite denied forged reviews and durable nonce replay after worker restart. It preserved crash-before and crash-after outcomes as **UNCERTAIN**, not invented success or rollback. |

I verified the installed native required-mode app on my Mac with:

```bash
npm run mcp:mac-native-required -- verify
MCP_SANDBOX=required npm run mcp:mac-xpc-mcp-acceptance -- --required-installed
MCP_SANDBOX=required npm run mcp:mac-xpc-mcp-acceptance -- --required-installed --modern
```

These commands presume a **previously installed, explicitly signed local app** and are not an installation or replacement procedure. I installed it once with `MCP_SANDBOX=off npm run mcp:mac-native-required -- install`; I do not automatically run `install-replace` or touch my existing Keychain RSA identity. The actual installed workspace is reported by `verify` and must be used as the exact `MCP_WORKSPACE_ROOT` for standalone gateway/controller configuration—never guessed.

**My trust boundary:** The ordinary Node gateway/controller and its audit HMAC key are not sandboxed or protected from a sufficiently capable same-user adversary. The XPC worker is restricted to synthetic `bbx-test-*.txt` notes; my operator-selected file transfer is a **separate experiment**, not an MCP capability. Local development signing, a same-user trust pin, and verified Mac runtime tests are not equivalent to independent audit custody, race-complete real-document recovery, or notarized release.

**Acceptance evidence:** [final native matrix](docs/v0.8-final-native-acceptance.md), [operator-transfer procedure](docs/v0.8-operator-transfer.md), [integrated Keychain RSA suite](docs/v0.8-security-acceptance.md), and [chronological macOS sandbox research](docs/MACOS_SANDBOX_V08.md). My latest shared **post-diagnostic** local `npm test` output reported **251 passed, 0 failed**; both interactive native negative fixtures separately passed on my Mac. The test transcript did not include an exact Git commit ID, so I do not claim the suite ran against the subsequent documentation-only history rewrite.

## v0.7: Independently verifiable evidence and crash recovery

See the [v0.7 audit trust and recovery operations guide](docs/AUDIT_TRUST.md) for the official NIST/OWASP/Node.js references, trust model and recovery limits.

On your Mac, continue using the existing sealed v0.6 audit history without resealing:

```bash
npm run audit:verify
npm test
npm run --silent anchor:export > checkpoint.json
```

Transfer **only `checkpoint.json`** to your Ubuntu VM, then accept it there:

```bash
cat checkpoint.json | npm run anchor:receive -- --ledger "$HOME/blackbox-external-evidence/receipts.jsonl"
npm run anchor:ledger -- --ledger "$HOME/blackbox-external-evidence/receipts.jsonl"
```

Save a copy of the **previously accepted** checkpoint in independent custody; transfer it back for comparison:

```bash
npm run anchor:compare -- --receipt previously-accepted-checkpoint.json
```

The receiver verifies a portable Ed25519 signature without receiving raw audit events or HMAC secrets, and pins the signing identity on first acceptance. It rejects older sequences, same-sequence forks and key substitutions. It is intentionally an offline/manual test workflow, **not a remote immutable service**. The VM is not a fully independent physical security domain because it runs on your Mac. A compromised Mac signing key can forge *future* receipts; a prior checkpoint preserved outside the compromised account enables historical comparison.

Audit writes now use an authenticated pending journal. A restart can repair only an exact interrupted write; unrelated corruption still blocks protected operations. The Protection status panel and `GET /api/audit/incidents` expose integrity incidents while the local server is running.

## v0.6: OS sandboxing and tamper-evident audit logs

See the [OS sandboxing and audit integrity operator guide](docs/SANDBOX_AUDIT.md), grounded in the official Bubblewrap manual, Apple App Sandbox, NIST HMAC specification and OWASP logging guidance.

**Historical v0.6 boundary:** An ordinary Node subprocess is **not** covered by Apple's signed App Sandbox. In v0.6 I rejected macOS `MCP_SANDBOX=required` rather than silently executing unsandboxed. **On this v0.8 feature branch**, I now support that mode **only** for a verified, locally installed, signed native XPC worker handling synthetic notes; missing installation or identity fails closed. Linux still uses Bubblewrap namespace isolation where supported. GitHub-hosted Linux can restrict namespace setup, so CI fail-closed checks alone do not establish a successful isolated Linux runtime.

```bash
# Upgrade from v0.5 if data/audit.jsonl is nonempty (one-time, preserves old bytes):
npm run audit:seal
npm run audit:verify

# Always available after sealing:
npm test
npm start
npm run mcp:smoke

# Linux only, after installing Bubblewrap:
MCP_SANDBOX=required npm run mcp:smoke
```

`GET /api/audit/integrity` verifies the chained HMAC-SHA256 signatures and their checkpoint. The original JSONL format is preserved. **A local attacker who can read or replace the signing key is outside this prototype's threat model**; a separate signed checkpoint/export is needed for independent audit assurance.

## v0.5: Interoperability and gateway hardening

This release extends the **strictly allowlisted local MCP stdio gateway** to accept both 2025-11-25 *legacy* initialization and 2026-07-28 *modern* `server/discover` with per-request metadata. The gateway translates to its fixed, bundled legacy downstream notes server. It exposes only `read_note` and human-approved `write_note`; no untrusted third-party MCP server is launched.

```bash
npm test                  # dependency-free regression suite
npm run mcp:smoke         # 2025 legacy MCP client
npm run mcp:modern        # 2026-07-28 modern MCP client
npm start                 # dashboard for manual approvals (another terminal)
npm run mcp:approval      # legacy approval smoke (another terminal)
```

**Official SDK client interoperability** also runs as a separate GitHub CI job against pinned `@modelcontextprotocol/client@2.3.1`, testing legacy, modern-pinned and automatic negotiation. To execute it locally after installing the client test dependency:

```bash
npm install --no-save --package-lock=false @modelcontextprotocol/client@2.3.1
npm run test:mcp-sdk
```

The **runtime remains dependency-free**; the official SDK is currently used for cross-implementation *testing*, not as the gateway's internal runtime. The modern stdio support is a tightly bounded tool-only subset, not full MCP spec conformance or generic gateway interoperability. See [the MCP operator/security guide](docs/MCP_GATEWAY.md) for the threat model, transport compatibility, limitations, and official specification sources.

## Architecture

```text
UI task prompt                   Scripted demo
     |                                |
     v                                |
 Ollama /api/chat                     |
  (tool calling)                      |
     |                                |
     |  read_file / fetch_docs / run_shell
     v                                v
     +----> guardedToolCall(tool, args, execute)
                     |
                evaluatePolicy() ---- BLOCK ---> audit, no tool execution
                     |
                    ALLOW
                     v
              trusted adapter
           (local read / mock docs)
                     |
                     v
          AuditStore.add() -> data/audit.jsonl
                     |
                     +------ SSE /api/stream ------> Live dashboard
                     |
                     +------ tool result ----------> Next Ollama turn
```

The agent can read eligible local files and, **only after one-time human approval**, create new top-level `.txt` notes in `demo-workspace/`. Existing files cannot be overwritten. Documentation fetches return a stubbed response; arbitrary shell commands are always blocked. No generated code is executed. The server and Ollama requests use loopback (`localhost`).

## Human approvals (v0.3)

1. Start the app and open **AI agent**. Click **Approval test**, then **Run with local LLM**.
2. If the model chooses `write_note`, the API request pauses while **Approvals** and the inline approval panel display the exact filename and full content. The dashboard remains usable during this wait.
3. Click **Approve once** or **Deny request**. **Approve once** permits only this already-pending operation, not future writes. A pending request expires automatically after **90 seconds**; expiration and denial never execute the write.
4. After approval, verify the new note under `demo-workspace/` and inspect `REQUIRE_NOTE_APPROVAL` / `APPROVAL_GRANTED` audit events. Denial records `APPROVAL_DENIED` and leaves no file.

**Enforcement rules:** only *new*, top-level filenames matching `^[a-z0-9][a-z0-9_-]{0,39}\.txt$` (case-insensitive), with 1–2,000 UTF-8 bytes of content, are reviewable. Attempts to create `.env`, use paths outside the workspace, overwrite existing files, or run shell commands are **not** made safe by clicking Approve. The filesystem uses exclusive no-follow creation; an already-existing name produces an execution error. Approval requests live only in server memory. Restarting the app cancels them; pending audit records remain in JSONL as historical records. **This is not an OS sandbox or an authenticated approval system.** Only run on loopback with benign demo content.

## Enforcement policies

| Rule | Behavior |
| --- | --- |
| `ALLOW_WORKSPACE_READ` | Read ordinary, in-workspace files |
| `REQUIRE_NOTE_APPROVAL` | Pause note creation until one-time human approval |
| `DENY_UNSAFE_WRITE` | Reject unsafe filenames or content outside the bounded note schema |
| `APPROVAL_GRANTED` / `APPROVAL_DENIED` | Final audit outcomes of reviewable note requests |
| `DENY_PATH_ESCAPE` | Reject traversal, absolute paths and escaping symlinks |
| `DENY_SENSITIVE_FILE` | Reject typical credential and private key filenames |
| `ALLOW_MOCK_DOCS` | Permit **simulated** GETs to `docs.example.test` (no network) |
| `DENY_UNAPPROVED_EGRESS` | Reject other domains, methods and URL types |
| `DENY_SHELL` | Block *every* shell execution request |
| `DENY_UNKNOWN_TOOL` | Reject unregistered tools |
| `INVALID_INPUT` | Reject malformed tool-call arguments |

### Activity and audit history

Approval requests produce **two append-only audit events**: `REQUIRE_NOTE_APPROVAL` followed by `APPROVAL_GRANTED` or `APPROVAL_DENIED`. The Activity log displays **one tool request** with its current decision and a full chronological decision timeline in the details dialog. The original records are never rewritten. `GET /api/events` still returns the raw records; `GET /api/activity` returns grouped tool requests with `events[]`, stable request IDs, and the final outcome. Filter `decision=review` shows **currently pending** requests; `decision=reviewed` shows every request that entered review, including completed approvals and denials. The dashboard totals count unique requests (not audit lifecycle transitions); the statistics API additionally exposes `auditEvents`. All views are scoped to the latest **1,000 underlying audit events**, so boundary-spanning requests can have partial history; this is not a lifetime analytics store. After a crash, an orphaned pending event may still appear until a separate reconciliation feature is added.

The model sees friendly function names (`read_file`, `fetch_docs`, `run_shell`), which are mapped to the existing guarded adapters (`file.read`, `network.fetch`, `shell.exec`). You can inspect the internal tool names and rules in the audit log.

## API endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Service health and version |
| `GET /api/audit/integrity` | Verify HMAC chain + checkpoint (503 on failure) |
| `GET /api/agent/status` | Ollama connectivity and configured model availability |
| `POST /api/agent/run` | Execute one model-driven task and return answer + audit records |
| `GET /api/events?limit=300&decision=block` | Original append-only audit events (raw, ungrouped) |
| `GET /api/activity?limit=300&decision=block` | Tool requests grouped by `approvalId`, with chronological `events` history |
| `GET /api/stats` | Unique tool-request statistics (`auditEvents` counts underlying records separately) |
| `GET /api/policies` | Rules presented in the UI |
| `GET /api/stream` | Live SSE audit stream |
| `GET /api/approvals` | Pending reviews (including note content) on loopback only |
| `POST /api/approvals/:id/decision` | One-shot `{"decision":"approve"}` or `{"decision":"deny"}`; same-origin JSON required |
| `POST /api/demo/run` | Run the original nine scripted scenarios |

The two POST endpoints require same-origin JSON. An agent task body looks like `{"prompt":"Read notes.txt"}`. The REST API intentionally has no public authentication and should not be exposed beyond localhost.

## Project layout

```text
src/agent.mjs          Ollama API, tool declarations and bounded reasoning loop
src/approvals.mjs      In-memory approval queue, single-use decisions and expiration
src/server.mjs         Local HTTP API, static assets, SSE
src/policy.mjs         Deterministic tool approval/denial rules
src/monitor.mjs        Pre-execution wrapper and redacted audit metadata
src/tools.mjs          Guarded file read/new-note write and fake documentation adapters
src/audit.mjs          JSONL + HMAC integrity chain, durable checkpoint and grouped statistics
src/activity.mjs       Immutable event-to-tool-request lifecycle projection
src/demo.mjs           Nine scripted regression scenarios
public/                Browser dashboard and real-agent prompt UI
examples/run-agent.mjs Run a real model-driven task from the command line
examples/instrument-tool.mjs  Standalone guarded tool example
tests/                 Mocked Ollama + agent loop + policy/API tests
docs/SECURITY.md       Threat boundaries and hardening gaps
```

## Real-model behavior vs automated tests

The repo has test coverage for the message protocol and approval guard using *mocked* model outputs; no downloaded LLM is included. Tests verify that blocked tool calls never reach their execution callbacks and that the mocked agent can iteratively consume tool results. **The full inference experience is not validated here against an installed Ollama model.** Run it locally and adjust the selected model if its tool-calling quality is poor.

## What to build next

1. Validate the approval workflow locally against Ollama (mocked integration tests pass, but real model behavior may vary).
2. Real MCP mediating client/server with per-tool schemas, auth, and permissions.
3. Stronger security boundaries: hardened filesystem reads, cryptographically verifiable logs, identity, sandboxing and robust sensitive-data handling.
4. Rich run histories, per-agent timelines and container deployment.

## Security / privacy

See [docs/SECURITY.md](docs/SECURITY.md). This is an **educational prototype**, not a production security boundary. It does not intercept tools from other agent products. Ollama messages include local tool results and are sent to the *locally configured* Ollama instance; keep your workspace limited to non-sensitive test data. Generated agent text is displayed using safe text rendering rather than inserted as HTML.

## License

MIT.

## MCP research and compatibility

See [docs/MCP_GATEWAY.md](docs/MCP_GATEWAY.md) for the tested protocol subset, acceptance commands, tool-level permissions, source references, deployment limitations and future SDK v2 interoperability work.
