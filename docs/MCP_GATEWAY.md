# MCP gateway: protocol subset, approval and native-mode security

> **Version context:** I retain my v0.5 gateway notes and protocol constraints below, but on the v0.8 feature branch I also support **explicitly installed, Apple Development-signed macOS `MCP_SANDBOX=required`** for fixed synthetic notes through a separately App Sandbox-entitled XPC worker. My Node policy, approval and HMAC audit controller remains unsandboxed. I verified both legacy and modern required-mode MCP flows on my Mac; see [the actual acceptance evidence](v0.8-final-native-acceptance.md).

## What is implemented

I implement a **real MCP stdio gateway** (`src/mcp-gateway.mjs`) launched by an MCP client as a child process. In the default `MCP_SANDBOX=off` demo, it launches my fixed bundled Node notes server (`examples/mcp-notes-server.mjs`) and forwards only allowlisted, policy-authorized `tools/call` requests over bounded UTF-8 JSON-RPC 2.0. **On macOS with `MCP_SANDBOX=required`**, it instead uses a fixed native adapter that reaches the verified, signed host and private XPC worker. These two modes are **not interchangeable security boundaries**.

```text
MCP host/client
    | stdio: legacy initialize OR modern metadata/discover, tools/list, tools/call
    v
Agent Black Box gateway (child process)
    | deny unknown tool/method; validate schema; apply existing policies
    |  read_note: ALLOW / DENY
    |  write_note: REVIEW / DENY -> localhost approval controller, 90-second expiry
    |  audit JSONL before/after execution, grouped by stable approvalId
    v
Allowlisted downstream (Node demo server in off mode; verified native XPC adapter in Mac required mode)
    | read_note (real UTF-8 read)
    | write_note (new file only; O_EXCL + O_NOFOLLOW, 0600)
    v
Demo workspace (off mode) / worker-private Documents scratch root (Mac required mode)
```

The existing dashboard on `127.0.0.1:4317` is the approval controller. All MCP lifecycle events appear in the same local audit file. Because the gateway runs in a separate process, the dashboard also polls its audit projection every 3 seconds; its Server-Sent Events channel covers events originating from the dashboard process only.

## Protocol compatibility (official 2026-07-28 specification)

On a new **stdio connection**, the gateway pins one of two protocol eras:

- **Legacy `2025-11-25`:** `initialize` followed by `notifications/initialized`, then `tools/list`, `tools/call`, `ping`, cancellation. The downstream receives its own separate legacy handshake and initialized notification **before tool discovery**.
- **Modern `2026-07-28`:** Optional `server/discover` with `params._meta` protocol version/client capabilities; or direct `tools/list`/`tools/call` with per-request metadata; no initialize handshake; version/identity/capabilities validated **for each request**. `tools/list` and `tools/call` respond with modern `resultType: "complete"` and `_meta['io.modelcontextprotocol/serverInfo']`. Unknown versions receive `-32022` with supported versions. A connection cannot switch eras.

There is **no direct network MCP listener**. Other RPC families including resources, prompts, sampling, subscriptions, task extensions, and multi-round-trip `input_required` are not supported. Modern `ping` is not a supported method. Only `read_note` and `write_note` are exposed; downstream `shell_command` remains hidden and denied. I limit tool-call results to my bounded text-note protocol; in installed macOS required mode these operations execute in the private native XPC worker, not an arbitrary bundled or third-party downstream.

I intentionally keep a compact, manually maintained wire implementation because this is a **gateway prototype**, not a complete SDK server. An official `@modelcontextprotocol/client` v2 interoperability suite runs in CI for both protocol eras, alongside the dependency-free tests. Full adoption of the official v2 **server** SDK, remote transports and arbitrary downstream targets is **not claimed**.

## Test it today

From the repository root (Node.js >=22):

```bash
npm test             # protocol parsing, real downstream stdio calls, approval, denial, cancellation, timeouts
npm start            # terminal 1: keep approval dashboard open
npm run mcp:smoke    # terminal 2: 2025 legacy client, read and denial
npm run mcp:modern   # terminal 2: 2026-07-28 modern client, read and denial
npm run mcp:approval # terminal 2: also requests note creation; approve/deny in dashboard
```

Open http://localhost:4317 in a browser. For the approval smoke test, select **Approvals** and review the exact generated filename/content. Do not approve unknown requests. The `demo-workspace` directory contains only harmless sample notes.

### MCP client configuration example

Configure an external MCP host that supports **stdio** with the following conceptual `mcpServers` entry. Replace the path with the **absolute** path on your machine and keep the dashboard server running to allow note creation:

```json
{
  "mcpServers": {
    "agent-black-box": {
      "command": "node",
      "args": ["/absolute/path/to/agent-black-box/src/mcp-gateway.mjs"]
    }
  }
}
```

MCP host configuration format and version negotiation differ by application. For an app using an MCP client SDK, connect via `StdioClientTransport` with the legacy handshake. Do not configure the downstream notes server as an MCP host directly: doing so bypasses this gateway.

### Local configuration

- `MCP_WORKSPACE_ROOT`: absolute path to benign demo workspace (defaults to `<repo>/demo-workspace`).
- `MCP_AUDIT_FILE`: audit JSONL file used by the dashboard (defaults to `<repo>/data/audit.jsonl`).
- `MCP_CONTROLLER_PORT`: dashboard port for approval requests (defaults to `4317`); matches dashboard's `PORT` when customized.
- `MCP_TOKEN_FILE`: dashboard-created, mode-0600 local bearer credential path (defaults to `<audit directory>/mcp-controller-token`).

Start the **dashboard first** so it can generate its ephemeral token. The token is regenerated on every restart; pending approvals fail closed if the dashboard goes away. Do not check in or expose the token. The token is not forwarded to the downstream child. The `data/` directory is gitignored.

## Security guardrails

1. **Allowlisted tool names**: Only `read_note` (`file.read`) and `write_note` (`file.write`) appear in `tools/list` and can be forwarded. Extra tools advertised by the downstream (e.g. `shell_command`) are hidden and denied even when called directly.
2. **Hard block before forwarding**: The gateway calls the original deterministic policy engine, rejects invalid arguments, unsafe filenames, `.env`, traversal, symlink escapes, and unsupported method families. The downstream also independently validates its filesystem operations.
3. **Time-limited explicit approval**: `write_note` pauses in the guarded callback, generates a unique ID, and submits the immutable filename/content to the localhost approval queue. Only a matching one-time approval permits the pending downstream `tools/call`. Denied, expired, disconnected, and unavailable approvals cannot authorize a write.
4. **Audit**: Events are appended with bounded, redacted input summaries. A request is represented by a stable `approvalId` and separate start/result records; the dashboard groups these into one visible request with a timeline. Audit payloads intentionally omit file contents and raw tool outputs.
5. **Process boundaries**: The gateway uses `spawn(process.execPath, [...], { shell:false })` to launch **only the bundled downstream**. The child receives a restricted environment that excludes the approval bearer token and other inherited secrets.
6. **Protocol limits**: 16 KiB inbound JSON-RPC message bound, 64 KiB outbound downstream request bound, 128 KiB downstream response bound, max eight in-flight calls, 12-second downstream deadline, and a 90-second approval deadline. Incoming frames must be valid UTF-8 (malformed byte sequences are rejected). Oversized frames and unexpected server-initiated requests close the downstream connection.
7. **Cancellation**: If the host cancels before forwarding, the approval request aborts and the callback is never invoked. Once forwarded, cancellation terminates the downstream process, but **cannot guarantee rollback** of a side effect that already happened. The audit records `MCP_OUTCOME_UNKNOWN` for a post-forward cancellation; do not interpret it as a prevented write.

## Known limitations (important)

- **Mode-specific OS sandbox**: In `MCP_SANDBOX=off`, the Node notes downstream is not OS-sandboxed and a caller can bypass gateway policy by launching another tool directly. In my **installed macOS `required` mode**, the fixed **XPC worker** is App Sandbox-entitled and signed, but the parent Node gateway/controller remains unsandboxed. This is not generic third-party server containment.
- **Not complete modern MCP**: the 2026-07-28 era requires many surfaces we do not implement. This is a bounded stdio `server/discover`/tool subset, not a certification of protocol conformance.
- **Interoperability bounds**: the custom JSON-RPC implementation has official MCP v2 *client* interoperability tests in GitHub Actions, but no full conformance certification, Streamable HTTP, or broad commercial-host test matrix. This is not proof of general MCP conformance.
- **Same-user threat**: a local process running as the same OS user can read the controller token. The dashboard also lacks multi-user authentication. Never expose the controller over a network.
- **Race / filesystem semantics**: canonical-path checks are best-effort; a separate low-privilege OS sandbox, directory-fd confinement, and mount isolation are needed before operating on untrusted files.
- **Not exactly-once or crash-durable**: if a downstream call times out or the process dies after doing work, its effect may have happened. Approval state lives in memory; an abrupt process death may leave an orphaned pending audit event.
- **Audit provenance remains local**: My v0.6+ `AuditStore` uses HMAC-chained records, an authenticated journal and checkpoints; this detects tampering without the secret, but does **not** independently protect against same-user compromise of the Node-held secret or constitute immutable external audit custody.
- **No multi-tenant policy engine**: tool names, process and argument schemas are fixed to the bundled demo. Generic upstream config, schema attestation, identity and least-privilege process isolation belong to a later milestone.

## Research references

- [MCP 2025-11-25 lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [MCP 2025-11-25 tool schemas, list and call](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP stdio transport and stdout restrictions](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP 2026-07-28 stateless transport semantics](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [Official TypeScript SDK v2, the stable release line](https://ts.sdk.modelcontextprotocol.io/v2/)
- [Official v2 protocol-era migration](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28)

### v0.5 official references

- [MCP 2026-07-28 versioning & backward compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [MCP 2026-07-28 stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
- [MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Official TypeScript SDK v2 protocol-era negotiation](https://ts.sdk.modelcontextprotocol.io/v2/protocol-versions)
- [Official TypeScript SDK v2 migration details](https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28)


## v0.6 process isolation

**Historical v0.6**: I used Bubblewrap for Linux required mode and refused macOS required mode rather than substituting an unsandboxed Node process. **Current v0.8 feature branch**: On macOS the requested `required` mode succeeds only when I have explicitly installed and verified my signed XPC host/worker, enrolled local Team ID pin and exact worker workspace. Missing credentials, signatures, entitlements or workspace cause fail-closed refusal. I verified that exact path with both legacy and modern real-MCP acceptance tests on my Mac. The native worker accepts only bounded synthetic notes; the separate operator file picker is never exposed as an MCP tool. See [SANDBOX_AUDIT.md](SANDBOX_AUDIT.md) and [the native acceptance record](v0.8-final-native-acceptance.md).
