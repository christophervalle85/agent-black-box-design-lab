# v0.8 design gate: native macOS App Sandbox and XPC isolation

> **Current result — October 19, 2026:** I completed on-device acceptance of the **locally Apple Development-signed** native required-mode MCP prototype on `feature/v0.8-native-transfers`. The installed host/worker passed signature, Team ID, entitlement, peer-identity and canonical Documents workspace verification. My separately signed **diagnostic build of the final worker source** demonstrated real OS denial of host-private file and reachable loopback access with allowed container scratch writes. Both **legacy and modern** `MCP_SANDBOX=required` gateway-to-XPC-to-audit acceptance runs passed. I also accepted the separate operator-only real-byte import/export negative matrix and integrated synthetic Keychain RSA replay/crash suite. **The Node controller is still unsandboxed; the native worker handles only bounded synthetic notes; this is not Developer ID/notarized production distribution or an arbitrary MCP transfer service.** I maintain the authoritative results and unresolved limits in [my v0.8 native acceptance record](v0.8-final-native-acceptance.md).

> **Reading this journal:** I am preserving the sections below as a dated, chronological **engineering history**. Labels such as “pending,” “next gate,” or “macOS required mode refuses” describe each *historical phase*, not the current accepted local-prototype state. My older phase design sometimes required **production Developer ID** before enabling required mode; the final v0.8 prototype deliberately narrowed that gate to a locally pinned Apple Development-signed installation and real on-device testing. I am not silently treating that production requirement as satisfied. Likewise, the former experimental `feature/v0.8-macos-sandbox` references are historical; my current working branch is `feature/v0.8-native-transfers`.

**Status: feasibility research and native boundary probe, NOT a production MCP sandbox.**
`main` continues to ship stable v0.7 until acceptance on real macOS.
The `feature/v0.8-macos-sandbox` branch may change substantially.

## Official Apple references reviewed

- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox): kernel-enforced sandbox with separately configured filesystem and networking rights.
- [Protecting user data with App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox): sandbox limits the impact of compromised code.
- [Discovering and diagnosing App Sandbox violations](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations): components needing distinct access rights use XPC, login items, or a helper app—not a plain inherited child sandbox.
- [Embedding a command-line tool in a sandboxed app](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app): signing, entitlements, the `inherit` caveat, and why XPC is often preferable.
- [Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html): per-service sandbox and lifecycle management. Apple calls XPC the preferred way to achieve privilege separation.
- [Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox): the app container, user-selected documents, and operating system permission constraints.
- [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/): inspect and audit executable entitlements before shipping.

## Threat model and intended architecture

**Trust boundary:** The existing Node gateway retains HMAC-protected audit history, signed receipts, MCP message validation, deterministic policy authorization and human approvals. A **separately entitled native worker/XPC service** processes only allowlisted file operations. The worker must be unable to read the gateway's audit keys, the host's unrelated user data, or establish outbound connections. It should write only inside its own sandbox container. Workspaces used by the unsandboxed Node demo are not silently exposed to the worker; a user-controlled import/export or explicit approved workspace mechanism must be designed.

**Untrusted inputs:** MCP tool names/arguments, crafted JSON-RPC messages, file names, symlinks, poisoned workspace files, dropped IPC connections, child failure, malicious native-worker payloads. The parent gateway is not itself protected from other malicious processes running under the same macOS user.

**Out of scope:** root/administrator compromise, kernel exploit chains, physically immutable logs, key compromise under the same OS user, generic unrestricted MCP servers, notarized production distribution. The initial probe is not an XPC service. It has no authority to claim isolation of the current Node downstream server.

**Failure policy:** When `MCP_SANDBOX=required` on macOS, the gateway MUST continue refusing unprotected execution until a separately signed/enforced native worker is integrated and Mac acceptance tests pass. Do not substitute `sandbox-exec`, environment sanitization, codesign output or an unsigned Node subprocess for genuine OS-enforced isolation.

## Phase 1 — OS behavior probe (current)

The opt-in macOS-only script:

```sh
npm run mcp:mac-probe
```

uses Apple's `xcrun swiftc` to compile `native/macos/SandboxProbe.swift`, ad-hoc signs the throwaway executable using `codesign` and the `com.apple.security.app-sandbox` entitlement with **no network privileges**, verifies the signature/entitlement, then runs it while:

1. The parent confirms it can read a disposable marker under the user's home. The helper must be unable to read it.
2. The parent opens an accessible 127.0.0.1 TCP listener and establishes a baseline connection. The helper's connect attempt must be rejected with `EACCES` or `EPERM`, **not** `ECONNREFUSED`/timeout.
3. The helper must write and remove a disposable file inside its reported sandbox home.

All three must pass. The script cleans up its temporary code and marker, and prints a failure if compiler or signing tools are missing. An ad-hoc signature is suitable only for local feasibility; Apple signing/entitlement rules for an embedded tool, app bundle and independent XPC service still need a separate implementation. This probe can also show a **negative** result: for example, if macOS does not create a usable sandbox container for an independently launched CLI, we must move directly to an Xcode app/XPC host without misreporting success.

**Mac prerequisites:** `xcrun --find swiftc` and `codesign --version`, typically provided by Xcode/Command Line Tools. This test is not run by Linux CI: Swift/macOS kernel policy cannot be emulated reliably there.


### If code signing succeeds but the native helper exits without a status

Node's synchronous child-process API reports `status: null` for a signal-terminated process; status alone does **not** tell us whether the OS denied execution, the binary trapped, or it timed out. The probe's native launch now uses asynchronous `spawn` with an explicit 12-second deadline, and prints `status`, `signal`, `timedOut`, `error`, `stderr` and elapsed time when something fails.

For relevant Apple sandbox diagnostics, use the **Console** app and search for `type:error`, subsystem `com.apple.sandbox.reporting`, and category `violation`, as described in [Apple's App Sandbox violation guide](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations). A `SIGTRAP` or `SIGKILL` is not itself evidence that the intended restrictions work. Apple's engineering team also describes a specific `libsystem_secinit` entitlement conflict when an **embedded tool** attempts to start a new sandbox instead of inheriting its parent's; our standalone test is different, so do not assume that explanation without diagnostics ([Apple Developer Forums](https://developer.apple.com/forums/thread/679940)). Do not disable SIP, Gatekeeper, or App Sandbox to make the probe pass.

### Observed on Apple Silicon — diagnostic investigation, 13 Oct 2026

The signed standalone Swift CLI passed compiler and `codesign` entitlement checks, then terminated with `SIGTRAP` before any JSON result (`status:null`, `signal:"SIGTRAP"`, `timedOut:false`, ~289 ms, empty stderr/stdout). **No macOS isolation success has been established.** App Sandbox policy or container initialization is a possible cause, but only the crash's termination reason and faulting thread can establish which subsystem trapped. Apple [explains the fields in a crash report](https://developer.apple.com/documentation/xcode/examining-the-fields-in-a-crash-report) and provides a [sandbox-violation investigation guide](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations).

After reproducing the failure, run `npm run mcp:mac-crash` on the Mac to summarize the newest matching `.ips` or `.crash` report without printing the entire diagnostic file. If no report appears, open macOS Console > Crash Reports and locate `blackbox-sandbox-probe`, or use Console's `type:error`, `subsystem:com.apple.sandbox.reporting` and `category:violation` filters. Prefer sharing the summary only, not a raw user crash report (which can contain private paths and environment details).

**Architectural recommendation:** regardless of this ad-hoc standalone CLI failure, favor a bundled XPC service with independently configured permissions and `launchd` lifecycle for the actual MCP tool worker, following [Apple's XPC documentation](https://developer.apple.com/documentation/xpc). Do not add `com.apple.security.inherit` to a standalone process launched by an unsandboxed Node parent: inheritance cannot create a protected parent context. Never disable SIP or Gatekeeper for this project.

### Phase-1b: sign the same probe inside a macOS .app bundle (experimental)

The **confirmed crash** (`EXC_BREAKPOINT / SIGTRAP`, signal 5, faulting frame `_libsecinit_appsandbox.cold.6`) occurred during system-library sandbox initialization, before Swift's entrypoint. The report does **not** identify `SYSCALL_SET_PROFILE` or prove whether Node's parent sandbox or missing bundle metadata is the primary cause. Apple's [entitlement inheritance guidance](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html) and [Apple Developer Technical Support notes](https://developer.apple.com/forums/thread/679940) explain why an inherited-versus-new-sandbox conflict can trap, but that is not a conclusive diagnosis for the standalone test.

The next low-risk differentiation is:

```sh
npm run mcp:mac-bundle-probe
```

This compiles **the same Swift logic** within a disposable `BlackBoxSandboxProbe.app/Contents/MacOS` structure, provides an explicit `Info.plist` application identifier, and ad-hoc signs **the bundle**, not just a loose executable. The Node harness still launches the bundled executable and verifies OS permissions; signing or a successful launch alone never counts as a PASS. This helps determine whether standard bundle packaging changes behavior, but it **is not an XPC service**, a registered LaunchServices test, or a reliable production macOS security boundary.

Results:
- If the three actual file/network/container checks pass, proceed to a separately sandboxed XPC worker and end-to-end MCP integration.
- If it still traps in `libsystem_secinit`, do **not** add `com.apple.security.inherit` to the unsandboxed Node process's child and claim success. Use the Xcode XPC Service template within a native host app for a supported `launchd`-managed separation, then repeat real isolation tests.

The test deletes the temporary `.app` bundle and synthetic host marker. macOS may retain its system-created sandbox container under `~/Library/Containers/dev.agentblackbox.sandbox-probe.bundle`; do not delete arbitrary containers by script.

### Phase 1c — macOS XPC service feasibility (awaiting on-device test)

The user's **app-bundled signed Swift probe passed all three OS-level checks**, in contrast with the identically entitled loose executable's `libsystem_secinit` SIGTRAP. This establishes that app-bundle packaging changes the result; it does not establish the exact low-level secinit root cause.

The next step embeds a **private XPC service in `Contents/XPCServices` of an ad-hoc signed host .app** and uses Apple's C-based XPC Services API. The service has its own `CFBundleIdentifier`, `XPC!` package type, a restrictive App Sandbox signature with **no network entitlement**, and a fixed single-method diagnostic interface. It is launched by macOS on demand through `xpc_connection_create`, not directly via Node's `spawn`. The parent host remains unsandboxed in this experiment so the boundary can be measured between host and service. Official documentation: [Apple Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html) and [XPCService Info.plist keys](https://developer.apple.com/documentation/bundleresources/information-property-list/xpcservice).

To test on macOS (requires Xcode Clang):

```sh
npm run mcp:mac-xpc-probe
```

Apple's [Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html) describes the C XPC Services API as **libSystem-level**. Xcode's macOS SDK does not expose the separate linker target `-lxpc`; Clang links libSystem by default. The first on-device attempt stopped before executing the service with `ld: library 'xpc' not found`. The build now omits the incorrect `-lxpc` flag. This is a build-system correction, **not** an App Sandbox or XPC runtime PASS.

The harness builds and signs a disposable host `.app` and nested `.xpc`, checks the nested signature/entitlement, starts a reachable loopback server, verifies an unrelated marker is host-readable, and requests one XPC diagnostic. Four outcomes must pass: separate process PID, permission-denied host file, permission-denied loopback TCP, and an allowed temporary-file write/cleanup in the service. Any failure (including XPC connection invalidation, timeout, or missing sandbox denial) fails closed and prints bounded diagnostics.

**On-device compilation correction (13 Oct 2026):** The first retry compiled the C XPC host, then reported a compile-time callback-type mismatch for the service's `xpc_main` call. Apple's [`xpc_main` declaration](https://developer.apple.com/documentation/xpc/xpc_main%28_%3A%29?language=objc) takes `xpc_connection_handler_t`, a **C function pointer**, while [`xpc_connection_set_event_handler`](https://developer.apple.com/documentation/xpc/xpc_connection_set_event_handler%28_%3A_%3A%29?language=objc) accepts a **block** for incoming message events. The service now supplies a named C function (`accept_peer`) to `xpc_main`, and keeps the message-event block in that function. This is a source-level build fix, not runtime isolation proof.

**Not yet the production worker:** the service currently accepts only a synthetic test operation, not `read_note` or `write_note`. The Node gateway still uses the bundled Node MCP notes executable, and `MCP_SANDBOX=required` on macOS remains unsupported/fail-closed. Only after native XPC acceptance do we design the bounded, authorization-checked Node→host→XPC request bridge, secure workspace provisioning, and real MCP read/write tests. Build-system and signing policy remain experimental; an Xcode project may be preferable to manual app packaging for shipping.

## Phase 2a — bounded native note operations (experimental)

**Previous gate on Mac PASSED:** The user ran `npm run mcp:mac-xpc-probe` and verified that the signed host app connected to a separately sandboxed native XPC service with a distinct process PID. A readable user-owned host marker and a reachable loopback TCP endpoint were both denied **with OS permission errors** from inside the worker; its temporary-file write/cleanup succeeded. This demonstrates real OS-enforced isolation of the diagnostic XPC service. It does not prove the complete MCP tool path.

**Next on-device gate:** `npm run mcp:mac-xpc-notes` compiles/signs an **additional independent native XPC notes worker**, which exposes fixed `write_note` and `read_note` operations to the experimental host and a test-only `cleanup_test_note`. The test exchanges a hard-coded non-secret note, verifies identical bytes returned through XPC, attempts a traversal read, and cleans the synthetic file. The worker is signed with `com.apple.security.app-sandbox` and no network entitlements. The C implementation restricts names to `bbx-test-*.txt`, content to at most 2,000 bytes, and uses `openat` with `O_NOFOLLOW` and `O_EXCL` for new-file-only writes.

**Strict limitation:** This deliberately operates only on synthetic files in the service's sandbox-accessible `TMPDIR`, **not** the project's demo workspace or durable notes. It has **no bridge to the Node MCP gateway**, no user approvals, no audit integration and no claim that the notes host is a complete MCP server. The earlier XPC OS isolation proof and existing Node policy/approval/audit checks remain separate. The test must pass on a real Mac before designing the Node-to-native IPC gateway or persistent workspace. No production credentials or existing audit records are needed. The native service is not yet hardened with client code-signature identity checks, and no other process should place sensitive content in this temporary test area.

### Phase 2b — Experimental Node to native host to private XPC transport

The **Phase 2A Mac test passed**: the separately signed App Sandbox notes worker performed a synthetic new-file write, returned exact note content, denied traversal, and removed its test file. No Node MCP or approval/audit path was exercised.

`npm run mcp:mac-xpc-node-bridge` now tests a **separate bounded binary IPC** between a Node script and a signed native host executable. The host forwards only `READ`, `WRITE` and `REMOVE` synthetic note commands to the previously validated private notes XPC worker. It uses bounded, length-prefixed note bodies via **stdin**, not process command-line arguments or environment variables. The native host is unsandboxed but designed to access only its private XPC service; the OS-enforced file boundary remains in the signed XPC service. There is no shell execution or generic tool forwarding.

The native worker still accepts only `bbx-test-*.txt` filenames (≤64 characters) and up to 2,000 bytes, and rejects attempts at paths outside its synthetic test namespace. The bridge smoke also attempts duplicate new-file creation, rejects a test traversal, confirms the original content is unchanged, removes the synthetic note and verifies it cannot be read afterward. The test deletes its temporary signed app bundle.

**Important:** This is NOT a production MCP downstream, not durable notes storage, and not connected to `src/mcp-gateway.mjs`. This smoke deliberately bypasses human approvals and audit logs **because it can access only expendable synthetic test fixtures**; it must not be repurposed for real files. Before routing user-controlled operations, we need to align policy and XPC workspace identity, use a native durable container directory, constrain client identity/signature and executable trust, enforce operator approval and authenticated audit logging, handle XPC request cancellation and uncertain write outcomes, and replay both OS-denial tests on the final service. A synchronous XPC response can block indefinitely according to [Apple's API documentation](https://developer.apple.com/documentation/xpc/xpc_connection_send_message_with_reply_sync%28_%3A_%3A%29); the test's Node process supervisor imposes a timeout and treats a timed-out write as an **unknown outcome**, not a rollback. macOS `MCP_SANDBOX=required` must remain fail-closed.

### Phase 2C — Container-owned durable scratch storage (Mac acceptance pending)

The user ran the **Phase 2B transport acceptance on Apple Silicon** and verified every synthetic Node→native host→XPC operation: signed worker, exclusive new-file creation, exact readback, traversal and duplicate-write refusal, original note unchanged, deletion and post-deletion denial. This proves the *experimental transport only*, not MCP policy integration or real document storage.

The next isolated gate runs:

```sh
npm run mcp:mac-xpc-durable
```

It compiles a **separate** Objective-C/C native XPC service (`dev.agentblackbox.xpc-durable.worker`) without changing the previously accepted temporary-file service. Using Foundation's documented `NSFileManager URLForDirectory:NSDocumentDirectory ... create:YES`, the service requests its own sandbox-managed Documents directory. It refuses the operation unless this resolves into macOS's expected `/Library/Containers/.../Data/Documents` path shape. It creates a `0700` `AgentBlackBoxScratchNotes` subfolder, rejects symlinked/non-owner/world-accessible directories, and continues to use `openat`, `O_NOFOLLOW`, `O_EXCL`, `0600` and synthetic `bbx-test-*.txt` filenames. This path is never supplied by the MCP client or Node.

A first signed host process creates/reads a synthetic note and exits. A **separate native host invocation** then tries to read the same bytes, denies a duplicate write and a traversal, confirms no mutation, removes the note and rejects a post-delete read. Because `launchd` can reuse an XPC service process, this test proves continuity *across client invocations*, **not** that the worker itself restarted; an explicit worker restart acceptance must be added later. On completion the signed temporary `.app` is deleted, but macOS may retain the application sandbox's scratch directory after the test. The note is removed on the success path; a killed test can leave a harmless synthetic file in the sandbox. Never delete unrelated container data automatically.

This is a deliberate **workspace authority gate**, not a workaround using App Groups or wider disk access. Apple recommends standard Documents paths inside an app's container ([Protecting user data with App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox), [Files and directories](https://developer.apple.com/documentation/technologyoverviews/files-and-directories)). Sharing a container with an unsandboxed Node process via Apple App Groups requires separately supported signing/entitlement and potentially notarization/provisioning ([Accessing files from the macOS App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox)). This experiment **does not grant** that access.

**Remaining gaps:** the real `MCP_WORKSPACE_ROOT` and signed worker's storage scope are intentionally different; we must define their matching policy and explicit data import/export, user approvals, signed-binary identity checks, audit records, cancellation/uncertain-write semantics, and final-worker file/network OS-denial tests. The Node gateway is unchanged; macOS `MCP_SANDBOX=required` continues fail-closed.

### Phase 2D — Native XPC workspace identity and fail-closed policy root comparison

**Phase 2C on-device passed**: the user ran `npm run mcp:mac-xpc-durable` and confirmed sandbox Documents note persistence across **two separate host invocations**, exclusive creation, traversal and overwrite refusal, unchanged content after denials, deletion and post-deletion denial. It did **not** prove a native XPC service restart, MCP policy or audit controls.

Next diagnostic gate, **not a production MCP configuration**:

```sh
npm run mcp:mac-xpc-authority
```

This builds an **independent** `dev.agentblackbox.xpc-authority.worker` service with the same signed App Sandbox restrictions and Documents scratch storage. A fixed `workspace_info` XPC method obtains the opened notes directory with macOS `fcntl(F_GETPATH)`. Its native host supports a special bounded `ROOT - 0` protocol frame and never uses a client-supplied filesystem path to select the worker's root. Node receives the path **in memory**, then applies `validateMacWorkspaceBinding`:

- refuse a distinct or unspecified `MCP_WORKSPACE_ROOT`; do not silently map the gateway's `demo-workspace` into the worker's container
- require canonical absolute container-owned `Data/Documents/AgentBlackBoxScratchNotes` and a private same-owner directory
- reject symlinked or group/world-accessible directory roots

The acceptance script first proves that the existing demo workspace cannot bind to native storage, then proves that an explicitly equal **synthetic test policy root** passes. Finally it reruns the native two-host persistence and denial tests. This is a workspace **comparison**, not cryptographic attestation of the worker: the actual signed native app must be verified before trusting its reported root, and same-user attackers are outside this prototype's trust assumptions. A production integration must require an independent, explicitly configured root, not accept a path simply because a worker reports it.

**Gateway remains unchanged:** no real MCP tool routing, durable user document ingestion, operator approval or authenticated audit. `MCP_SANDBOX=required` continues to refuse execution on macOS. The private worker is test-only and named `bbx-test-*.txt`; the Node policy currently permits a broader set of paths, so those grammars also need harmonization before enabling actual MCP calls.

### Phase 3A — Real MCP policy/approval/audit path with synthetic XPC notes (Mac acceptance pending)

**Phase 2D Mac result PASSED:** The user executed `npm run mcp:mac-xpc-authority` and confirmed the private worker's canonical Documents identity matched an explicitly chosen test policy root, while the unrelated `demo-workspace` was refused. It also repeated signed XPC storage read/write, exclusive-create, path-traversal rejection and cleanup. No signer attestation, XPC service restart or real MCP authorization has been proven by that test alone.

Run the **opt-in** Phase 3A Mac acceptance only:

```sh
npm run mcp:mac-xpc-mcp-acceptance
```

The harness constructs a disposable signed XPC host/service bundle, verifies nested signatures and App Sandbox entitlement, queries the worker's Documents path, rejects the unrelated repo demo workspace, then creates a **fresh isolated audit store and localhost approval controller** in a temporary directory. Through an **in-process-only experimentalLaunch test hook**, it instantiates the *actual* `startGateway` code and the same `guardedToolCall` policy, approval and authenticated audit logic as the existing MCP gateway. The downstream is an experimental test-only MCP adapter that sends bounded stdin frames to a separately signed native host and the private XPC worker.

The acceptance scenario sends genuine **legacy MCP stdio JSON-RPC requests** to the gateway: `initialize`, `tools/list`, blocked traversal, a write **denied through the real dashboard approval endpoint**, a write **explicitly approved through that endpoint**, readback from XPC, a second approved but **native-rejected duplicate write**, and verification of HMAC audit chain validity and the absence of full note content in the audit records. Native files are restricted to synthetic `bbx-test-*.txt` notes; the test removes the approved synthetic note after use. A crash may leave a harmless test file in the sandbox Documents scratch folder. **No real user notes or the existing audit/key/checkpoint history are touched.**

**Security limits that remain critical:**
- The ordinary `src/mcp-gateway.mjs` CLI still uses its fixed bundled Node downstream. Only a direct in-process test harness can pass `experimentalLaunch`, and that hook **refuses `MCP_SANDBOX=required` or any non-macOS platform**. This new test deliberately uses `MCP_SANDBOX=off`; it does **not** prove or enable production required-mode isolation.
- The Node/native host process is **unsandboxed** in this experiment, while the private XPC worker is the enforced filesystem/network boundary; the host's native service still only supports the synthetic note filename grammar. A production implementation requires trusted code-signing identity checks beyond ad-hoc signature syntax, and authenticated/authorized binding of the bridge to the intended service.
- Policy path checks and native exclusive-create checks are not an atomic authorization transaction across processes. We must address TOCTOU, XPC service identity, cancellation, crash recovery, unknown write outcome, and mismatched native/Node filename grammars.
- The acceptance uses an isolated disposable audit history rather than the real user's authentic historical events. It tests **legacy** MCP only; modern protocol and SDK interoperability through the native path need their own Mac runtime acceptance.
- The native scratch Documents container persists across test invocations, but may retain synthetic orphan notes after abrupt termination. Never expose it as a real document workspace until lifecycle management, explicit import/export and cleanup are designed.

### Phase 3B — Modern MCP 2026-07-28 over synthetic signed XPC notes (Mac acceptance pending)

**Phase 3A on-device ACCEPTED:** The user ran `npm run mcp:mac-xpc-mcp-acceptance` on Apple Silicon and confirmed the real legacy MCP gateway executes policy checks, operator approval/denial, bounded private XPC note writes and reads, exclusive-create enforcement, and disposable authenticated audit history without recording note contents. This is **synthetic-only** acceptance, not production required-mode or native signer identity attestation.

A new opt-in mode of the **same** acceptance harness reuses the real native host, signed XPC service, local approval controller, private Documents workspace and throwaway audit log:

```sh
npm run mcp:mac-xpc-mcp-modern
```

This mode uses real **modern MCP `2026-07-28` client-visible request metadata**, `server/discover`, metadata-preserving `tools/list`/`tools/call`, `resultType:complete` and private/no-cache response semantics. It explicitly rejects an unknown protocol version (`-32022`) and missing modern metadata (`-32602`) before any native tool call. It then repeats the real gateway path-traversal refusal, controller-denied write, approval-gated new note, exact XPC readback, approved-but-rejected duplicate write, and verification of a **fresh HMAC audit history** free of full note contents.

The downstream test adapter continues to speak the previously validated **legacy 2025-11-25** protocol **only between the gateway and its fixed XPC adapter**. This matches the gateway's actual protocol translation architecture: the external client uses modern MCP, while the gateway pins its audited downstream to a legacy interface. This test uses the same synthetic note namespace, never the user's live notes or authentic audit/checkpoint files.

**Not yet production:** On-device native modern test is pending; failures in cancellation, native worker termination, crash recovery, status unknown, signer trust, final OS denial on the exact service, or explicit user document import/export still block `MCP_SANDBOX=required` on macOS. The normal `npm run mcp` launch is unchanged and cannot select this test path via an environment variable. This is a test-only in-process hook in `MCP_SANDBOX=off` mode.

### Phase 3C — Native host hang and post-commit crash fault injection (Mac acceptance pending)

**Phase 3B on-device accepted:** The user ran `npm run mcp:mac-xpc-mcp-modern` and passed real modern MCP discovery/version and missing-metadata refusals, allowlisted native note operations, denied and approved writes, exact XPC readback, exclusive-create protection and fresh HMAC audit integrity. As with Phase 3A, all notes and audit keys were disposable synthetic test fixtures.

The next opt-in diagnostic is:

```sh
npm run mcp:mac-xpc-faults
```

This uses a **separate, intentionally instrumented** `FaultBridgeHost.c` only in the test build. The **unchanged** normal `AuthorityBridgeHost.c` still has no fault injection. Node forwards a fixed `BLACKBOX_XPC_TEST_FAULT=1` flag exclusively to this diagnostic host through the synthetic-only adapter; a real user cannot select it from the normal gateway CLI. The separately sandboxed XPC service is still signed with the original restrictive entitlement. Both tests go through the real MCP gateway, actual operator approval endpoint, native service, and a fresh temporary authenticated audit log:

1. `bbx-test-fault-hang-*.txt`: the diagnostic host intentionally hangs **before dispatching its XPC write**. Node's bounded subprocess supervisor terminates it; the client gets an error, the note must be absent, and the audit records **`MCP_OUTCOME_UNKNOWN`** conservatively. A missing pre-write side effect observed afterwards does not prove rollback for arbitrary future operations.
2. `bbx-test-fault-crash-*.txt`: the worker successfully creates the synthetic note, then the diagnostic native host deliberately terminates after receiving XPC success **but before notifying Node**. The MCP client must receive an error, the synthetic note must actually exist with exact bytes, and the HMAC audit must record **`MCP_OUTCOME_UNKNOWN`**, never false success or a confidently rolled-back write.

The test then reads the crash-committed synthetic note via the normal native host path to show the adapter remains available, verifies the fresh HMAC audit chain and note-content redaction, and attempts to delete only its synthetic note in `finally`. A killed test can leave disposable scratch notes; never delete existing containers or user documents automatically.

**Scope and exclusions:** This is native **host** termination/hang injection, not an actual XPC **service** crash or a cancellation-after-dispatch guarantee. We still need a safe service-crash/lifecycle test, cancellation propagation down to the host process, independent Developer ID/Team ID verification and service identity, final-worker denied file/network regressions, user-workspace data flow, and complete Mac required-mode acceptance. `MCP_SANDBOX=required` on macOS still refuses execution, and v0.7 `main` is unchanged.

### Phase 3D — XPC SERVICE abrupt termination after a committed synthetic write (Mac acceptance pending)

**Phase 3C on-device passed:** `npm run mcp:mac-xpc-faults` demonstrated that a native **host** hanging before a write leaves no note, while a native host dying **after XPC committed** leaves the synthetic note present. Both outward MCP responses were errors, and the freshly verified HMAC audit contained two `MCP_OUTCOME_UNKNOWN` outcomes without the note bodies. A subsequent native MCP read succeeded. This result is host-failure acceptance, **not** actual XPC service lifecycle acceptance.

**Next acceptance command** on an Apple Silicon Mac with Xcode:

```sh
npm run mcp:mac-xpc-service-failure
```

The test signs a **separate disposable XPC worker**, `dev.agentblackbox.xpc-servicefault.worker`, with App Sandbox enabled and no network entitlement. Its source `ServiceFailureNotesService.m` is copied from the already validated worker but has one deliberately dangerous **test-only** hook: after `openat(O_CREAT|O_EXCL|O_NOFOLLOW,0600)`, writing and `fsync(file)` of a synthetic `bbx-test-xpc-crash-*.txt` file, the **XPC service process itself** calls `_exit(86)` *before its XPC reply*. This is a controlled **abrupt service exit**, not evidence of an attacker exploit, a full process crash dump or a simulated power-loss durability guarantee. The original `AuthorityNotesService.m` is unchanged.

The separate `ServiceFailureBridgeHost.c` treats XPC connection interruptions/errors as a nonzero native-host exit rather than an ordinary application-level `ERR 0`. Node's synthetic test adapter therefore propagates loss of write acknowledgement up through the actual MCP gateway, and the monitor must record `MCP_OUTCOME_UNKNOWN` in a **fresh disposable HMAC audit chain**. The test requires: an outward MCP error after a real human-approved synthetic write, the exact committed note visible afterwards, a different XPC **worker PID** responding after the abrupt exit, the authenticated audit's single uncertain-write record without note content, and successful readback through the recovered native MCP path. The note is deleted through the test host in `finally`; interrupted tests may leave harmless `bbx-test-*` scratch notes in the dedicated worker container.

**Scope:** This exercises one controlled service exit and relaunch in synthetic-only `MCP_SANDBOX=off`, not in-flight client cancellation, malicious process compromise, repeated crash-loop limits, independent Developer ID/Team ID signer attestation, complete filesystem/network denial on the final worker, or production macOS `MCP_SANDBOX=required`. No authentic audit data, user notes, signing keys or checkpoints are read or rewritten. The ordinary MCP gateway CLI and validated v0.7 `main` remain unchanged.

### Phase 3E — Post-commit MCP cancellation and native-host process supervision (Mac acceptance pending)

**Phase 3D PASSED on user's Apple Silicon Mac:** `npm run mcp:mac-xpc-service-failure` confirmed an actual sandboxed XPC service exited after committing/fsyncing a synthetic note but before replying; real MCP returned a fail-closed error; a subsequent XPC worker with a **different PID** recovered, the exact synthetic note survived, and fresh HMAC history recorded `MCP_OUTCOME_UNKNOWN` without note content. This was controlled service termination, not malicious compromise.

Run the next **isolated** acceptance:

```sh
npm run mcp:mac-xpc-cancellation
```

The separately entitled `dev.agentblackbox.xpc-cancel.worker` is an otherwise ordinary fixed, synthetic-only XPC note worker, paired with a **different test-only** `CancellationBridgeHost.c` that intentionally pauses *after* XPC successfully replies to a newly created synthetic `bbx-test-cancel-after-*.txt` note but *before* it responds to its Node parent. The native test host emits **only its PID** through stderr as a synthetic synchronization marker; the Node test adapter writes this PID to a private `0600` marker within the disposable test directory, never the note bytes.

The harness uses the **real MCP gateway, operator approval controller and fresh temporary HMAC audit**. It sends an approved legacy MCP write, waits for confirmed **post-commit/pre-acknowledgement** host pause, then sends `notifications/cancelled` for the exact active request ID. The gateway's `McpPeer` closes its downstream and sends SIGTERM. The synthetic-only adapter now **tracks spawned native hosts in separate POSIX process groups** and kills those groups when the adapter receives SIGTERM, SIGINT or exits. The test checks that the identified native host actually disappears, the XPC note already committed still exists with exact bytes, and the HMAC history contains **one** `MCP_OUTCOME_UNKNOWN` error without note bodies or false success. It also checks that the now-closed gateway downstream does **not** restart unsandboxed or accept a subsequent native request.

This is a *partial, specifically scoped cancellation property*, **not** an assurance that a long-running XPC service operation is itself interrupted by killing its native host. The XPC worker has completed its write before this cancellation. Tests still needed: cancellation while native XPC service is executing, crash-loop/rate control, pending approvals, trusted signed host/service identities, final worker OS-denial checks, and production document import/export. The original native workers remain unchanged and `MCP_SANDBOX=required` still refuses macOS.

**Further Phase 3E hardening:** Tool calls enter the active cancellation map before asynchronous modern-protocol discovery, so a stdio cancellation during cold start cannot race into downstream dispatch. Cancellation that races a completed callback is classified as `MCP_OUTCOME_UNKNOWN`; cancellation that races operator approval remains blocked under `MCP_CANCELLED`. Additional Node tests verify the HMAC audit chain and these states.

References: [MCP 2026-07-28 Cancellation](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/patterns/cancellation.mdx) requires stdio cancellation notifications and recommends no response to cancelled requests. Apple's [xpc_connection_cancel](https://developer.apple.com/documentation/xpc/xpc_connection_cancel%28_%3A%29) is **asynchronous and non-preemptive**: cancelling a host-side connection does not stop a running XPC worker handler. Full Phase 3E and macOS required-mode acceptance therefore remain blocked on a controlled in-progress native worker cancellation test.

### Phase 3E in-flight diagnostic — new on-device gate (not yet accepted)

The earlier Phase 3E **post-commit** scenario passed on my Mac on October 13, 2026: all nine PASS lines, including native host termination, preserved synthetic committed note, authenticated `MCP_OUTCOME_UNKNOWN` record and no unsandboxed fallback. This proves **post-commit host process supervision**, not that execution within an XPC worker was aborted.

I added a separate opt-in **`--during`** path to the same synthetic-only cancellation harness. This mode uses a distinct `bbx-test-cancel-during-*.txt` note. The worker asynchronously executes a bounded delay and creates a **content-free marker in its own private Documents scratch directory** after entering native work. The harness waits for the real worker-owned marker, verifies that the target note has not yet been created, and issues MCP `notifications/cancelled` while the operation is active. The native host should die, its XPC peer should become invalid, and the experimental worker observes that invalidation on a separate event queue and cooperatively aborts its delayed write. The harness asserts removal of the worker marker, absence of the target note, `MCP_OUTCOME_UNKNOWN` in a verified HMAC audit, no false client response and no fallback.

**Mac commands, after updating the feature branch:**

```sh
MCP_SANDBOX=off npm run mcp:mac-xpc-cancellation -- --during
MCP_SANDBOX=off npm run mcp:mac-xpc-cancellation -- --during --modern
```

This experiment does not cancel arbitrary synchronous native worker operations. It specifically exercises a cooperative, asynchronous test hook; no production worker, signer trust or required-mode path is changed. Apple's [`xpc_connection_cancel` documentation](https://developer.apple.com/documentation/xpc/xpc_connection_cancel%28_%3A%29) says cancellation is asynchronous and **non-preemptive**; Apple's [synchronous reply API](https://developer.apple.com/documentation/xpc/xpc_connection_send_message_with_reply_sync%28_%3A_%3A%29) can block indefinitely. The modern [MCP stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) continues to use `notifications/cancelled` on shared stdio connections; per-request Streamable HTTP differs. Treat all dispatch-time transport loss as UNKNOWN until an externally verifiable commit/abort outcome exists. Do not declare full Phase 3E or `MCP_SANDBOX=required` accepted based on this test alone.


### Phase 3E accepted on-device; Phase 4 signer-trust diagnostic under development

**October 13, 2026 Mac acceptance:** I ran all three synthetic Phase 3E cancellation scenarios, and each passed:

- Legacy `npm run mcp:mac-xpc-cancellation -- --during`: XPC worker execution marker observed before cancelling, host terminated, cooperative abort prevented note creation, audit marked `MCP_OUTCOME_UNKNOWN`, no downstream fallback.
- Modern `npm run mcp:mac-xpc-cancellation -- --during --modern`: the same native outcome with MCP `2026-07-28` discovery/metadata checks.
- Legacy post-commit `npm run mcp:mac-xpc-cancellation`: already-committed note survived termination; authenticated audit reported uncertainty rather than an invented rollback.

These are `MCP_SANDBOX=off` synthetic tests, not production preemption or fail-safe rollback.

**Next diagnostic — trust in signed bundles (not production acceptance):** I added `npm run mcp:mac-signer-trust` as a **read-only, explicit, fail-closed** verifier for a separately provisioned Developer ID-signed host and its directly nested XPC service. It requires an operator-pinned Team ID and *two distinct* signing identifiers, and verifies Apple's Developer ID Application certificate chain through a required Apple code-signing expression for each bundle; the entire nested app seal; signer metadata and hardened runtime; and the worker's minimal App Sandbox entitlement. It rejects ad-hoc bundles. It cannot change launch policy or enable required-mode macOS.

```sh
npm run mcp:mac-signer-trust -- \
  --app /absolute/path/to/TrustedHost.app \
  --service /absolute/path/to/TrustedHost.app/Contents/XPCServices/TrustedWorker.xpc \
  --team-id YOUR10CHAR \
  --host-id dev.example.trusted.host \
  --worker-id dev.example.trusted.worker
```

**The Team ID and both signing IDs must come from a previously approved release configuration, not from the code being examined.** The current ad-hoc acceptance bundles are expected to be rejected. We have not established a production Developer ID distribution identity, trust manifest or live peer authentication. Even a successful static requirement validation would *not* prove Gatekeeper/notarization, runtime peer checks or OS isolation of the final worker. On-device acceptance of this gate awaits the signed production artifact and separately pinned identity.

Official Apple guidance: [Creating distribution-signed code for macOS](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/), [TN3127 code-signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements), [code signing -R verification](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html), and [XPC peer team identity requirements](https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_team_identity_requirement%28_%3A_%3A%29). A future production host must also enforce peer requirements on the live XPC connection; static verification alone is insufficient.

### Engineering gates before enabling `MCP_SANDBOX=required` on macOS

1. Complete native note XPC test using synthetic data.
2. Design a durable, sandbox-contained workspace and explicit import/export workflow. Require the Node gateway's policy workspace to match the worker's actual data scope.
3. Build a bounded MCP stdio/native host IPC adapter with fixed `initialize`, `tools/list`, and `tools/call` schemas, enforce message size limits, and deny direct worker access to audit keys and controller approval tokens.
4. Exercise real MCP legacy/modern calls, read and operator-approved write, cancellations and worker crash / timeout; audit both successes and uncertain outcomes.
5. Rerun permission-denial tests on the **final native notes worker**, reverify signatures and entitlements at launch, and reject any unsupported configuration without unsandboxed fallback. Retain Linux 7/7 isolation acceptance.

## Phase 2 — native XPC worker architecture (not yet implemented)

- Build a dedicated sandboxed XPC service inside a minimal signed macOS host app, separated from the existing unsandboxed Node control plane. Model its IPC as a fixed set of `read_note`/`write_note` operations; never forward arbitrary tool names, paths, file descriptors or commands.
- Choose an app-owned workspace with explicit user-approved import/export. Keep the Node gateway's data directory and signing keys inaccessible to the XPC worker.
- Add supervisor and lifecycle integration (timeouts, cancellations, terminated XPC service, crashed worker) without treating partial or unknown execution outcomes as success.
- Prove the subprocess's actual sandbox (file access denied, loopback networking denied, allowed app-container writes) with native negative tests.
- Gate `MCP_SANDBOX=required` on successful entitlement/signature verification, worker handshake and runtime acceptance. Never fall back to the unsandboxed Node server.

## v0.8 release acceptance

Native macOS file and network denial **from the production worker**, not merely from this probe; safe positive workspace operation; Mac required-mode MCP legacy/modern protocol tests; approvals and audit chain remain intact; Linux Bubblewrap 7/7 acceptance preserved; CI and manual signature verification documented. No merge to `main` until user Mac results establish those claims.

## Phase 4 — real XPC peer identity, Developer ID pending

I added a **separate, optional ad-hoc negative experiment** after the successful Phase 3E Mac cancellation runs. It builds the already accepted signed Authority host and its private notes worker, proves a baseline `workspace_info` response, then recompiles that host with `BBX_TEST_PEER_REQUIREMENT=1`, re-signs the throwaway bundle and requires Apple's **`xpc_connection_set_peer_team_identity_requirement`** on the live host → worker connection *before* resuming it. The same test worker has only an ad-hoc signature and **must not satisfy** Apple's same-team identity requirement.

```sh
MCP_SANDBOX=off npm run mcp:mac-xpc-peer-negative
```

The fail-closed `PeerRequirementGate.h` helper resolves Apple's runtime enforcement API. A missing API, failed requirement installation, unavailable baseline, malformed peer identifier, unobserved native worker, ordinary timeout, or an unexpectedly successful worker reply **fails acceptance**; no PID, UID or process-name trust fallback is permitted. This code is used ONLY in an alternate test host build and never relaxes the previously accepted sandbox / gateway. A positive Developer ID trust path still needs externally pinned signing identities, **worker-side authentication of its host peer**, approved code-signing trust, and live Mac acceptance. This negative result alone is not a production signing gate. Apple reference: [XPC same-team peer identity requirement](https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_team_identity_requirement%28_%3A_%3A%29).

Mac observation: `security find-identity -v -p codesigning` found **zero currently valid identities**. Accordingly, no real Developer ID positive test can be accepted here. Apple Developer Program membership can eventually support separate [Apple Distribution (App Store)](https://developer.apple.com/help/account/certificates/certificates-overview/) and [Developer ID (outside Store)](https://developer.apple.com/developer-id/) workflows.


## Phase 4 — AuthorityNotesService-derived OS-denial acceptance (on-device pending)

After the accepted native XPC same-team **negative** peer result, I added a second independent Mac fixture that compiles the **`AuthorityNotesService.m` implementation itself**, rather than accepting OS-denial results from a separate generic `ProbeService.c`. The disposable worker is built with `BBX_TEST_NOTES_ISOLATION=1` to permit *one* read-only synthetic isolation diagnostic method; the ordinary worker is **not** compiled with this macro and retains its original fixed `workspace_info`, `write_note`, `read_note`, and `cleanup_test_note` interface. A one-purpose `ProbeHost.c` variant contacts the Authority worker identity only in the experimental build.

```sh
MCP_SANDBOX=off npm run mcp:mac-xpc-notes-isolation
```

Acceptance requires a baseline **host-readable synthetic home-directory file**, a verified **live reachable loopback listener**, an independently entitled ad-hoc-signed XPC worker with a different PID, an actual **`EPERM`/`EACCES` denial** opening the host marker, and an actual **`EPERM`/`EACCES` denial** attempting the reachable TCP loopback. `ENOENT`, `ECONNREFUSED`, missing messages, worker death and timeouts cannot count as sandbox successes. The positive storage check fsyncs and removes an exclusive synthetic note using **the notes worker's existing private Documents scratch directory** via `notes_fd()`; it does not grant any arbitrary filesystem access.

This is an **instrumented build of the actual notes-worker source**, not a byte-identical production release binary. The test macro and ad-hoc signing must never be present in release artifacts. Static Developer ID/Team ID trust, live positive host ↔ worker identity authentication, notarization as appropriate, explicit user-approved document import/export and macOS `MCP_SANDBOX=required` remain incomplete. This fixture does not grant approval to merge the PR.


### Phase 4 notes-worker isolation — test response serialization fix

My first on-Mac run of `MCP_SANDBOX=off npm run mcp:mac-xpc-notes-isolation` compiled and verified the signed test worker, established the host-file and loopback baselines, then raised `Native notes worker did not acknowledge a valid probe.` The ordinary `mcp:mac-xpc-authority` acceptance separately passed all checks.

The cause was a **harness response-shape mismatch**, not an observed OS isolation failure. `ProbeHost.c` rejected a native reply unless it was a dictionary with `valid=true`; upon success it emitted the existing probe JSON fields **without** `valid`. The new notes isolation JS diagnostic incorrectly required that validated field in the serialized JSON. I updated **only the disposable native probe host's `BBX_TEST_NOTES_ISOLATION` build** to include a verified `valid:true` prefix. The ordinary probe JSON stays byte-for-byte compatible. The strict JS native-acknowledgement check and OS-denial conditions are unchanged. The new run still requires actual on-device OS permission-denied and private Documents write evidence; do not call this gate accepted until that command passes.



## Phase 4 — worker-side incoming XPC peer authentication (negative gate, Mac pending)

The real Mac **host → worker** same-Team-ID requirement negative test and notes-worker OS filesystem/network denial tests passed on October 14, 2026. The new complementary diagnostic now tests the **worker's own incoming XPC connection** rather than trusting a host-only requirement. Apple documents that if an *initiating* process does not satisfy the signing requirement on an inbound connection, the worker's handler receives **no message** (it does not emit a rejection RPC). A generic timeout is therefore never sufficient evidence.

My new \`MCP_SANDBOX=off npm run mcp:mac-xpc-inbound-peer-negative\` fixture:

1. Builds a uniquely named synthetic App Sandbox XPC worker and ad-hoc host using the already-tested \`AuthorityNotesService.m\` and \`AuthorityBridgeHost.c\` sources, with a **working unrestricted baseline** verified against the private canonical Documents workspace.
2. Rebuilds and signs only the throwaway worker with \`BBX_TEST_INBOUND_PEER_REQUIREMENT=1\`; it calls \`bbx_install_same_team_peer_requirement(peer, "dev.agentblackbox.xpc-inbound.host")\` **before** its incoming connection resumes. A failed API lookup or requirement installation **refuses the peer** and creates no success marker. No UID/PID trust fallback exists.
3. On successful installation only, the worker writes a small PID marker in its private Documents scratch root. The harness independently checks the signature, minimal entitlements, fresh marker, and **live** worker PID. If Apple's requirement ever incorrectly delivers the unauthorized host request, the worker writes a separate *delivered* marker **without executing any note operation**.
4. Requires an unreturned native \`ROOT\` request **while the worker is demonstrably alive**, with a present armed marker and **absent delivered marker**. The native host is then killed during test cleanup, and only the exact synthetic marker files are removed.

Because the ad-hoc host cannot prove an Apple-issued Team ID, the expected result is **rejection**. The normal worker and prior cancellation/native-authority tests do not compile this instrumentation, and macOS \`MCP_SANDBOX=required\` remains fail-closed. This new negative test still needs real Mac execution and does **not** prove that a positively Developer ID-signed pair can mutually authenticate, which requires the separate signing identity and release gate.

Official reference: [Apple xpc_connection_set_peer_team_identity_requirement](https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_team_identity_requirement%28_%3A_%3A%29).

### Phase 4 inbound-worker trial: premature host exit is not a pass

On October 14, 2026, my first native `mcp:mac-xpc-inbound-peer-negative` run proved the unrestricted baseline and re-signed worker but then stopped with **`Restricted native host terminated before worker identity was armed`**. I did not accept this result as an authenticated denial. The fixture had two important test-design flaws: it **overwrote an already-launched and ad-hoc-signed private XPC service in place** and assumed an unauthorized host must remain alive. Neither behavior is a reliable proof of Apple's live peer policy, especially when an unauthorized connection can immediately return an XPC error.

I replaced the in-place build with **two independent app/XPC bundles and unique worker and host signing identifiers** for baseline and restricted modes. Their code seals and entitlements are separately checked; the baseline native worker reveals only its validated private container root. The restricted worker's expected scratch location is derived by substituting the independently known sandboxed worker ID; unexpected container layouts fail closed. The harness waits for a **worker-owned armed marker and live PID** even if the initiating host exits early. The test host now emits synthetic-only fixed markers for attempted dispatch and a *typed XPC error*. Early host exit can be accepted only if a native typed XPC error occurred, exit was clean and denied, and the worker was alive with no delivered marker. A missing worker marker, launch failure, missing handler proof, ordinary timeout, or any successful response still fails. These changes remain test-only; positive Developer ID trust still requires a genuine distribution identity and was not tested.


### Phase 4 inbound-worker trial: requirement installed, worker exited

On October 14, 2026, I reran the split-bundle native inbound negative fixture. Both the unrestricted baseline and independent restricted-worker signing checks passed. The worker-owned armed marker was created after its inbound signing requirement returned success, but the worker PID was no longer alive at the observation check. I did **not** accept this as an authentication result; a normal XPC service lifecycle exit and a code-signing/runtime termination remain different possible causes.

I added a **test-only, six-second bounded XPC transaction** after installing the peer requirement, before writing the armed marker, to test whether premature idle service termination is the cause. A scheduled callback ends that transaction; the hook is not compiled into normal notes workers. The harness still requires a live worker, absent delivered marker, attempted client request, and no successful response. Worker liveness now checks the expected executable identity as well as PID state and emits bounded process/host diagnostics if the worker still disappears. This is an isolation/lifecycle diagnostic, not production acceptance or a relaxation of peer signing requirements.

The next Mac run is `MCP_SANDBOX=off npm run mcp:mac-xpc-inbound-peer-negative`. If the worker exits even with the bounded transaction, the result stays **NOT ACCEPTED** pending crash/launchd evidence or genuine Developer ID-signed testing. `MCP_SANDBOX=required` remains fail-closed; PR #6 must not merge without explicit approval.

### Phase 4 accepted on-device — inbound XPC rejection (October 14, 2026)

I reran `MCP_SANDBOX=off npm run mcp:mac-xpc-inbound-peer-negative` on my Mac after adding the test-only bounded XPC transaction. This time **all six acceptance checks passed**:

1. The separately ad-hoc-signed baseline host reached its private notes worker.
2. The restricted nested worker was built and signed independently, without replacing an already running XPC service.
3. The restricted worker remained alive throughout the bounded XPC diagnostic window after installing Apple's incoming peer-signature requirement.
4. The unauthorized host's request never reached the live worker's message handler.
5. The unauthorized host received no successful response.
6. The worker-side OS peer-requirement **negative** test was accepted, synthetic-only.

The earlier native host-side same-team negative test and actual notes-worker source file/network OS-denial regression were independently accepted on October 14, 2026. This completes **both directions of negative XPC peer rejection** in test fixtures. It does **not** show a positively authenticated Developer ID-signed host/worker pair; neither artifact has an independently pinned, production-issued Team ID signature. No production reciprocal trust gate is enabled. The timed diagnostic transaction must stay out of release worker builds.

## Phase 5 — secure document import/export: proposed implementation contract

**Status: design only; no file-transfer implementation or operator-approval bypass is authorized.** The existing synthetic notes API and Linux sandbox are unchanged. This stage must be implemented and separately tested before any production macOS required-mode integration.

### Proposed trust boundary

- **Trusted operator UI / host:** An explicit user action selects a single import source or export destination using a native macOS picker. The agent and XPC worker never choose an arbitrary host path. Any security-scoped access is acquired and released by trusted code, and is never implicitly granted by a model/tool request.
- **Policy and approval controller:** Treat the import/export request as a distinct high-risk capability. Bind authorization to the exact action, content size, expected source identity/digest or export bytes, destination selection, expiry, and a single-use nonce. Require authenticated operator decision before dispatch. Never accept an agent-supplied approval token, filesystem path, or raw bookmark as authorization.
- **Native transport:** Use a dedicated, versioned, bounded and authenticated host→worker protocol; never expand the generic shell or arbitrary-path interface. Limit payload bytes, number of in-flight requests, timeout, retry semantics, and error text. A lost acknowledgement after possible commit is an **UNKNOWN** outcome with an HMAC-authenticated audit event, not automatic retry.
- **Sandboxed notes worker:** Accept only validated note identifiers or protocol-owned, opaque transfer handles. Open only under its private Documents scratch root using descriptor-relative operations, no-follow flags, strict ownership/mode checks, exclusive temporary names, bounded read/write loops, flush/fsync and commit atomicity where supported. Reject symlink, hard-link, directory replacement and TOCTOU confusion. Never open caller-supplied absolute paths.
- **Export:** The worker returns only approved bytes or a fixed bounded stream. The trusted host, under an explicit user-selected destination capability, performs safe exclusive/replace semantics and verifies the exact intended content. An export destination is never selected by the worker or generated by a model. A failed or uncertain export is audited without claiming success.

### Acceptance criteria before enabling transfers

1. Import and export cannot execute without explicit, single-use, authenticated approval tied to the exact operation; replay, expiry, approval substitution and altered content are denied.
2. Unauthorized files outside the sandbox, network access, symlinks, path traversal, race-triggered swap of directories/files and unexpected hard links are denied or safely contained.
3. Oversized files, malformed text or unsupported types, forged bookmarks/handles, concurrent conflicting transfers and shutdown/cancellation paths all fail closed with bounded resource use.
4. A finalized import has durable, exact bytes in the worker's private root. Pre-commit failures leave no approved destination; post-commit lost acknowledgements produce **UNKNOWN**, never invented rollback.
5. Export writes only the destination selected in an active trusted user interaction, uses an explicit overwrite policy and never leaks audit keys, approvals or unrelated files into the worker.
6. Both legacy and modern MCP paths retain policy, real operator approval, authenticated audit, no unsandboxed fallback, and Linux Bubblewrap acceptance. Mac required mode stays disabled until Developer ID and full runtime gates are met.

**Next engineering slice:** implement pure validation and approval-binding tests for bounded import/export request manifests **without touching macOS host files yet**. Follow with an isolated synthetic transfer protocol, then trusted native picker integration and macOS on-device lifecycle/race tests.

### Phase 5 validation-only foundation (no file transfer enabled)

I implemented `src/macos-transfer-intent.mjs` as an isolated, cross-platform **request preview and metadata validator**; the MCP gateway, approval controller, Mac host, and notes worker do not import this module. The strict schema has only: `version`, `operation` (`import` or `export`), a synthetic top-level `bbx-test-*.txt` note name, exact `byteLength`, SHA-256 digest, fresh UUID nonce, and a short bounded issuance/expiry window. The payload ceiling is initially **2000 bytes**, matching the existing synthetic XPC notes worker. Unknown keys, host source/destination paths, bookmarks, approval flags, tokens, malformed names, oversized buffers, altered hashes, future-dated or expired records and changed review metadata all fail validation.

This intentionally verifies **data integrity and reviewed-metadata equality only**. Neither an intent nor a matching review snapshot grants permission to import/export. A future implementation MUST authenticate and atomically consume a separate single-use operator approval through the existing controller, bind that grant to this exact immutable intent (including nonce and digest), and audit execution/unknown outcomes. The module does not create filesystem paths, open native file pickers, access security-scoped resources, or dispatch any XPC operation. Synthetic note names and the 2000-byte ceiling are design constraints, not a claim that general-purpose document transfer exists.

### Phase 5 staged, in-memory authorization-consumption gate

I added `src/macos-transfer-review.mjs` with a **strictly separated trusted-host and trusted-controller interface** for synthetic import/export intents. A trusted host creates a pending review from the existing validated path-free digest manifest. The operator-only controller facet can approve or deny exactly once; absent approval, expiry, cancellation, replay, mismatched digest/name/operation/nonce, invalid payloads and shutdown all deny consumption. The host consumes before validating a candidate payload, so a failed attempt burns that grant and cannot be retried against a different payload. A bounded per-process nonce tombstone set prevents duplicate manifests and intentionally fails closed when capacity is exhausted. A restart loses **all** approvals, not merely the pending ones. Only metadata is stored; no transfer contents or bearer tokens are retained.

**Important scope:** this is an **in-memory state-machine component, NOT an authenticated operator approval service**. The caller must enforce that only the already-authenticated local controller receives the `controller` facet; possession of that object alone is not strong identity proof. The existing `ApprovalQueue` / MCP approval endpoint still only handles `file.write`. This new module is not imported by the web server, MCP gateway or XPC worker, issues no transferable grant, audits no action and touches no host files. Next production steps: authenticated/controller-bound review integration, audited grant consumption, native file picker and safe import/export protocol. No macOS required-mode change.


### Phase 5 local controller wiring — opt-in, synthetic only

I connected the in-memory transfer review state machine to an HMAC-audited local controller, only if trusted application code explicitly passes experimentalMacTransferReviews: true to createBlackBoxServer. The normal CLI starts with the new functionality OFF. An in-process macTransferHost facade can open, consume or cancel synthetically reviewed metadata; no HTTP or MCP tool can create a review, access host files or perform an import/export.

The optional read-only GET /api/mac/transfers/pending displays path-free metadata. POST /api/mac/transfers/:id/decision permits only same-origin, JSON, one-field approve/deny requests and checks audit integrity. HMAC audit records bind lifecycle events to the unique review ID while omitting payload bytes, native paths, credentials and bookmarks. A failed audit verification or append prevents staging; on failure of the completion audit for a decision the grant is cancelled. A successful consume means only that digest-bound one-time metadata was validated, not that a file transfer occurred. No authenticated native picker or XPC file transfer exists.

SECURITY LIMITATION: same-origin HTTP Origin enforcement is a browser anti-CSRF boundary, NOT operator identity authentication. A local malicious process can forge Origin headers. Final production approval requires an independent trusted operator-authentication and native picker capability, plus authenticated host-worker signing. This adapter remains synthetic and opt-in, and macOS MCP_SANDBOX=required still fails closed.

### Phase 5 decision gate hardening — operator verification required (opt-in only)

I found that an experimental same-origin HTTP decision could previously mark synthetic transfers approved without independently verifying the person making the decision. That Origin check only defends against some browser CSRF scenarios: it is NOT proof of an operator's identity.

The new opt-in experimentalMacTransferOperatorVerify callback is supplied by trusted **in-process** application code and receives only the immutable, path-free review intent, review ID and approve/deny decision. Without a verifier, POST decisions return 403 and no synthetic grant becomes approved. The normal server continues with all synthetic transfer functionality disabled. A verifier that rejects, errors, or fails to return exactly true cannot authorize anything. Verification runs before the existing HMAC-audited decision call, with a 15-second abort deadline, no double prompt for the same pending review, and a fresh review/expiry check after the callback finishes. Client disconnect, host cancellation, stale reviews and server shutdown cannot revive an unconsumed grant. Approval grants remain in-memory, single-use and digest-bound, and no OS document transfer or HTTP creation/consumption capability was added.

**Not production authentication:** the callback is deliberately a narrow integration seam, not an actual Apple LocalAuthentication implementation. Injecting a test mock that returns true proves the control flow only. A future audited, natively authenticated, user-initiated operation must implement the real verifier plus a trusted macOS document picker and signed host/worker transport before any real file access. MCP_SANDBOX=required remains fail-closed.

### Phase 5 macOS device-owner authentication — actual OS acceptance pending

A new **standalone, opt-in, disposable** native acceptance harness tests Apple's LocalAuthentication framework directly on the developer's Mac. The helper source is `native/macos/LocalOperatorAuthentication.m`; `examples/mcp-macos-operator-auth.mjs` compiles it with Xcode's macOS SDK, signs the disposable executable ad-hoc, verifies the code signature, and then invokes a fixed-mode test that calls `LAContext canEvaluatePolicy` and `evaluatePolicy` with `LAPolicyDeviceOwnerAuthentication`. This OS policy may use Touch ID, a nearby Apple Watch or the Mac account password, depending on system configuration. This is **device-owner authentication**, not proof of a particular named operator's identity, and Apple's dialog remains user-controlled. The helper uses a fresh context with biometric reuse duration 0 and a bounded 75-second native wait.

All commands require `MCP_SANDBOX=off` because they are ad-hoc-signed **experiments**, not production sandboxed operations. A real interactive macOS login session is necessary. Commands must be run individually:

```sh
MCP_SANDBOX=off npm run mcp:mac-operator-auth -- probe
MCP_SANDBOX=off npm run mcp:mac-operator-auth -- approve
MCP_SANDBOX=off npm run mcp:mac-operator-auth -- cancel
```

`probe` must report that the OS device-owner policy is available, without prompting. For `approve`, complete the native OS prompt; an exact OS success is required. For `cancel`, actively click Cancel in the OS prompt; **only** Apple's `LAErrorUserCancel` result counts as a negative pass. Incorrect passwords, unavailable policies, crashes, missing prompts, helper timeouts and unexpectedly successful authentication are **not** accepted as cancellation evidence. The fixture prints only fixed markers and does not accept user paths, process tool arguments, arbitrary prompt reasons, content or approvals. Its temporary executable is removed in cleanup.

**This is NOT yet integrated with an actual transfer approval.** No real OS-authentication verdict is currently bound to the digest/nonce-bound Phase 5 review, no local controller invokes this helper, no signed approval token exists, no file picker or user document is accessed, and `MCP_SANDBOX=required` remains fail-closed. A successful prompt in this fixture will justify implementing a trustworthy native review-bound verifier, not enabling transfers. CLI ad-hoc signing is not Developer ID production signing.

The pure Node verdict tests run in CI on Linux, but **only a human executing the three commands on macOS** can establish OS user-presence acceptance. Record each result separately and mark the native gate accepted only after all three complete successfully.

### October 14, 2026 — owner-auth cancellation is NOT accepted; isolate biometric-only policy

On my Mac, the disposable `mcp:mac-operator-auth` fixture passed both `probe` and `approve` using `LAPolicyDeviceOwnerAuthentication`, but the requested `cancel` mode returned **status 85 / BBX_LOCAL_AUTH_UNEXPECTED_SUCCESS**. This is an OS authentication **success**, *not* a `LAErrorUserCancel` response, so the strict negative verifier correctly rejected it. This is **not** evidence that the local operator's explicit cancellation was ignored by the OS: the output cannot identify the mechanism or prove when/whether a dialog appeared. Apple documents that the generic device-owner policy on macOS can attempt Touch ID and Apple Watch authentication in parallel, with password fallback. A successful Watch (or other configured mechanism) can race a cancellation attempt. The existing `touchIDAuthenticationAllowableReuseDuration=0` disables Touch ID device-unlock reuse; it does not prove that other allowed authentication paths cannot succeed.

I added three explicitly labeled **biometric-only** modes using the Apple `LAPolicyDeviceOwnerAuthenticationWithBiometrics` policy, without Watch/password fallback:

```sh
MCP_SANDBOX=off npm run mcp:mac-operator-auth -- touchid-probe
MCP_SANDBOX=off npm run mcp:mac-operator-auth -- touchid-approve
MCP_SANDBOX=off npm run mcp:mac-operator-auth -- touchid-cancel
```

These require enrolled and available Touch ID on the test Mac. In `touchid-approve`, authenticate with the enrolled finger. In `touchid-cancel`, **do not touch the sensor**; click the OS prompt's Cancel button. The negative test passes only if the callback supplies `LAErrorUserCancel` and the helper exits with **83** plus an exact, biometric-specific marker. Any unexpected successful authentication, unavailable policy, different error, invalid signature, timeout or absent GUI interaction remains **NOT ACCEPTED**. Biometrics-only tests do not retroactively pass the earlier generic owner-auth cancellation; results must be tracked separately and the production device-owner policy must be checked in its final configuration.

If `touchid-probe` is unavailable on hardware without Touch ID or enrollment, stop: do not weaken the test or interpret an unavailable biometric policy as a successful cancellation. The prior generic `approve` evidence remains accepted; generic `cancel` is unresolved. No native proof is wired into the Phase 5 approval controller, and no file access, MCP transfer or macOS required-mode behavior is enabled.

Apple references: [deviceOwnerAuthentication](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication), [deviceOwnerAuthenticationWithBiometrics](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics/), [LAErrorUserCancel](https://developer.apple.com/documentation/localauthentication/laerror/laerrorusercancel).

### Phase 5: review-bound real Touch ID acceptance harness (on-device pending)

The opt-in synthetic review demonstration now contains a dedicated macOS Touch ID binary and strict Node receipt validator. A disposable ad-hoc signed native helper evaluates LAPolicyDeviceOwnerAuthenticationWithBiometrics with a fresh LAContext, no fallback to Apple Watch or password. The trusted Node launcher creates an exact, expiring 1–2000-byte import review, logs a MAC_TRANSFER_REVIEW event into a temporary HMAC-authenticated audit store, and calls the helper with the immutable review ID, operation, synthetic note name, byte count, full SHA-256 digest and unique intent nonce. A successful native callback prints a fixed marker echoing review ID, nonce and digest; the Node verifier accepts *only* that exact output, status 0 and no errors, after rechecking expiry. An explicit LAErrorUserCancel callback returns distinct status 83 and a matching review-bound cancellation marker. Timeouts, crashes, altered outputs, other errors and cancelled requests are not accepted. No executable files are read or written besides a disposable compiled fixture and isolated temporary HMAC test artifacts.

The positive fixture's authenticated outcome may then drive exactly one in-memory controller.approve decision and one exact-byte consume. Its HMAC audit must contain a consumed synthetic review. The negative fixture accepts ONLY explicit OS user cancellation, calls controller.deny and confirms the review cannot be consumed. The test never opens a real document, contacts MCP, launches XPC, nor enables a production permission. No HTTP endpoint or operator-verifier configuration was changed.

Run both modes individually on a Mac with enrolled Touch ID:

    MCP_SANDBOX=off npm run mcp:mac-transfer-touchid -- approve
    MCP_SANDBOX=off npm run mcp:mac-transfer-touchid -- cancel

Complete the OS fingerprint prompt in the first mode. For the negative mode, click Cancel WITHOUT touching the sensor. **Do not mark this new integration gate accepted until both real Mac runs pass.** It is strictly synthetic. The OS's biometric success does not prove the specific named person's identity or that the full request summary was visibly understood; Apple may abbreviate the localized reason. A full trusted native review UI, user consent, real file picker, production code-signing trust, OS-denial and MCP required-mode acceptance remain mandatory before release.

### October 14, 2026 — real Mac review-bound Touch ID and owner-cancel ACCEPTED

I executed these acceptance commands on a real Mac with MCP_SANDBOX=off and recorded these exact outcomes:

- mcp:mac-transfer-touchid -- approve: the ad-hoc helper compiled and verified, an immutable synthetic transfer-intent review was HMAC-audited, an actual Touch ID prompt succeeded, the matching review ID/nonce/digest was validated, and the reviewed synthetic grant was consumed once with HMAC consistency.
- mcp:mac-transfer-touchid -- cancel: the native Touch ID prompt returned explicit user cancellation; the audited review was denied, could not be consumed, and HMAC consistency was verified.
- mcp:mac-operator-auth -- cancel: after correctly clicking Cancel rather than authenticating, the original general device-owner-policy test returned explicit LAErrorUserCancel evidence and passed.

The earlier unexpected general-policy authentication success was due to a positive authentication during a test expecting user cancellation. That earlier failed run remains part of the historical evidence, while the subsequent deliberate-cancellation run is accepted. Both the biometric-only and general owner-cancel acceptance tests have now produced successful negative evidence. This is real macOS acceptance, not merely Linux CI; no user files, native document picker, or production MCP operations were involved. Ad-hoc binary signing does not imply Developer ID positive authentication, and a synthetic review echo does not itself authenticate a native application's UI or human intent.

### Phase 5 next gate — synthetic macOS Open Panel file selection (unaccepted until Mac runs)

I added a separate NSOpenPanel fixture harness as an OS file-selection test, based on Apple's AppKit Open Panel interface. The temporary helper is ad-hoc signed and may choose exactly one file. The Node test harness creates a private temporary bbx-test-panel.txt synthetic fixture and compiles a disposable native AppKit application. The native panel starts in that temporary directory. If the operator selects another file or directory, the test fails. If selected, the native helper checks the chosen path is exactly the generated synthetic fixture, rejects symlinks and non-regular files, and emits only a fixed success marker; it does NOT read or return any file content or path. A native Cancel outcome is separately accepted only in cancellation mode.

On the development Mac, after pulling the branch, run the commands individually:

    MCP_SANDBOX=off npm run mcp:mac-native-picker -- select
    MCP_SANDBOX=off npm run mcp:mac-native-picker -- cancel

For select, explicitly choose ONLY the generated bbx-test-panel.txt and click Select Test File. For cancel, click Cancel WITHOUT selecting a file. The tested panel may let the operator browse outside the temporary fixture folder, but any different selection is rejected without opening/reading it; do not select personal documents. The temporary fixtures are deleted on exit. A successful picker test does not grant the MCP agent or native worker any capability to access user files, and the production signed, sandboxed document picker/import/export design is still pending. Mac MCP_SANDBOX=required must remain fail-closed.

### October 17, 2026 — native picker cancellation accepted; selection rejected (investigating path aliases)

An actual macOS NSOpenPanel run with MCP_SANDBOX=off returned an explicit user cancellation and the negative test **PASSED**. A separate selection trial returned exit 87 with BBX_MAC_PICKER_OUTSIDE_FIXTURE and therefore **FAILED CLOSED**. The marker does not identify the selected path or prove the precise root cause. macOS commonly presents temporary directories as /var/folders/... from Node's os.tmpdir(), while AppKit may resolve the same underlying location under /private/var/folders/...; string-equality checks can reject a legitimate selection of the identical file. The failed result is preserved pending independent Mac retest.

To distinguish a lexical path-alias mismatch from a different selected file without relaxing acceptance, the native diagnostic now uses lstat() to require BOTH selected path and original path to be the same user-owned, regular, non-symlink test fixture with the required byte size and exactly one link, and checks matching st_dev and st_ino. It also checks the exact bbx-test-panel.txt basename. This accepts only the *same inode* even if the parent path string is normalized differently, while rejecting another file, a leaf symlink, a hard-linked file, and unexpected panel actions. No file is opened, read, or returned. There is still a potential future TOCTOU concern if an actual import were ever added: this is test-only path identity, NOT durable permission or safe production file handle. Static tests and a parent-path-alias regression case accompany the change.

Acceptance remains pending until the actual Mac `MCP_SANDBOX=off npm run mcp:mac-native-picker -- select` succeeds after updating the branch. If it still fails, investigate the selected test fixture and AppKit behavior without weakening file identity checks, allowing arbitrary paths, logging personal paths or bypassing test denial. No production document access or MCP_SANDBOX=required mode was changed.

### October 17, 2026 — native picker positive acceptance passed on real macOS

The user reran `MCP_SANDBOX=off npm run mcp:mac-native-picker -- select` after commit b899044 (the inode-based fixture identity fix). The actual disposable, ad-hoc-signed macOS AppKit helper compiled, verified its signature, and returned **BBX_MAC_PICKER_EXACT_FIXTURE_SELECTED** for the generated bbx-test-panel.txt; the Node acceptance harness reported PASS. The earlier same-file `BBX_MAC_PICKER_OUTSIDE_FIXTURE` failure remains in the record as the pre-fix result. The real Mac cancellation path had already passed. This establishes *synthetic native picker selection and cancellation*, not a production capability to import external files.

### Next native negative acceptance: deliberate wrong synthetic file

I added `MCP_SANDBOX=off npm run mcp:mac-native-picker -- reject-other` to deliberately test denying the wrong file. The harness creates two owner-owned regular files in the same private temporary folder, `bbx-test-panel.txt` (allowed) and `bbx-test-other.txt` (intentionally disallowed). The human must **select bbx-test-other.txt** in the AppKit Open Panel, not Cancel and not the allowed file. The native helper checks that both pre-staged fixtures are individually safe, distinct inodes, and expected filenames in the same generated folder. It accepts as negative evidence ONLY an AppKit selection matching the alternate fixture's inode and basename. It then emits fixed `BBX_MAC_PICKER_OTHER_FIXTURE_REJECTED` with exit 87; the Node harness marks this explicit wrong-file rejection as a PASS for **reject-other only**. Selecting a different file, selecting the allowed fixture, cancelling, unavailable UI, unexpected errors, or any other output CANNOT pass the wrong-file negative test. No contents or selected path are opened, read, or returned. The helper is ad-hoc-signed and both fixtures are deleted after the test.

**Gate status: ACCEPTED on real macOS, October 17, 2026.** After commit 49eb286, the user ran `MCP_SANDBOX=off npm run mcp:mac-native-picker -- reject-other` and explicitly selected `bbx-test-other.txt`. The ad-hoc-signed AppKit fixture built and verified, and the native result was recognized as an independently verified alternate-file rejection. The CLI reported `PASS: Native file panel rejected the independently verified alternate synthetic fixture.` and `PASS: The fixture never returned file paths or contents to the caller.` This completes the *synthetic* picker acceptance matrix: exact fixture selection PASS (after the inode fix), explicit cancellation PASS, and wrong-file rejection PASS. The earlier pre-fix selection failure remains documented. The diagnostic is not a production authorization boundary: it does not exercise XPC transport, durable file handles, atomic import/export, full filesystem race prevention or signed host/worker trust. No actual file import/export was implemented, and macOS `MCP_SANDBOX=required` remains fail-closed.
