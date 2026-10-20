# Phase 6 — Native Selected-File Snapshot (experimental)

> **Current result — October 19, 2026:** I preserve this document as the chronological record of my earlier **synthetic-only selected-file, reviewed XPC, and RSA handoff experiments**. Since these entries were written, I separately added and on-device accepted an **operator-only, Apple Development-signed real-byte import/export** prototype with Open/Save Panels, fresh Touch ID, an independent matching SHA-256 round trip, and cancellation, size, overwrite, symlink and wrong-file negative checks. I also completed the fixed 39-byte **integrated RSA Keychain suite** with durable replay/restart and both uncertain-crash cases, plus installed required-mode legacy/modern MCP **synthetic note** acceptance. These remain **distinct** capabilities and do not establish arbitrary MCP document transfer or production authorization. See [my operator-transfer acceptance](v0.8-operator-transfer.md), [integrated RSA suite](v0.8-security-acceptance.md) and [final native acceptance matrix](v0.8-final-native-acceptance.md).

> **Historical scope:** Phrases below such as “real import/export disabled,” “required mode unavailable,” and “PENDING” identify the capabilities and open questions **at the time of those experiments**. I have kept failed trials and older conditions visible rather than retroactively rewriting them as successes. Current scope and unresolved production restrictions are stated in the linked final acceptance record.

## Scope
This feature tests a real, user-initiated macOS NSOpenPanel selection and bounded file-descriptor read of ONE generated synthetic fixture. It is not a document import, MCP tool, production signing, or production macOS sandbox permission. Only the byte count and SHA-256 digest are reported; the file path and contents are not returned.

## Security controls exercised
- Node creates exactly one bbx-test-snapshot.txt in a private temporary directory, with a disposable ad-hoc signed AppKit helper.
- A pre-panel O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK descriptor pins the generated fixture; only the exact selected fixture can be opened after the user acts.
- Both FDs must pass fstat: regular file, owner matches effective UID, exactly one hard link, 1–2000 bytes, identical device/inode/size. Path normalization between /var and /private/var is accepted only for the same inode.
- The selected leaf is opened with O_NOFOLLOW to exclude symlinks; unrelated file selections are rejected before any bytes are read.
- The helper reads only from the already opened selected FD, checking exact length, EOF and unchanged file metadata. A 2KiB buffer is wiped after computing CommonCrypto SHA-256.
- stdout includes only a fixed receipt carrying byte length and lowercase SHA-256. The trusted Node runner requires an exact process outcome and receipt, and uses constant-time digest comparison.
- All fixtures and binaries are deleted after the test. The entire experiment requires MCP_SANDBOX=off, never required mode.

## Real macOS acceptance — passed October 17, 2026
After switching to feature/v0.8-native-transfers and updating it, run each command individually:

    MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- select
    MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- altered

Choose ONLY bbx-test-snapshot.txt in the macOS native panel each time. The select mode must confirm the exact original fixture digest. The altered mode intentionally modifies one byte before the chooser opens; the native read must return the altered fixture's digest, and the controller-side verdict must reject it as different from the expected original. This is a CONTENT INTEGRITY negative test, NOT a concurrent filesystem race test. Never select personal documents.

An incorrect selection, cancellation, timeout, missing prompt, unavailable developer tools, or generic error cannot satisfy these acceptance gates.

## Production gates NOT met
Actual native import/export and XPC data transfer remain disabled. The ad-hoc helper is not Developer ID signed, the signed host/worker are not authenticated as same-Team-ID peers in production, a user-initiated picker has not yet been integrated with the review-specific Touch ID/HMAC authority, and durable file capabilities, atomic commit, race-safe transaction handling and worker-side checks remain outstanding. Production MCP_SANDBOX=required stays fail-closed.

Reference: https://developer.apple.com/documentation/Security/accessing-files-from-the-macos-app-sandbox

## October 17, 2026 — native compile failure and prevention

The first real Mac `select` and `altered` snapshot attempts **both failed during compilation**, before opening NSOpenPanel. Apple's Clang reported an undeclared `explicit_bzero` in SelectedFileSnapshot.m. The initial hypothesis was a missing function declaration header; the next macOS CI run demonstrated that adding `strings.h` was insufficient. Neither failed compilation run reached file-descriptor validation. The executable's local build now treats implicit function declarations as errors.

To prevent this Linux-only-CI blind spot, CI has a **macos-15 native compile** job for the snapshot fixture and three previously accepted native helpers using the real Apple SDK and `-Werror=implicit-function-declaration`. A successful macOS compile job confirms only native compilation, not OS prompt behavior, sandbox authorization, or successful file reads. At that stage, both Phase 6 GUI tests still required a real-Mac rerun.

## October 17, 2026 — follow-up CI result and SDK-compatible secure zeroing

The new **real macOS 15 native CI compile job failed** even after adding strings.h: `explicit_bzero` is not declared in the Xcode SDK tested. We therefore replaced `explicit_bzero` with Apple's documented `memset_s`, enabled by defining `__STDC_WANT_LIB_EXT1__ 1` before system headers. The secure_wipe helper treats any unexpected wipe error as fatal instead of continuing. Source contract tests cover the declaration and secure-wipe use.

The macOS compile job remains required and will be checked on this follow-up commit. Both native GUI tests were pending at the time of that fix; the successful results are documented below.

## October 17, 2026 — real Mac selected-file snapshots ACCEPTED

The operator reran both commands on the development Mac after the native-macos-compile CI fix (commit 92a2d796). The following results were observed directly:

- `MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- select`: **PASS**. The disposable AppKit/Objective-C helper compiled, its ad-hoc signature verified, and the OS picker returned the generated `bbx-test-snapshot.txt`. The already-opened, bounded file descriptor read yielded the expected SHA-256 digest and exact byte count. The helper printed neither the selected path nor its content.
- `MCP_SANDBOX=off npm run mcp:mac-selected-snapshot -- altered`: **PASS**. The same synthetic fixture was deliberately modified by one byte *before opening the panel*. The native helper successfully read and hashed that modified fixture, and the Node verdict rejected the altered digest against the expected original digest. This is controlled content-integrity testing, not a simultaneous modification or filesystem race.

**Acceptance scope complete for this slice:** native file-selection, bounded synthetic FD read, exact digest verification, and altered-content rejection all passed on a real Mac. The four-job CI run for the SDK-compatible source also passed (174/174 Node tests, native compilation, Linux sandbox, and MCP interoperability): https://github.com/christophervalle85/agent-black-box/actions/runs/39071303426

**What the evidence does NOT establish:** a user document was transferred, a native host passed data into XPC, code-signing identities were approved for production, prompt consent and file selection were tied to the same review, or kernel-mediated sandbox access was fully verified. The 2 KiB generated file is the only permitted read target in the present experiment. No release gate for `MCP_SANDBOX=required` was changed.

## Next independent gate: bounded reviewed bytes across authenticated native XPC

The next substantive security step should be a **separately tested, synthetic-only native transfer path**, not a generic request to 'open files'. Before any real document import, enforce these design constraints:

1. The trusted native host must own the NSOpenPanel interaction and read the selected file from a verified descriptor into a bounded, immutable snapshot. A path, copied URL, or digest-only receipt cannot be treated as an XPC authorization grant.
2. Issue one review for the exact operation, synthetic destination, data size, full SHA-256, unpredictable nonce and expiration. Present the review to the operator, run macOS authentication, and confirm pending state and unchanged bytes before authorizing one use.
3. Only a verified host-to-worker XPC channel can deliver the bounded bytes; the private sandboxed worker must independently verify the digest, destination constraints, nonce/authorization state, and single-use semantics. No remote model or ordinary HTTP request may set authority fields.
4. Reject cancel, wrong file, changed bytes, replay, forged or expired review, unauthorized XPC peers, worker crash, timeout, and partial commits with clear HMAC audit outcomes. An uncertain write must not be described as successful.
5. Preserve `MCP_SANDBOX=required` fail-closed until native positive **and** negative Developer ID / same-Team-ID code identity checks, App Sandbox confinement, and end-to-end on-device acceptance are complete.

Next-phase status: **not implemented**. The current Phase 6 commit is not a production document-transfer feature; do not merge or open a review PR until the next cohesive set of security gates is actually supported.

## Phase 6 next slice — bounded synthetic host-to-XPC data receipts (pending Mac acceptance)

An additional isolated test creates a disposable ad-hoc-signed app containing a sandbox-entitled XPC worker. The host transfers fixed 33-byte synthetic bytes inside an XPC DATA field. A separately compiled worker independently validates an exact five-key dictionary, the synthetic filename, 1–2000-byte payload size, 32-character random nonce and 64-character SHA-256 digest. It recomputes the digest over bytes received and refuses a mismatch. A process-local serial-queue nonce cache rejects a second use (up to 64 distinct nonces, then fail-closed). The worker returns only fixed status strings; no payload, file path, or file contents are written to disk or returned. The host checks responses and exposes one fixed outcome marker.

Run each mode separately on an interactive development Mac after updating feature/v0.8-native-transfers:

    MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- valid
    MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- tamper
    MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- replay

Valid must accept one bounded payload with matching digest. Tamper must deny one deliberately changed payload and then accept unmodified bytes with that same nonce, establishing that invalid bytes did not burn a nonce. Replay must accept once and then deny the identical nonce in the SAME XPC worker process. Each test must fail if the worker is unavailable, the process exits abnormally, or a receipt marker differs. The macOS CI job compiles both native files but cannot supply interactive XPC OS acceptance; the real Mac runs remain REQUIRED before marking this gate accepted.

SECURITY LIMITATIONS: This is an ad-hoc-signed transport and digest/replay experiment, not an OS-authenticated XPC peer. The receipt's nonce is generated by the test host and is NOT a Touch ID authorization grant, and its worker-side cache is not durable across crashes/restarts. No native picker-selected contents, controller-approved review bytes, operator-presence proof, MCP operations, document imports, or filesystem writes are connected to this worker. A malicious local client is not prevented from submitting its own well-formed synthetic receipt. Production must require same-Team-ID signing, a verified native consent chain, exact immutable review binding, durable replay protection when meaningful, and fail-closed transaction uncertainty handling. The worker's App Sandbox entitlement is checked, but its full production OS confinement acceptance is still pending. Required macOS sandbox mode remains fail-closed.

### XPC receipt implementation compile check (October 17, 2026)

The first macOS native compile job for the new transfer-receipt worker failed, correctly refusing an XPC dictionary enumeration callback with inferred int return type instead of bool. It also caught applying Objective-C ARC to the low-level XPC source that intentionally uses xpc_release. The worker now explicitly declares a bool-returning XPC block, and the macOS CI job compiles this specific native worker with -fno-objc-arc while retaining strict implicit-declaration checks. The test-only host itself is pure C. No real OS XPC receipt acceptance is claimed until the Mac runner build and subsequent on-device tests succeed.
 
### macOS XPC worker linker correction

After the callback/ARC adjustments, the macOS-15 CI compiler passed code generation but the linker reported missing __objc_personality_v0 for the Objective-C .m worker. The worker build now explicitly links the Foundation framework in both CI and the local XPC fixture runner, matching the existing AuthorityNotesService compilation. This was a compile/link gate failure; it did not exercise native XPC behavior. The real Mac receipt checks are still pending.

## October 17, 2026 — real macOS synthetic XPC receipt acceptance PASSED

The operator executed all three disposable native XPC experiments in an interactive macOS session after commit 7bc236a. Each ad-hoc native host/worker pair built, signed and verified; the worker was nested and sandbox-entitled. The observed results:

- `MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- valid`: **PASS**. The worker accepted the fixed synthetic payload when its recomputed SHA-256 matched the supplied digest.
- `MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- tamper`: **PASS**. The worker refused deliberately altered bytes, then accepted the correct bytes with the same nonce. This proves digest failure did not consume that nonce.
- `MCP_SANDBOX=off npm run mcp:mac-xpc-transfer-receipt -- replay`: **PASS**. The worker accepted the first request and refused reuse of the same nonce within the same worker process.

**This isolated XPC transport acceptance gate is complete.** These runs prove on-device outcomes for the fixed-payload transport/digest/nonce tests, not OS-authenticated application identity or a real file transfer. The worker does not know whether any specific request was reviewed or authorized. A malicious, unsigned or ad-hoc-signed local client may be able to produce a well-formed payload and digest, because the worker currently has no production incoming-peer requirement. Also, the replay cache is volatile; it does not establish cross-restart replay resistance. No user files, picker-selected bytes, Touch ID proof, controller approvals or filesystem writes traveled through the tested channel.

### Next engineering boundary (NOT ACCEPTED): host-owned, reviewed native transaction

Do not simply add reviewId/nonce/digest fields to the existing XPC dictionary and label the transfer 'authorized': a self-asserted review ID or digest does not prove user consent, host identity or permission. Instead:

1. Build a single trusted native-host flow that owns the user-selected file descriptor, snapshots bounded bytes, obtains a fresh review for those exact bytes, and presents a visible, immutable operation/target/size/hash review.
2. Require the real LocalAuthentication result on that same reviewed transaction; do not let a Node/HTTP/model-provided success flag act as OS-authentication evidence. Deny cancellation, expiry, altered bytes and review mismatch before any worker dispatch.
3. Establish OS-enforced code-signing peer requirements on **both sides** of the XPC channel before any transfer authority can cross it. Ad-hoc signing is insufficient for positive same-Team-ID trust. The existing negative peer requirement experiments are not substitutes for a positive signed-pair acceptance.
4. Treat an approved review as single-use; independently bind operation, destination, payload digest, size and fresh transaction nonce. Prevent a worker from honoring arbitrary self-declared manifests from untrusted callers. If the worker crashes, times out or has an unknown commit state, fail closed and preserve audit evidence.
5. Add a regression matrix for wrong identity, wrong review, cancelled auth, expired review, modified bytes, replay, worker restart, unauthorized filesystem access, and disclosure of paths/contents. A successful synthetic XPC receipt alone must never enable MCP_SANDBOX=required or document imports.

Production rollout blocker: verified signing identities / same-Team-ID enforcement and a trusted native UI/consent chain. Until then, the experimental receipt worker must not perform filesystem mutation and must stay unreachable from the ordinary MCP tool surface.

## October 17, 2026 — first Apple Development signed XPC peer identity gate (pending real-Mac run)

The development Mac now reports **one valid Apple Development code-signing identity** from `security find-identity -v -p codesigning`. No account identifier, email address, signing hash, or Team ID is recorded in this repository. A new opt-in fixture checks the positive requirement against Apple's real peer-signature API rather than treating ad-hoc signing as positive trust.

The existing synthetic XPC receipt native host and sandboxed worker gain code behind `BBX_TEST_SIGNED_PEER_REQUIREMENT`. Both call the existing `bbx_install_same_team_peer_requirement` once per XPC connection **before** `xpc_connection_resume` with the **exact expected peer signing identifier**. Apple's `xpc_connection_set_peer_team_identity_requirement` checks the peer is signed by the **same Team ID as the calling binary** as well as the peer's signing identifier. It does not take a Team ID as its second parameter. Missing/unsupported enforcement API fails closed. The ad-hoc XPC receipt fixture remains an independent ungated test and must NOT be viewed as production authorization.

An isolated Node launcher selects exactly one locally valid Apple Development certificate from Keychain (refuses absent, ambiguous, ad-hoc or distribution identities); compiles the two native binaries with the signed-peer macro; signs the nested XPC worker *before* its host app using the selected local development identity, not a repository-stored secret; checks exact signing identifiers, matching non-empty Team IDs, deep signature validity and the worker's App Sandbox/no-network entitlements; and executes a fixed payload test. All temporary app binaries are deleted after each run. It requires `MCP_SANDBOX=off` and never touches a real document, the MCP gateway or the Touch ID review path.

Two separate tests are needed (one invocation each):

    MCP_SANDBOX=off npm run mcp:mac-xpc-signed-peers -- signed-valid
    MCP_SANDBOX=off npm run mcp:mac-xpc-signed-peers -- wrong-worker

`signed-valid` requires the host and worker (both developer-signed with the same local identity) to exchange the known bounded synthetic payload and receive its expected digest-verified worker receipt while both OS-level peer requirements are installed. `wrong-worker` uses a purposely different worker signing identifier in the **host's OS-installed requirement**, while the worker is still genuinely signed. The native host only passes if the OS returns **`XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT`**. A timeout, connection error, unsigned worker, wrong Team ID, missing gate API, or generic XPC error CANNOT count as a pass. The exact certificate hash/Team ID/private keys are never printed to the transcript.

**Gate status: PENDING on-device acceptance.** CI compiles both macro-enabled variants on real macOS, but hosted CI has no local development signing identity and cannot claim a successful signed-peer connection. Even two successful tests would not prove denial of a separately signed *unauthorized inbound host* (that remains a separate negative test), nor tie Touch ID, reviewed payload bytes, actual file selections or durable revocation to XPC. Apple's expected certificate requirements are described at https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_team_identity_requirement and https://developer.apple.com/documentation/xpc/xpc_peer_requirement_create_team_identity . Production `MCP_SANDBOX=required` remains fail-closed. No user documents, filesystem writes or production transfer permissions are enabled.

## October 17, 2026 — positive signed peer accepted; separate negative blocked during Keychain signing

On the real development Mac, `MCP_SANDBOX=off npm run mcp:mac-xpc-signed-peers -- signed-valid` **PASSED**: the Apple Development-signed native host and App Sandbox worker reported matching Team IDs and expected signing identifiers, and the OS-gated same-team connection exchanged the fixed digest-verified synthetic receipt. This is **on-device positive acceptance** of the isolated code-signing identity fixture, not approval of any document transfer.

The separately invoked `-- wrong-worker` test **DID NOT COMPLETE**. It ended at `Apple Development worker signing failed; no signed XPC evidence was accepted.` The failure occurred before the host could run and before any OS peer-identity rejection was tested. This is neither a positive nor a negative XPC result; the underlying Keychain/codesign reason was previously suppressed by the harness. Do not record it as a successful unauthorized-peer denial.

### Retry one signed bundle, retain strict OS rejection

The native test harness now accepts `-- both` to compile and sign ONE nested development app/worker pair, verify signatures and entitlements once, then execute `signed-valid` followed by `wrong-worker` with the *same signed bundle*. This prevents the second Keychain signing operation from obscuring the negative OS check. Individual modes remain supported. Each native result still must exactly match its mode-specific status marker, and the negative result must come from Apple's specific `XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT`, not a timeout or generic transport failure.

Run the single combined test after pulling this branch:

    MCP_SANDBOX=off npm run mcp:mac-xpc-signed-peers -- both

Any failure is fail-closed. On signing failures, output now contains only a classified Keychain/codesign reason and numeric exit status, not raw command output, personal directory paths, email, signing certificate fingerprint, Team ID or private-key material. An unknown error remains explicitly unclassified; do not guess the cause. If the combined test fails, report the sanitized output for triage. **The wrong-worker OS rejection acceptance gate remains pending** until a successful run prints both positive and specific wrong-identity denial passes.

No real file contents, native picker, Touch ID grants, MCP endpoints or production XPC transfer are connected to this fixture. `MCP_SANDBOX=required` remains fail-closed.

## October 17, 2026 — combined Apple Development-signed XPC peer acceptance PASSED

The operator ran the post-fix combined native fixture on a real development Mac:

    MCP_SANDBOX=off npm run mcp:mac-xpc-signed-peers -- both

**PASS (positive signed peer):** The disposable host and sandboxed XPC worker compiled, were signed using the same local Apple Development identity, had matching Team IDs and exact expected signing identifiers, and passed signature/entitlement verification. With OS-enforced same-team and exact-identifier requirements installed before XPC connection resume, the two processes exchanged a bounded synthetic payload and the worker returned the matching digest receipt.

**PASS (incorrect outgoing worker identity):** In the SAME signed fixture invocation, the host installed a deliberately wrong expected worker identifier. The operating system returned its specific `XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT` rejection marker, which was strictly checked by the native host and Node harness. No generic timeout, unexpected XPC reply, code-signing failure, or missing OS gate is acceptable evidence for this case.

**Result:** These two *real-Mac* signed-peer acceptance checks are complete (2/2). The earlier standalone `wrong-worker` Keychain-signing failure is retained above as historical triage; it did not test XPC rejection. Reusing one signed bundle prevented that separate second-signing failure from confounding the paired test.

**Limitations:** This is still an isolated Apple Development-signed, synthetic-only experiment. It tests outbound worker-identity rejection with the trusted host's requirement; it does NOT independently demonstrate refusal of a separately signed unauthorized *incoming* host by the worker, nor prove a Developer ID production-distribution trust chain. No Touch ID proof is bound to XPC payload metadata, no selected file bytes flow into XPC, no real user-document operations or worker writes occur, and a valid digest/nonce is not an authorization grant. The synthetic test worker retains an in-memory replay cache only. `MCP_SANDBOX=required` remains fail-closed.

**Next acceptance gate:** Sign a genuinely different, unauthorized development test host (with a different code-signing identifier) and demonstrate that the worker's inbound requirement rejects it *without delivering a handler response*, while a correctly identified host succeeds. Keep this separate from attaching operator approval to exact transfer bytes; do not enable production file transfer based on this receipt alone.

## October 17, 2026 — signed unauthorized INCOMING host diagnostic (PENDING real-Mac acceptance)

The next isolated macOS test verifies the **worker's incoming** signing requirement, rather than only the previously accepted trusted host's outgoing requirement. This is an exact-identifier negative test using the development certificate already installed in the operator's local Keychain; the certificate, fingerprint, personal name, Team ID and private keys are never stored in the repository or sent to MCP. The normal MCP gateway remains disconnected.

The disposable native app includes two independently signed executables with **the same Team ID**, plus one sandbox-entitled nested XPC worker. The legitimate host executable has identifier `dev.agentblackbox.xpc-snapshot-receipt.host`. The second executable is deliberately signed as `dev.agentblackbox.xpc-snapshot-receipt.wrong-host`. Both are signed with the same local Apple Development identity; the worker requires the legitimate host's exact identifier and same Team ID on **each inbound connection before resume**. The two clients require the real worker's identifier and same Team ID on the outbound connection. All three identities must be verified after signing, and the worker must hold its App Sandbox entitlement with no network capability.

The signed legitimate host keeps its XPC connection open for the entire test, sends a known synthetic receipt and reads the worker's PID and a worker-owned count of *all delivered XPC dictionaries* from an explicitly test-gated diagnostics method. It then spawns the wrong-identifier sibling, which must send the same fixed synthetic receipt but obtain a **typed XPC connection error**, not an `ACCEPTED` reply. The legitimate host checks the **same worker PID** again and demands that only its own diagnostics incremented the worker handler count. If an unauthorized request reached the event handler, its counter would increase and the test would fail. This is necessary because Apple's incoming-peer requirement is designed to block handler delivery, not necessarily return the outgoing-only `XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT` to a rejected client. See https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_team_identity_requirement

Run on the development Mac, from the updated `feature/v0.8-native-transfers` branch:

    MCP_SANDBOX=off npm run mcp:mac-xpc-inbound-signed

Approve ONLY the expected macOS Keychain requests for `codesign` to access the **locally installed Apple Development private key**; select Allow for each expected signing request, not Always Allow. A Keychain prompt is about allowing local executable signing, not a user decision to reject XPC messages. No Touch ID approval, personal documents or picker selection occurs. The test may invoke signing for the worker, wrong host and container app, so there may be multiple prompts. Never send passwords, the private key or certificate hashes in chat.

**Acceptance PENDING:** Native compilation in CI validates API compatibility; a real-Mac run must demonstrate correct signing, the legitimate receipt, the typed error from the wrong host and unchanged message delivery count on the same live worker. A timeout, worker crash, an unsigned helper, a Team ID mismatch, a changed worker PID, malformed counters, unexpected handler delivery or a generic successful response must NOT be called passing. The worker diagnostic counter exists **only in a test-macro variant**, makes no persistent files, and is not an HMAC audit trail. This test does not authenticate a Touch ID-approved transaction or enable filesystem writes. `MCP_SANDBOX=required` must remain fail-closed.

## October 17, 2026 — real Mac incoming signed-host rejection ACCEPTED

The operator ran `MCP_SANDBOX=off npm run mcp:mac-xpc-inbound-signed` on the real Mac. The native harness reported all of the following:

- **PASS**: legitimate host, wrong-identifier helper, and sandboxed worker were Apple Development-signed with the **same Team ID**.
- **PASS**: the worker accepted the legitimate host's fixed synthetic receipt and rejected the differently signed incoming host **before handler delivery**.
- **PASS**: the same live worker PID remained active, and its handler-delivery counter incremented only for authorized control probes. No unauthorized message reached the worker's handler.

**Acceptance status: PASSED** for the isolated on-device incoming signing-identifier test. Taken together with the earlier signed-valid and wrong-worker results, synthetic outbound and inbound same-Team-ID/exact-identifier acceptance and negatives have been exercised on a real development Mac. These tests do not establish Developer ID production signing, actual file transfers, durable replay protection, or Touch ID-bound authorization.

The macOS Keychain asked for the login password/authorization three times because the harness runs `codesign --sign` three times: once for the sandboxed XPC worker, once for the wrong-identifier helper executable, and once for the containing legitimate host app. Each invocation can independently request access to the Apple Development signing private key. This permission is for **codesign**, not a decision to authorize the unauthorized host. For expected prompts, prefer **Allow** rather than **Always Allow**; never share a password or private key. A future harness could sign fewer times by reusing already-signed fixtures, but it must not weaken the separate exact code identities being tested.

**Next release blocker:** connect the real native Touch ID outcome and audited, single-use immutable review to exact synthetic bytes on a signed trusted host-to-worker connection; implement expiry/cancellation/mismatch/replay/crash negative tests and verify their on-device outcomes. Production `MCP_SANDBOX=required` remains fail-closed and MCP document access remains disabled.

## Phase 6 — native in-host Touch ID followed by signed XPC reviewed receipt (PENDING real Mac)

New isolated experimental signed `ReviewedTransferHost.m` keeps an entire fixed synthetic transaction inside a single native process. No request from Node, HTTP, MCP or an agent may set `approved=true`, select a file path or inject bytes. The host owns a 1–2000-byte **compiled-in fixture** `bbx-test-reviewed.txt`, generates a fresh random 32-digit hex nonce and review ID and 60-second timestamps, computes SHA-256, and uses a **biometric-only LocalAuthentication policy** with reuse duration zero. The reason displays synthetic import target, byte length and digest; macOS may truncate the displayed digest, so it is NOT yet a production immutable review UI. The native host rechecks expiry and byte digest *after* the OS prompt and, on approval only, creates an XPC connection to the expected worker with OS-enforced same-Team-ID and exact signing identifier. The sandboxed worker independently installs the exact trusted host peer requirement before resume.

Only a separate macro-enabled worker (`BBX_TEST_NATIVE_REVIEWED_RECEIPT`) accepts `reviewed_snapshot_receipt` with **exactly ten typed fields**: method, synthetic name, operation, review ID, nonce, SHA-256, declared byte length, issued-at epoch milliseconds, expiry epoch milliseconds, and raw payload. It rejects extra fields, incorrect types, wrong operation/name, length mismatch, invalid nonce/review ID, malformed/future/expired timestamps, altered SHA-256 bytes, replayed nonce and cache exhaustion. Receipts return only fixed status strings. The existing five-field receipt experiments remain unchanged when the macro is off. No filesystem mutation exists in either worker.

Test modes: `approved` (requires successful **real Touch ID**, deliberately sends tampered synthetic bytes first and demands DIGEST_MISMATCH, then sends exact reviewed bytes once and demands ACCEPTED, then demands REPLAY for the same nonce), `cancel` (requires clicking **Cancel** in the native Touch ID prompt, must return without creating XPC connection), and `expired` (constructs an intentionally expired review, refuses before a biometric prompt or any XPC dispatch). Each is a new disposable signed app. The host must fail closed for denied/missing biometrics, timeouts, modified bytes or unexpected XPC outcomes.

On a development Mac after pulling the current feature branch, run individually:

    MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- approved
    MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- cancel
    MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- expired

**Distinct OS permissions:** During initial executable preparation macOS may request Keychain password access for `codesign` to sign the native host and worker **twice**, possibly with multiple prompts; for an expected `codesign`/Apple Development key prompt select **Allow** (not Always Allow). The later **Touch ID prompt is a separate operator-decision test**: for `approved`, approve with Touch ID; for `cancel`, deliberately click **Cancel**. `expired` requires no Touch ID. Never share Keychain passwords, certificate fingerprints or signing keys. Real file panels do not appear.

**Critical limits:** This first native integration is a transport/authentication-bound experimental receipt, **not** the existing HMAC-audited Node controller's approval. Its self-generated review ID and nonce do not by themselves prove an independent audited approval, and the worker trusts the code-signed host to run LocalAuthentication correctly. The worker nonce cache is process-local, not restart-durable. There is no NSOpenPanel selected-file FD or user document, no trusted agent tool integration, no persisted audit of native approval/dispatch outcomes, no Developer ID production sign-off, and no OS production sandbox release acceptance. Testing must NOT change `MCP_SANDBOX=required` fail-closed semantics. Neither a successful Touch ID nor signed XPC identity alone is permission to read documents.

**Acceptance PENDING:** CI compiles the native sources with Apple's macOS SDK but cannot verify actual LocalAuthentication prompts and signed XPC IPC. On-device approved/cancel/expired mode outputs must be collected before claiming this milestone passed. Next phase must connect a verifiable HMAC-audited, single-use review, trusted native file descriptor to exact authorized bytes, and restart/crash denial semantics before production use.

### Combined one-signature-cycle real Mac fixture (preferred)

To minimize Keychain authorization prompts, `all` signs the same disposable nested worker and native host **once**, then runs three independently reviewed test subprocesses sequentially. This does not reuse any Touch ID approval: each subprocess creates its own review and fresh LAContext. Before and after the native Touch ID prompt, the host now compares a fully initialized immutable pre-authentication `NativeReview` snapshot with the post-authentication record (including review ID, nonce, digest, size, issued time and expiration); a modification cannot be accepted. The worker still independently checks every received byte and metadata field.

    MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- all

Expected order: **expired** (no Touch ID), **approved** (explicitly approve the Touch ID request), and **cancel** (explicitly click Cancel, not fingerprint authentication). For Keychain private-key access prompts *before* the native review test, verify they are for `codesign` and the expected Apple Development key, then click **Allow**. Keychain `Allow` and Touch ID approval are different actions with different meanings. The combined command does not grant new OS file permissions, and the real-Mac result remains PENDING until actually executed.

## October 17, 2026 — real Mac native Touch ID–reviewed signed XPC receipt ACCEPTED

The operator executed the combined on-device test after commit `f38c534b9b61fdb5ae2f3ca1d5c92d0374ae3b00`:

    MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- all

**PASS — signed host and worker:** Apple Development-signed native Touch ID host and sandboxed XPC worker were verified with matching Team IDs.

**PASS — expired:** The fixed synthetic review was rejected before biometric prompt or XPC dispatch. The harness printed `PASS: Expired synthetic native review denied before biometric prompt or XPC dispatch.`

**PASS — biometric approved:** After the operator approved the real macOS Touch ID prompt, the native signed host dispatched the in-binary synthetic reviewed payload. Worker returned expected digest-mismatch for changed bytes, accepted the exact reviewed bytes once, and rejected the repeated nonce. Harness printed `PASS: Native biometric approval permitted exact bytes once; altered bytes and replay were denied by the signed XPC worker.`

**PASS — biometric cancelled:** After the operator chose Cancel in the Touch ID prompt, the signed native host refused XPC dispatch. Harness printed `PASS: Explicit user cancellation blocked XPC dispatch within the signed native host.`

**Acceptance status: PASS (3/3 test modes on real Mac).** This demonstrates the local native biometric decision gating the experimental transport plus payload/replay checks. It does NOT demonstrate a production user-consent flow, independent audited approval, selected-file transfer, durable nonce consumption, rollback recovery, or MCP read authorization. The worker currently trusts the verified host to have performed LocalAuthentication and its own review construction. The reviewed synthetic fixture is compiled into that host; no personal documents, selected file descriptors, or arbitrary bytes were imported or exported. The development signing and test-only macro do not authorize production operations. `MCP_SANDBOX=required` remains fail-closed.

**Next boundary — not yet accepted:** Integrate the HMAC-verified audit and single-use trusted approval controller with the native host review/dispatch transaction. Define an accountable handoff that cannot be self-declared by a model or presented as an unverified bearer-token/boolean; ensure cancellation, expiry, changed bytes, replay, audit failures and uncertain native worker outcomes fail closed and are auditable. The eventual file-descriptor snapshot must be bound to exactly the bytes reviewed and authenticated, while preserving the current absence of any arbitrary file operations.

The trailing npm major-version update notice in the operator's console was advisory and did not affect native test acceptance.

## Phase 6 — HMAC-audited synthetic dispatch reservation (test-only, NOT a native handoff)

After real-Mac signed Touch ID and XPC acceptance, this slice introduces an **independent, opt-in synthetic transport reservation** in `createAuditedMacTransferController`. The constructor accepts a trusted in-process `syntheticTransport` callback, never an agent-supplied command, path, signed identity, approval flag, or native executable. **The ordinary server constructor does not inject this callback**, so its `macTransferHost` does not even have `dispatchSynthetic`. This is NOT yet a connection to `ReviewedTransferHost.m`, signed XPC or LocalAuthentication; the callback is a test-only simulator that can return `SYNTHETIC_ACCEPTED` or `SYNTHETIC_DENIED` and must not be mistaken for OS proof.

The synthetic reservation process uses the actual HMAC-chained `AuditStore` and existing `createMacTransferReviewPair` controller approval. A separate trusted `controller.decide` is required first. On `dispatchSynthetic` it (1) verifies the audit chain; (2) HMAC-audits `MAC_TRANSFER_DISPATCH_ATTEMPT`; (3) **irreversibly consumes** the reviewed approval BEFORE inspecting changed/forged metadata or bytes; (4) requires an HMAC-durable, reverified `MAC_TRANSFER_DISPATCH_RESERVED` before calling the synthetic transport; (5) runs the injected callback once with a copied bounded payload and frozen reviewed metadata; and (6) records `MAC_TRANSFER_DISPATCH_SIMULATED` (positive), `MAC_TRANSFER_DISPATCH_DENIED` (explicit rejection) or `MAC_TRANSFER_DISPATCH_UNCERTAIN` (throw, unknown result or timeout). A missing/failed terminal audit prevents a successful return.

All terminal classifications remain explicitly **simulated** and are not authorizations to transfer files. The timeout cannot cancel work already in flight: a timeout is an **uncertain outcome** requiring investigation, never permission to retry. The in-memory approval and nonce registry fail closed on process restart. A durable reservation event survives but a real native transaction recovery / signed acknowledgement protocol is not yet implemented. Any HMAC journal fault or integrity mismatch stops dispatch. Raw fixture bytes, nonce, SHA-256, bearer secrets and filesystem paths are not written into the audit reasons.

CI tests use a real temporary HMAC `AuditStore`, the existing isolated trusted controller facet and a fake injected transport to check: successful single-use reservation, changed bytes and metadata burn, explicit denial, malformed callback result, thrown callback, stalled callback timeout, append failure before transport, HMAC tampering, terminal audit failure, concurrent invocation and absence of the capability in the ordinary controller. The native Mac acceptance suite is unchanged by this stage; no new Keychain or Touch ID prompts are required.

**Do not call this a native-integrated approval.** The independent HMAC controller presently uses its own UUIDv4 nonce and review ID, whereas `ReviewedTransferHost.m` independently creates a different native review. Combining these requires a precise, code-signing-authenticated, non-model-accessible handoff and native confirmation bound to the SAME reviewed bytes, operation, destination, nonce, expiry and review ID. An OS-signed host must not treat a Node-side boolean, mutable JSON, or externally supplied manifest as an authenticated Touch ID outcome. Until a design establishes this end-to-end and has crash/restart negative acceptance, no real file descriptor transfer or production sandbox permission should be enabled. `MCP_SANDBOX=required` stays fail-closed.

## October 17, 2026 — canonical transaction enforcement real-Mac ACCEPTED

The operator ran `MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- all` on the real development Mac after commit `7cc20222fecf22f0fbc376cdd17a4f9a9b695966`. Same-Team Apple Development host/worker signature verification **PASSED**. The `expired` test blocked before biometric prompt or XPC. The `approved` test used a real Touch ID success and the signed XPC worker rejected intentionally modified **canonical transaction ID, protocol version, synthetic note target, and UUIDv4 nonce**; also rejected digest-tampered bytes, accepted the original synthetic bytes exactly once, and denied the replay. The `cancel` test explicitly cancelled Touch ID and blocked XPC dispatch. **3/3 real-Mac acceptance modes passed.** No HMAC/native handoff or real document access was tested in this run.

## Next isolated test: preissued HMAC-controller review data to signed native host (PENDING)

The test harness now supports `MCP_SANDBOX=off npm run mcp:mac-xpc-native-reviewed -- handoff`. It compiles a **test-macro-only** native host with strict stdin-envelope parsing. The trusted Node test harness constructs exactly one generated 39-byte synthetic fixture, opens a review in a temporary real `AuditStore` with its HMAC journal, derives the canonical transaction from the controller's original UUIDv4 review ID and nonce, and runs controlled invalid-envelope variants. Each malformed review **must** fail before Touch ID or XPC. It then stages approval through an **in-process local test controller facet** (not an authenticated production operator UI), burns the one-use approval, writes/verifies a durable HMAC reservation, launches the signed native executable as the injected synthetic transport callback, and supplies the original immutable transaction fields over a bounded stdin pipe. The native host checks schema, ID, actual compiled-in synthetic fixture digest/size and freshness **before** offering a new biometric-only LocalAuthentication prompt. Only after a real Touch ID success will it dispatch the exact payload to the signed sandboxed XPC worker, which independently checks the canonical ID, OS peer signing requirements, bytes and one-use nonce. The HMAC harness records the result as `simulated`, verifies the HMAC log, and confirms it cannot reuse the consumed review.

**Security limitations:** stdin is an integrity-checked **data envelope, not a signed or authenticated authority token**. This step tests an orchestrated, code-sign-verified process launch; it does **not** independently prove the native host's peer client is a trusted controller (another local process could invoke the same test executable), nor does it cryptographically authenticate the HMAC reservation to the native host or XPC worker. The local harness directly stages the controller decision and does not establish an authenticated human approval source; actual Touch ID is performed later inside the signed host. A success marker must never be treated as production authority, durable replay protection or proof that unknown native outcomes can be safely retried. The disposable audit/HMAC test files are deleted after the run. Never use personal files, paths, agent-controlled manifests or production MCP operations; macOS `MCP_SANDBOX=required` remains fail-closed.

**Real-Mac acceptance PENDING:** Native Apple SDK compilation and Node tests are not enough to claim the handoff passed. A real Mac test must report all invalid-envelope variants rejected without Touch ID, exactly one operator-approved biometric prompt, one signed XPC synthetic receipt with tamper/replay rejection, and one HMAC-audited dispatch with approval replay denied. On any failure, stop rather than reporting a partial acceptance as success.
