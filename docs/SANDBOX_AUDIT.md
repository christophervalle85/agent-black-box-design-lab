# v0.6: OS sandboxing and audit integrity

> **Version context (updated October 19, 2026):** I preserve this guide's v0.6 Linux Bubblewrap design and original macOS limitation as historical background. On my **v0.8 feature branch**, I have since accepted a separately installed **Apple Development-signed macOS App Sandbox XPC worker** for bounded synthetic MCP notes in `MCP_SANDBOX=required`. The ordinary Node controller is still unsandboxed; the XPC worker is not a general file-transfer service or a production notarized release. See [my accepted native tests and current limitations](v0.8-final-native-acceptance.md).

## Official sources

- [Bubblewrap upstream manual](https://github.com/containers/bubblewrap/blob/main/bwrap.xml) — namespace options, `--ro-bind`, `--bind`, `--unshare-net`, `--new-session`, `--die-with-parent`.
- [Apple App Sandbox](https://developer.apple.com/documentation/security/app-sandbox) and [signed helpers](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app) — a sandboxed macOS helper requires signing and entitlements. An arbitrary child process launched by Node is **not** equivalent.
- [NIST FIPS 198-1 HMAC](https://csrc.nist.gov/pubs/fips/198-1/final) and [Node.js `crypto.createHmac`](https://nodejs.org/api/crypto.html#cryptocreatehmacalgorithm-key-options) — keyed SHA-256 authentication.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — restricted storage, tamper detection, verification and log safety.

## OS sandbox: explicit modes

`MCP_SANDBOX=off` (default): The downstream is **not OS-sandboxed**. The existing path validation, tool allowlist and human approval still apply. This is the compatible local demo mode on macOS.

`MCP_SANDBOX=required`: **Linux v0.6 path:** requires Bubblewrap at `/usr/bin/bwrap`, or `MCP_BWRAP_PATH=/absolute/path/to/bwrap`, and refuses missing/denied kernel namespace isolation. **macOS v0.8 feature-branch path:** requires my explicitly installed, locally signed and verified native host plus separately sandboxed XPC worker, its Team ID trust pin and exact workspace binding. It fails closed without that installation; it never substitutes an ordinary unsandboxed Node notes subprocess. I do **not** claim OS sandboxing for the parent controller. See [native acceptance](v0.8-final-native-acceptance.md).

The Bubblewrap process uses separate user/PID/IPC/UTS/network namespaces, a new session, die-with-parent, a private `/tmp`, minimal `/proc` and `/dev`; exposes the runtime and the specific bundled program and necessary system libraries read-only, and mounts only `demo-workspace` with write permission. No inherited `NODE_OPTIONS`, HOME, service token or audit secrets are passed to the child. It cannot access the host project's `data/` by these mounts. This is a **mount namespace isolation prototype**, not seccomp, a container security suite, or a defense against kernel bugs.

### Linux manual check

```bash
sudo apt-get install bubblewrap     # Debian/Ubuntu example
MCP_SANDBOX=required npm run mcp:smoke
MCP_SANDBOX=required npm run mcp:modern
```

Both commands must pass on a **Linux host configured to permit user and network namespaces**. GitHub-hosted Ubuntu CI can deny Bubblewrap network-namespace setup (`Failed RTM_NEWADDR: Operation not permitted`); our CI documents that host limitation and verifies fail-closed behavior rather than presenting it as a successful sandbox run. Full isolated execution remains an additional acceptance test on a compatible Linux machine. In particular, merely seeing `bwrap --version` succeed does **not** prove user namespaces can be created. An actual MCP call must succeed. If it fails, do **not** silently switch to `off` for untrusted servers; investigate OS namespace policy first.

### macOS users

Apple documents an official App Sandbox for signed applications and helpers using `com.apple.security.app-sandbox` entitlements. A shell-launched Node subprocess does **not** acquire those entitlements automatically. In v0.6, I therefore refused macOS `required` mode. On the v0.8 feature branch I now allow it **only** after verification of an explicitly installed, Apple Development-signed native host, sandboxed XPC worker, trust pin, expected OS peer requirements and canonical private Documents workspace. My real-Mac tests confirmed host-file and loopback denial in a disposable diagnostic worker-source build, and passed actual legacy/modern required-mode MCP requests on the installed worker. This is **not** a Developer ID/notarized production boundary, and the Node controller remains outside App Sandbox. I do not use undocumented `sandbox-exec` profiles as a substitute.

## Integrity files and enrollment

`data/audit.jsonl` stays in its existing readable JSONL format. The store maintains these private mode `0600` companions:

- `data/audit.jsonl.hmac.key`: randomly generated 32-byte key encoded as hex. **Never commit, expose via MCP or share**.
- `data/audit.jsonl.mac.jsonl`: each entry has monotonically increasing `seq`, prior MAC (`prev`), and HMAC-SHA256 (`mac`) authenticating the exact JSONL line and sequence.
- `data/audit.jsonl.anchor.json`: durable sequence/head-MAC checkpoint used to detect deletion of the signed tail.

For a **new empty** data store, initial signing is automatic. For an existing nonempty v0.5 log, the server refuses to run until you explicitly seal it:

```bash
# Run only after you trust and have reviewed the old local history.
npm run audit:seal
npm run audit:verify
```

Sealing preserves the original bytes at `data/audit.jsonl.pre-v06.jsonl` (exclusive creation; refuses to overwrite a previous backup) and signs the original history. **Events before sealing are not retroactively proven authentic.** Never rerun sealing to ignore an integrity failure; do not delete the chain/key/checkpoint to reset it.

On restart and before reads or tool adapters, the store verifies every line and its corresponding HMAC/checkpoint; failures **fail closed**. `GET /api/audit/integrity` returns current verification results; the dashboard's protection panel displays the status. The writer uses a directory lock across the dashboard and gateway processes. A crash while holding the lock leaves a stale `data/audit.jsonl.writer.lock` directory: verify all processes have exited and investigate storage integrity before clearing it. Crash between the three writes may also leave an inconsistent log; restore the last known-good verified backup or repair only through a controlled incident-recovery process. No unverified automatic repair is provided.

### Integrity threat model

Detects offline modification, truncation, deletion of individual signed events, wrong checkpoints, missing companion metadata, and mismatched sequence. Protects file contents from accidental exposure via mode `0600`; avoids logging raw note contents.

**Does not** protect against a malicious or compromised same-user process that can read the key, create alternate signatures and replace the checkpoint; an attacker who can erase *all* local state; root/admin compromise; disk rollback including key and checkpoint; replay of independently copied whole snapshots; log confidentiality against same-user processes; or physical hardware failures. For independently verifiable, immutable evidence, sign/export periodic checkpoint heads to a separately administered storage or transparency service, run under a different OS identity, and deploy proper key management.

Verification reads the chain (bounded to 64 MiB) and therefore has linear I/O/CPU cost. At scale, use an indexed append-only store and secure remote attestations rather than this local prototype. No unsafe automatic repair is attempted after partial writes. A full event is fsynced before its MAC is appended; the MAC is fsynced before the checkpoint is atomically replaced.


### Ubuntu AppArmor and real isolation acceptance

Ubuntu 24.04's \`kernel.apparmor_restrict_unprivileged_userns=1\` may deny
Bubblewrap network namespace setup (\`RTM_NEWADDR: Operation not permitted\`).
Do not disable AppArmor globally. The upstream
[AppArmor v4.1 Bubblewrap profile](https://gitlab.com/apparmor/apparmor/-/raw/v4.1.0/profiles/apparmor/profiles/extras/bwrap-userns-restrict)
allows namespace setup and stacks \`unpriv_bwrap\` on the executed child
to drop its capabilities. Any adapted profile must be reviewed and tested;
a copied executable plus local policy is **host configuration**, not part
of the default gateway installation.

On a compatible Linux test VM with the dedicated profile installed:

\`\`\`bash
MCP_BWRAP_PATH=/usr/local/libexec/agent-black-box/bwrap MCP_SANDBOX=required npm run mcp:isolation
\`\`\`

The acceptance script uses the **same downstream launch plan** as the MCP gateway,
then replaces the downstream program with a benign checker. It verifies
the child is in an enforcing \`unpriv_bwrap\` AppArmor profile; mount and
network namespace identities differ from the host; a temporary host-only
file is inaccessible; the approved workspace remains writable; and an
outbound IPv4 connection is rejected with a network/permission error.
The script deletes its temporary host and workspace files. If the test
fails or the profile is in complain mode, **do not call this host hardened**.

This diagnostic checks specific boundaries, not complete isolation,
syscall filtering, kernel vulnerability resistance, or production readiness.
