# v0.7 — Audit trust, crash recovery, and incidents

## Official documentation reviewed

- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final) — records, monitoring, and log-management controls.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — attack surface, confidentiality, integrity, and availability of logs.
- [Node.js crypto: Ed25519 signing and verification](https://nodejs.org/api/crypto.html) — public-key signatures and key formats.
- [Node.js file APIs](https://nodejs.org/api/fs.html) — fsync, exclusive creation, no-follow, and atomic rename primitives.
- [SQLite atomic commit](https://sqlite.org/atomiccommit.html) — multi-step durable write and crash recovery principles; this release remains JSONL, **not SQLite**.
- [AWS S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) — optional future immutable off-host retention; AWS is not required by this release.

## Checkpoint receipts and independent verifier

`npm run anchor:export` creates a JSON receipt for the *verified* local HMAC chain head. The receipt contains: version, stable log ID derived from SHA-256 of the 256-bit local HMAC key, sequence, chain head, creation timestamp, and an Ed25519 public key + detached signature. **No raw events or HMAC secret leave the Mac.** The Ed25519 signing key and public-key identity are stored under the local audit filename as `*.receipt-ed25519.key` and `*.receipt-ed25519.public`, mode 0600. Back them up securely alongside (not inside) your regular project copy. Never commit keys.

On Mac:

```sh
npm run audit:verify
npm run --silent anchor:export > checkpoint.json
# Transfer ONLY checkpoint.json to Ubuntu VM via reviewed clipboard / trusted transfer.
```

On Ubuntu VM, from the project repository, **under a separate OS identity** and choosing a ledger file owned by that identity:

```sh
cat checkpoint.json | npm run anchor:receive -- --ledger "$HOME/blackbox-external-evidence/receipts.jsonl"
npm run anchor:ledger -- --ledger "$HOME/blackbox-external-evidence/receipts.jsonl"
```

The receiver verifies the Ed25519 signature; the first receipt pins a log identity and public key (explicit **trust on first use**). Later receipts cannot downgrade sequence or change the head at the same sequence; signing key substitution is rejected. The receiver appends receipts with 0600 permission and fsync. Keep its ledger and any backups out of reach of the monitored Mac user. Linux VM on Mac is convenient testing but not a wholly independent physical trust domain.

For strongest local validation, copy a previously accepted receipt *back* from the independent verifier, and on Mac run:

```sh
npm run anchor:compare -- --receipt previously-accepted-checkpoint.json
```

This recomputes the whole HMAC chain, compares the log identity, local Ed25519 public key, and the **MAC at the previously anchored sequence**. It detects a shortened local history or a re-HMACed fork even if local HMAC validation was made to pass using a compromised local HMAC key. Never use a newly generated receipt as your sole baseline; the reference must come from independent custody.

**Limitations:** The signing key is on the same machine and protected only by filesystem permissions. A local-key compromise enables forged *future* receipts; the receiver does not prove extension of the previously anchored chain for increased sequences. Receipt transport is manual, not automatic; delivery can be suppressed. A same-user process can rewrite an unprotected receipt copy or ledger. A rollback of both physical Mac and VM defeats the demonstration. The initial receiver enrollment is TOFU. No immutable cloud storage, PKI, external time authority, transparency log or strong adversary-resistant receipt service is claimed.

## Crash-consistent audit journal

Before appending a record and MAC, `AuditStore.add` atomically persists and fsyncs `audit.jsonl.pending.json` with the exact signed transaction intent (`seq`, `prev`, raw event, MAC). It then appends and fsyncs the audit record and the MAC in order, atomically updates and syncs the checkpoint, and removes the pending file.

On restart, the audit store only repairs a pending transaction when:

1. The journal MAC matches the local signing key.
2. The complete previously signed history matches its MACs and the journal's `prev` head.
3. The file suffixes are each either missing, complete, or byte prefixes of **the exact journaled event/MAC**.
4. The checkpoint matches the earlier or final signed sequence, never a different head or earlier rollback.

It then replays only missing bytes, verifies the complete chain, and removes the journal. Arbitrary tampering, an incorrect checkpoint, incomplete metadata, or inconsistent suffixes **remain fail-closed**. A crash before the pending file was durably published cannot be recovered as a signed event; no promise about evidence for an operation that crashed *before* `add` began. Forced-power-loss durability depends on filesystem/OS correctness, which is not equivalent to tests that throw between operations. Never delete a pending journal to silence an incident. The existing v0.6 history remains compatible; no resealing is needed.

## Incident visibility

`GET /api/audit/incidents` reports verified state or `RECOVERY_REQUIRED` / `AUDIT_INTEGRITY_FAILURE` / `EXTERNAL_CHECKPOINT_MISMATCH` without exposing raw logs, HMAC secrets or signing keys. The dashboard Protection status panel reflects those states. When the audit store **cannot open at startup**, the server intentionally refuses to start; inspect with `npm run audit:verify` and preserve evidence rather than reinitializing the store.

Optional `MCP_EXTERNAL_RECEIPT_FILE=/absolute/path/accepted-receipt.json` enables on-request local comparison against a receipt copied from independent storage. Since a local receipt copy can be altered by the compromised host user, treat this as an operator convenience, not an independent verification boundary. On failure it responds with 503 and no protected operation should be interpreted as safe.

## Security testing and deployment gate

Regression tests simulate interruptions after each journal stage, partial suffix replay, malicious audit prefix edits, malformed pending journals, signed checkpoint integrity, identity/key substitution, sequence rollback, and full local HMAC re-signing that cannot match an earlier independently anchored head. The existing MCP legacy/modern SDK, human approvals, and Bubblewrap policies must continue passing.

No production-grade forensic chain of custody, crash-proof storage hardware guarantees, remote receiver authentication infrastructure, or macOS native OS sandbox is implied by this release.
