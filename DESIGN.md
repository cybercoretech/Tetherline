# Tetherline: design (draft for review)

**One encrypted, conflict-aware sync engine for every Cybercore app,
plus a tiny server on your own machine that only ever stores ciphertext.**

## Who uses it

| App | What syncs | Today |
|---|---|---|
| Cybernote | Markdown notes + attachments | local only; E2E sync was planned with Codex |
| CyberVault (Android ↔ desktop) | the CVL1 vault | manual export/import |
| Ghostframe | edit recipes, ratings, rejects per photo | local only |

## Architecture

- **`tetherline` (crate):** documents are opaque byte blobs with ids. Each change is
  an encrypted **op** `{doc_id, device_id, lamport, parent_hashes, ciphertext}`.
  - **Encryption:** the `age` format (X25519 recipients, so every device
    has its own key and a lost phone can be revoked) via the `age` crate.
    No homemade crypto.
  - **History:** a hash chain per document gives tamper evidence: the
    server can't reorder or drop ops unnoticed.
  - **Conflicts:** the app decides. Tetherline reports a conflict when two
    heads diverge and gives the app both versions plus the common ancestor.
    Apps with simple data use last-writer-wins helpers; Cybernote does a
    3-way text merge.
- **`tetherline-server`:** an axum service on blackbox, reached over the
  tailnet. It stores ops per space (SQLite + a blob dir), with append-only
  semantics, per-device tokens and quotas. It **never sees plaintext or
  keys**.
- **Mobile:** a uniffi bridge, the same pattern as CyberVault.
- **Recovery:** a recovery key (printed and kept offline) is an extra
  `age` recipient on every op, so losing every device isn't fatal.

## Milestones

1. Crate: the op format, encryption to N recipients, the hash chain,
   in-memory sync between two replicas, and property tests (random edit
   orders converge).
2. Server: append, fetch-since and device enrolment/revocation, end to end
   over the loopback address.
3. Cybernote integration (desktop TUI first).
4. CyberVault Android ↔ desktop.
5. Ghostframe.

## Decisions needed

- The server on **blackbox** or **darkbox**? (darkbox is always on.)
- How should a new device enrol: scan a QR code shown by an existing
  device (recommended), or paste an invite code?
