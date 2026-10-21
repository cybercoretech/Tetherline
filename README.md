# 🪢 Tetherline

**End-to-end encrypted, conflict-aware sync for your own devices. The server only ever stores ciphertext.**

Every change is an **op**: the document's new content, encrypted with [age](https://age-encryption.org) to every member device plus an offline recovery key, linked to its parent ops by SHA-256. The ops form a hash DAG per document, so a server can't alter, reorder or drop history without replicas noticing.

## 🧵 Milestone 1: the crate core

- **`Device`:** an age x25519 identity, plus the member keys new ops are encrypted to. `trust` adds a member and `revoke` removes one (a lost phone can't read anything written afterwards).
- **`Replica`:** `write`, `receive` (in any order; an op waits until its parents arrive), `read`, `heads`, `export`.
- **No silent merges:** concurrent edits give every replica the same `Read::Conflict` (both versions plus their common ancestor). Writing the resolution converges everyone.
- **Tamper-evident:** every received op's hash is re-checked, so a flipped byte or a forged clock is rejected.

```rust
let mut laptop = Replica::new(Device::generate("laptop"));
laptop.write("notes/todo.md", b"buy milk")?;
phone.receive(laptop.export())?;
assert_eq!(phone.read("notes/todo.md")?, Read::Value(b"buy milk".to_vec()));
```

## 🗺️ Roadmap

See [DESIGN.md](DESIGN.md):

1. ✅ Crate core
2. The `tetherlined` server on **darkbox** (stores ops, never keys)
3. **QR enrolment** for new devices
4. Holodrive, CyberVault and Nightwatch on top
5. Deltas and compaction

MIT licensed.
