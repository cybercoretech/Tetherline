//! Tetherline: end-to-end encrypted, conflict-aware sync for your own devices.
//!
//! Every change to a document is an [`Op`]: its plaintext is encrypted with
//! [age](https://age-encryption.org) to every member device (plus an offline
//! recovery key), and it names its parent ops by hash. The ops form a hash
//! DAG per document, so a server, which stores only [`Op`]s and never a key,
//! can't alter, reorder or drop history without replicas noticing.
//!
//! Merging never guesses. When two devices edit the same document
//! concurrently, every replica ends up with the same two heads and reports
//! the same [`Read::Conflict`] (both versions plus their common ancestor), and
//! an app-level resolution converges everyone.
//!
//! Milestone 1 stores whole-document snapshots per op; deltas, compaction and
//! the server come later.

use age::x25519;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::str::FromStr;

/// SHA-256 of an op's canonical encoding, hex.
pub type Hash = String;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The op's hash doesn't match its contents: tampered or corrupted.
    Tampered(Hash),
    /// This device isn't a recipient of the op (e.g. it was revoked before the op was made).
    NotARecipient(Hash),
    Crypto(String),
    BadKey(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Tampered(h) => write!(f, "op {} failed its hash check", short(h)),
            Error::NotARecipient(h) => write!(f, "op {} isn't encrypted to this device", short(h)),
            Error::Crypto(e) => write!(f, "encryption error: {e}"),
            Error::BadKey(e) => write!(f, "bad key: {e}"),
        }
    }
}
impl std::error::Error for Error {}

fn short(h: &str) -> &str {
    &h[..h.len().min(10)]
}

/// One encrypted change. This is all a server ever sees.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    pub doc: String,
    pub device: String,
    /// Lamport clock: greater than every parent's.
    pub lamport: u64,
    /// Hashes of the heads this op replaces (sorted, deduplicated).
    pub parents: Vec<Hash>,
    /// age ciphertext of the document's full new content.
    pub ciphertext: Vec<u8>,
    /// SHA-256 over everything above; checked on every receive.
    pub hash: Hash,
}

impl Op {
    fn compute_hash(
        doc: &str,
        device: &str,
        lamport: u64,
        parents: &[Hash],
        ciphertext: &[u8],
    ) -> Hash {
        let mut h = Sha256::new();
        // Length-prefixed fields so no two different ops share an encoding.
        for field in [doc.as_bytes(), device.as_bytes()] {
            h.update((field.len() as u64).to_be_bytes());
            h.update(field);
        }
        h.update(lamport.to_be_bytes());
        h.update((parents.len() as u64).to_be_bytes());
        for p in parents {
            h.update(p.as_bytes());
        }
        h.update((ciphertext.len() as u64).to_be_bytes());
        h.update(ciphertext);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn verify(&self) -> Result<(), Error> {
        if Self::compute_hash(
            &self.doc,
            &self.device,
            self.lamport,
            &self.parents,
            &self.ciphertext,
        ) == self.hash
        {
            Ok(())
        } else {
            Err(Error::Tampered(self.hash.clone()))
        }
    }
}

/// A device: its private age identity and the space's current member keys.
pub struct Device {
    pub id: String,
    identity: x25519::Identity,
    /// Public keys every new op is encrypted to: all member devices plus the
    /// recovery key. Removing a key revokes that device for future ops.
    recipients: BTreeMap<String, x25519::Recipient>,
}

impl Device {
    pub fn generate(id: &str) -> Device {
        let identity = x25519::Identity::generate();
        let mut recipients = BTreeMap::new();
        recipients.insert(id.to_string(), identity.to_public());
        Device {
            id: id.into(),
            identity,
            recipients,
        }
    }

    pub fn public_key(&self) -> String {
        self.identity.to_public().to_string()
    }

    /// Add (or replace) a member: another device or the recovery key.
    pub fn trust(&mut self, member: &str, public_key: &str) -> Result<(), Error> {
        let r =
            x25519::Recipient::from_str(public_key).map_err(|e| Error::BadKey(e.to_string()))?;
        self.recipients.insert(member.into(), r);
        Ok(())
    }

    /// Stop encrypting future ops to `member` (lost or retired device).
    pub fn revoke(&mut self, member: &str) {
        if member != self.id {
            self.recipients.remove(member);
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let rs: Vec<&dyn age::Recipient> = self
            .recipients
            .values()
            .map(|r| r as &dyn age::Recipient)
            .collect();
        let enc = age::Encryptor::with_recipients(rs.into_iter())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let mut out = Vec::new();
        let mut w = enc
            .wrap_output(&mut out)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        w.write_all(plaintext)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        w.finish().map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(out)
    }

    fn decrypt(&self, op: &Op) -> Result<Vec<u8>, Error> {
        age::decrypt(&self.identity, &op.ciphertext)
            .map_err(|_| Error::NotARecipient(op.hash.clone()))
    }
}

/// What a document currently reads as.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    Missing,
    Value(Vec<u8>),
    /// Concurrent edits. `versions` are sorted by op hash, so every replica
    /// reports them in the same order.
    Conflict {
        versions: Vec<(Hash, Vec<u8>)>,
        ancestor: Option<Vec<u8>>,
    },
}

/// One replica's view: every op it has, by hash, and the ones still waiting
/// for a parent that hasn't arrived yet.
pub struct Replica {
    pub device: Device,
    ops: HashMap<Hash, Op>,
    pending: HashMap<Hash, Op>,
}

impl Replica {
    pub fn new(device: Device) -> Replica {
        Replica {
            device,
            ops: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Current heads of `doc` (ops no other op names as a parent), sorted.
    pub fn heads(&self, doc: &str) -> Vec<Hash> {
        let referenced: BTreeSet<&Hash> = self
            .ops
            .values()
            .filter(|o| o.doc == doc)
            .flat_map(|o| o.parents.iter())
            .collect();
        let mut h: Vec<Hash> = self
            .ops
            .values()
            .filter(|o| o.doc == doc && !referenced.contains(&o.hash))
            .map(|o| o.hash.clone())
            .collect();
        h.sort();
        h
    }

    /// Write `content` as the new state of `doc`, superseding every current
    /// head. Writing while in conflict is how a conflict is resolved.
    pub fn write(&mut self, doc: &str, content: &[u8]) -> Result<Op, Error> {
        let parents = self.heads(doc);
        let lamport = parents
            .iter()
            .filter_map(|p| self.ops.get(p))
            .map(|o| o.lamport)
            .max()
            .unwrap_or(0)
            + 1;
        let ciphertext = self.device.encrypt(content)?;
        let hash = Op::compute_hash(doc, &self.device.id, lamport, &parents, &ciphertext);
        let op = Op {
            doc: doc.into(),
            device: self.device.id.clone(),
            lamport,
            parents,
            ciphertext,
            hash: hash.clone(),
        };
        self.ops.insert(hash, op.clone());
        Ok(op)
    }

    /// Take ops from anywhere (a server, another replica), in any order.
    /// Tampered ops are rejected; ops whose parents haven't arrived wait.
    pub fn receive(&mut self, incoming: impl IntoIterator<Item = Op>) -> Result<(), Error> {
        for op in incoming {
            op.verify()?;
            if !self.ops.contains_key(&op.hash) {
                self.pending.insert(op.hash.clone(), op);
            }
        }
        // Apply everything whose parents are present, until nothing moves.
        loop {
            let ready: Vec<Hash> = self
                .pending
                .values()
                .filter(|o| o.parents.iter().all(|p| self.ops.contains_key(p)))
                .map(|o| o.hash.clone())
                .collect();
            if ready.is_empty() {
                return Ok(());
            }
            for h in ready {
                if let Some(op) = self.pending.remove(&h) {
                    self.ops.insert(h, op);
                }
            }
        }
    }

    /// Ops still waiting for a parent (a gap in what we've been sent).
    pub fn waiting(&self) -> usize {
        self.pending.len()
    }

    /// Everything this replica has, for syncing to another.
    pub fn export(&self) -> Vec<Op> {
        let mut v: Vec<Op> = self.ops.values().cloned().collect();
        v.sort_by(|a, b| (a.lamport, &a.hash).cmp(&(b.lamport, &b.hash)));
        v
    }

    pub fn read(&self, doc: &str) -> Result<Read, Error> {
        let heads = self.heads(doc);
        match heads.len() {
            0 => Ok(Read::Missing),
            1 => Ok(Read::Value(self.device.decrypt(&self.ops[&heads[0]])?)),
            _ => {
                let versions = heads
                    .iter()
                    .map(|h| Ok((h.clone(), self.device.decrypt(&self.ops[h])?)))
                    .collect::<Result<Vec<_>, Error>>()?;
                let ancestor = match self.common_ancestor(&heads) {
                    Some(a) => Some(self.device.decrypt(&self.ops[&a])?),
                    None => None,
                };
                Ok(Read::Conflict { versions, ancestor })
            }
        }
    }

    /// The newest op that is an ancestor of every head (for 3-way merges).
    fn common_ancestor(&self, heads: &[Hash]) -> Option<Hash> {
        let ancestors = |start: &Hash| {
            let mut seen = BTreeSet::new();
            let mut stack = vec![start.clone()];
            while let Some(h) = stack.pop() {
                if let Some(op) = self.ops.get(&h) {
                    for p in &op.parents {
                        if seen.insert(p.clone()) {
                            stack.push(p.clone());
                        }
                    }
                }
            }
            seen
        };
        let mut common = ancestors(&heads[0]);
        for h in &heads[1..] {
            let a = ancestors(h);
            common.retain(|x| a.contains(x));
        }
        common
            .into_iter()
            .max_by(|a, b| (self.ops[a].lamport, a).cmp(&(self.ops[b].lamport, b)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    /// Two devices of one space, each trusting the other plus a recovery key.
    fn pair() -> (Replica, Replica, x25519::Identity) {
        let recovery = x25519::Identity::generate();
        let mut a = Device::generate("laptop");
        let mut b = Device::generate("phone");
        let (ka, kb) = (a.public_key(), b.public_key());
        a.trust("phone", &kb).unwrap();
        b.trust("laptop", &ka).unwrap();
        a.trust("recovery", &recovery.to_public().to_string())
            .unwrap();
        b.trust("recovery", &recovery.to_public().to_string())
            .unwrap();
        (Replica::new(a), Replica::new(b), recovery)
    }

    fn sync(from: &Replica, to: &mut Replica) {
        to.receive(from.export()).unwrap();
    }

    #[test]
    fn edits_sync_and_ciphertext_hides_content() {
        let (mut a, mut b, _) = pair();
        let op = a.write("notes/todo.md", b"buy milk").unwrap();
        assert!(
            !op.ciphertext.windows(4).any(|w| w == b"milk"),
            "plaintext must not appear in the op"
        );
        sync(&a, &mut b);
        assert_eq!(
            b.read("notes/todo.md").unwrap(),
            Read::Value(b"buy milk".to_vec())
        );
        b.write("notes/todo.md", b"buy oat milk").unwrap();
        sync(&b, &mut a);
        assert_eq!(
            a.read("notes/todo.md").unwrap(),
            Read::Value(b"buy oat milk".to_vec())
        );
    }

    #[test]
    fn concurrent_edits_conflict_identically_then_converge() {
        let (mut a, mut b, _) = pair();
        a.write("d", b"base").unwrap();
        sync(&a, &mut b);
        a.write("d", b"from laptop").unwrap();
        b.write("d", b"from phone").unwrap();
        sync(&a, &mut b);
        sync(&b, &mut a);
        let (ra, rb) = (a.read("d").unwrap(), b.read("d").unwrap());
        assert_eq!(ra, rb, "both replicas see the same conflict");
        let Read::Conflict { versions, ancestor } = ra else {
            panic!("expected a conflict")
        };
        let mut texts: Vec<&[u8]> = versions.iter().map(|(_, v)| v.as_slice()).collect();
        texts.sort();
        assert_eq!(texts, [&b"from laptop"[..], b"from phone"]);
        assert_eq!(ancestor.as_deref(), Some(&b"base"[..]));
        // Resolve on one side; both converge.
        a.write("d", b"merged").unwrap();
        sync(&a, &mut b);
        assert_eq!(a.read("d").unwrap(), Read::Value(b"merged".to_vec()));
        assert_eq!(b.read("d").unwrap(), Read::Value(b"merged".to_vec()));
        assert_eq!(a.heads("d"), b.heads("d"));
    }

    #[test]
    fn any_delivery_order_converges() {
        let (mut a, mut b, _) = pair();
        for i in 0..6 {
            a.write("x", format!("a{i}").as_bytes()).unwrap();
            if i % 2 == 0 {
                sync(&a, &mut b);
                b.write("x", format!("b{i}").as_bytes()).unwrap();
                sync(&b, &mut a);
            }
        }
        let all = a.export().into_iter().chain(b.export()).collect::<Vec<_>>();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut reference: Option<(Vec<Hash>, Read)> = None;
        for _ in 0..20 {
            let mut shuffled = all.clone();
            shuffled.shuffle(&mut rng);
            let mut fresh = Replica::new(Device::generate("observer"));
            // The observer can't decrypt (not a recipient) but must still agree on structure.
            for op in shuffled {
                fresh.receive([op]).unwrap();
            }
            assert_eq!(fresh.waiting(), 0, "every op eventually applies");
            let heads = fresh.heads("x");
            match &reference {
                None => reference = Some((heads, Read::Missing)),
                Some((h, _)) => assert_eq!(&heads, h, "same heads whatever the order"),
            }
        }
        assert_eq!(reference.unwrap().0, {
            let mut full = Replica::new(Device::generate("o2"));
            full.receive(all).unwrap();
            full.heads("x")
        });
    }

    #[test]
    fn tampering_is_rejected() {
        let (mut a, mut b, _) = pair();
        let mut op = a.write("d", b"hello").unwrap();
        op.ciphertext[40] ^= 1;
        assert_eq!(
            b.receive([op.clone()]),
            Err(Error::Tampered(op.hash.clone()))
        );
        let mut reordered = a.write("d", b"two").unwrap();
        reordered.lamport = 99;
        assert!(matches!(b.receive([reordered]), Err(Error::Tampered(_))));
    }

    #[test]
    fn ops_wait_for_missing_parents() {
        let (mut a, mut b, _) = pair();
        let first = a.write("d", b"1").unwrap();
        let second = a.write("d", b"2").unwrap();
        b.receive([second]).unwrap();
        assert_eq!((b.waiting(), b.read("d").unwrap()), (1, Read::Missing));
        b.receive([first]).unwrap();
        assert_eq!(
            (b.waiting(), b.read("d").unwrap()),
            (0, Read::Value(b"2".to_vec()))
        );
    }

    #[test]
    fn revoked_devices_cant_read_new_ops_but_recovery_can() {
        let (mut a, mut b, recovery) = pair();
        a.write("d", b"before").unwrap();
        sync(&a, &mut b);
        a.device.revoke("phone");
        a.write("d", b"after revocation").unwrap();
        sync(&a, &mut b);
        assert!(matches!(b.read("d"), Err(Error::NotARecipient(_))));
        let newest = a.export().into_iter().last().unwrap();
        assert_eq!(
            age::decrypt(&recovery, &newest.ciphertext).unwrap(),
            b"after revocation"
        );
    }

    #[test]
    fn op_json_roundtrip_keeps_hash_valid() {
        let (mut a, _, _) = pair();
        let op = a.write("d", b"x").unwrap();
        let back: Op = serde_json::from_str(&serde_json::to_string(&op).unwrap()).unwrap();
        assert_eq!(back, op);
        back.verify().unwrap();
    }
}
