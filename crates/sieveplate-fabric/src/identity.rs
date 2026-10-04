//! Host identities and peer pinning for the secure fabric link.
//!
//! Every host owns two long-term signing keys:
//! - **Ed25519** (classical) — small, fast, universally understood.
//! - **ML-DSA-65** (post-quantum, FIPS 204) — survives a large quantum
//!   computer running Shor-adjacent attacks on Ed25519.
//!
//! Handshake signatures are **hybrid catena**: a message is signed with
//! *both* keys and a peer is authenticated only when *both* verify. That
//! gives no downgrade path — either algorithm alone is never sufficient.
//! Key exchange is hybrid too (see `secure.rs`): X25519 ‖ ML-KEM-768.
//!
//! Trust model: SSH-style TOFU (trust on first use) with an optional
//! strict mode where only explicitly pinned peers may connect. Peer
//! records are persisted and content-verifiable (ed25519 key is the id).
//!
//! # Key format freeze (ADR-0007)
//!
//! The on-disk identity format is **v1**, frozen:
//!
//! ```json
//! {"format":"sieveplate-identity","version":1,"host":"…",
//!  "generation":0,"ed_seed_hex":"…","pq_seed_hex":"…"}
//! ```
//!
//! Field names, order and semantics are contractual (a golden-file test
//! pins them). Rotation replaces the key *pair* under the same host name
//! by a **RotationStatement** signed with BOTH algorithms on BOTH sides
//! (old and new — four signatures, no downgrade in either direction),
//! and a monotonic `generation` counter that rejects replays.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::FabricError;

/// The frozen identity format tag (ADR-0007).
pub const IDENTITY_FORMAT: &str = "sieveplate-identity";
/// The frozen identity format version (ADR-0007).
pub const IDENTITY_VERSION: u32 = 1;
/// Domain separator for rotation-statement signatures.
pub const ROTATION_CONTEXT: &[u8] = b"sieveplate-rotation-v1";

/// A host's long-term signing material. Seeds are persisted; everything
/// else is derived on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    /// Frozen-format tag. Defaults for files written before the freeze.
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_version")]
    pub version: u32,
    pub host: String,
    /// Key generation: bumps on every rotation. Pin verification uses it
    /// to reject stale rotation statements.
    #[serde(default)]
    pub generation: u32,
    /// Ed25519 seed (32 bytes, hex).
    pub ed_seed_hex: String,
    /// ML-DSA-65 seed (32 bytes, hex).
    pub pq_seed_hex: String,
}

fn default_format() -> String {
    IDENTITY_FORMAT.to_string()
}

fn default_version() -> u32 {
    IDENTITY_VERSION
}

impl HostIdentity {
    /// Generate a fresh identity for `host` (generation 0).
    pub fn generate(host: impl Into<String>) -> Result<Self, FabricError> {
        let mut ed_seed = [0u8; 32];
        let mut pq_seed = [0u8; 32];
        getrandom_fill(&mut ed_seed)?;
        getrandom_fill(&mut pq_seed)?;
        Ok(HostIdentity {
            format: IDENTITY_FORMAT.to_string(),
            version: IDENTITY_VERSION,
            host: host.into(),
            generation: 0,
            ed_seed_hex: hex::encode(ed_seed),
            pq_seed_hex: hex::encode(pq_seed),
        })
    }

    /// Load from `dir/identity.json`, creating it if absent.
    pub fn load_or_create(dir: &std::path::Path, host: &str) -> Result<Self, FabricError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("identity.json");
        if path.exists() {
            let id: HostIdentity = serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|e| FabricError::Codec(e.to_string()))?;
            Ok(id)
        } else {
            let id = HostIdentity::generate(host)?;
            let bytes =
                serde_json::to_vec_pretty(&id).map_err(|e| FabricError::Codec(e.to_string()))?;
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, bytes)?;
            std::fs::rename(&tmp, &path)?;
            Ok(id)
        }
    }

    pub fn ed_signing(&self) -> SigningKey {
        let seed: [u8; 32] = hex::decode(&self.ed_seed_hex)
            .expect("ed seed hex")
            .try_into()
            .expect("ed seed len");
        SigningKey::from_bytes(&seed)
    }

    pub fn ed_public_bytes(&self) -> [u8; 32] {
        self.ed_signing().verifying_key().to_bytes()
    }

    fn pq_seed(&self) -> [u8; 32] {
        hex::decode(&self.pq_seed_hex)
            .expect("pq seed hex")
            .try_into()
            .expect("pq seed len")
    }

    pub fn pq_signing(&self) -> ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65> {
        ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa65>::from_seed(&self.pq_seed().into())
    }

    /// The encoded ML-DSA verification key peers should pin.
    pub fn pq_vk_bytes(&self) -> Vec<u8> {
        self.pq_signing().verifying_key().encode().to_vec()
    }

    /// Rotate to a fresh key pair (generation + 1): generate, persist the
    /// new identity atomically, and produce the **RotationStatement**
    /// signed by BOTH the old and new keys with BOTH algorithms (ADR-0007).
    /// The statement is also persisted (`rotation-<gen>.json`) so it can
    /// be replayed to any peer that was offline during the rotation.
    pub fn rotate(&self, dir: &Path) -> Result<(HostIdentity, RotationStatement), FabricError> {
        std::fs::create_dir_all(dir)?;
        let mut next = HostIdentity::generate(&self.host)?;
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| FabricError::Crypto("generation exhausted".into()))?;

        // Persist the new identity atomically BEFORE revealing anything.
        let bytes =
            serde_json::to_vec_pretty(&next).map_err(|e| FabricError::Codec(e.to_string()))?;
        let tmp = dir.join("identity.json.tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, dir.join("identity.json"))?;

        let core = RotationCore {
            host: self.host.clone(),
            old_generation: self.generation,
            new_generation: next.generation,
            old_ed_public: self.ed_public_bytes(),
            old_pq_vk: self.pq_vk_bytes(),
            new_ed_public: next.ed_public_bytes(),
            new_pq_vk: next.pq_vk_bytes(),
            rotated_at_ms: now_ms() as u64,
        };
        let msg = rotation_msg(&core);
        let stmt = RotationStatement {
            core: core.clone(),
            sig_old_ed: self.ed_signing().sign(&msg).to_bytes().to_vec(),
            sig_old_pq: self
                .pq_signing()
                .sign_deterministic(&msg, b"sieveplate-sieve1")
                .expect("ML-DSA sign")
                .encode()
                .to_vec(),
            sig_new_ed: next.ed_signing().sign(&msg).to_bytes().to_vec(),
            sig_new_pq: next
                .pq_signing()
                .sign_deterministic(&msg, b"sieveplate-sieve1")
                .expect("ML-DSA sign")
                .encode()
                .to_vec(),
        };
        let stmt_path = dir.join(format!("rotation-{}.json", next.generation));
        let stmt_bytes =
            serde_json::to_vec_pretty(&stmt).map_err(|e| FabricError::Codec(e.to_string()))?;
        std::fs::write(stmt_path, stmt_bytes)?;
        Ok((next, stmt))
    }

    /// Load the most recent rotation statement persisted in `dir`, if any
    /// (the statement a host attaches to handshakes after rotating).
    pub fn latest_rotation(dir: &Path) -> Option<RotationStatement> {
        let entries = std::fs::read_dir(dir).ok()?;
        let best = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.strip_prefix("rotation-")
                    .and_then(|s| s.strip_suffix(".json"))
                    .and_then(|s| s.parse::<u32>().ok())
                    .map(|gen| (gen, e.path()))
            })
            .max_by_key(|(gen, _)| *gen)?;
        let bytes = std::fs::read(best.1).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Public material a peer needs to authenticate this host.
    pub fn public(&self) -> HostPublic {
        HostPublic {
            host: self.host.clone(),
            ed_public: self.ed_public_bytes(),
            pq_vk: self.pq_vk_bytes(),
        }
    }
}

/// Everything a peer needs in order to verify this host's signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPublic {
    pub host: String,
    pub ed_public: [u8; 32],
    pub pq_vk: Vec<u8>,
}

impl HostPublic {
    /// Hybrid verification: BOTH signatures must verify (no downgrade).
    pub fn verify(&self, msg: &[u8], ed_sig: &[u8], pq_sig: &[u8]) -> Result<(), FabricError> {
        let ed_vk = VerifyingKey::from_bytes(&self.ed_public)
            .map_err(|e| FabricError::Crypto(format!("bad ed25519 key: {e}")))?;
        let ed_sig = EdSignature::from_slice(ed_sig)
            .map_err(|e| FabricError::Crypto(format!("bad ed25519 sig: {e}")))?;
        ed_vk
            .verify(msg, &ed_sig)
            .map_err(|e| FabricError::Crypto(format!("ed25519 verify failed: {e}")))?;
        // Decode the encoded ML-DSA verification key and signature.
        let vk_arr: &ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa65> = self
            .pq_vk
            .as_slice()
            .try_into()
            .map_err(|_| FabricError::Crypto("bad ML-DSA key length".into()))?;
        let pq_vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(vk_arr);
        let sig_arr: &ml_dsa::EncodedSignature<ml_dsa::MlDsa65> = pq_sig
            .try_into()
            .map_err(|_| FabricError::Crypto("bad ML-DSA sig length".into()))?;
        let pq_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(sig_arr)
            .ok_or_else(|| FabricError::Crypto("undecodable ML-DSA signature".into()))?;
        if !pq_vk.verify_with_context(msg, b"sieveplate-sieve1", &pq_sig) {
            return Err(FabricError::Crypto("ML-DSA verify failed".into()));
        }
        Ok(())
    }
}

/// SHA-256 of the identity public material — used as a compact fingerprint.
pub fn fingerprint(p: &HostPublic) -> String {
    let mut h = Sha256::new();
    h.update(p.ed_public);
    h.update(&p.pq_vk);
    hex::encode(h.finalize())[..16].to_string()
}

/// The signed payload of a rotation: everything except the signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationCore {
    pub host: String,
    pub old_generation: u32,
    pub new_generation: u32,
    pub old_ed_public: [u8; 32],
    pub old_pq_vk: Vec<u8>,
    pub new_ed_public: [u8; 32],
    pub new_pq_vk: Vec<u8>,
    pub rotated_at_ms: u64,
}

/// Bytes signed by all four rotation signatures.
fn rotation_msg(core: &RotationCore) -> Vec<u8> {
    let mut msg = ROTATION_CONTEXT.to_vec();
    msg.extend_from_slice(&bincode::serialize(core).unwrap_or_default());
    msg
}

/// A key rotation statement (ADR-0007): a host's declaration that its
/// identity moves from the old key pair (generation N) to the new pair
/// (generation N+1). Signed with BOTH algorithms under BOTH keys — an
/// attacker needs Ed25519 AND ML-DSA for the old keys (to steal the
/// rotation) AND for the new keys (to forge the destination), so a
/// partial quantum/classical break alone is not enough.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationStatement {
    pub core: RotationCore,
    pub sig_old_ed: Vec<u8>,
    pub sig_old_pq: Vec<u8>,
    pub sig_new_ed: Vec<u8>,
    pub sig_new_pq: Vec<u8>,
}

impl RotationStatement {
    /// Full cryptographic check: old signatures verify under the OLD keys,
    /// new signatures under the NEW keys, generations advance by exactly
    /// one, and both key sets belong to the statement's host name.
    pub fn verify(&self) -> Result<(), FabricError> {
        let c = &self.core;
        if c.new_generation
            != c.old_generation
                .checked_add(1)
                .ok_or_else(|| FabricError::Crypto("rotation generation overflow".into()))?
        {
            return Err(FabricError::Crypto(
                "rotation must advance generation by exactly 1".into(),
            ));
        }
        let msg = rotation_msg(&self.core);
        let old = HostPublic {
            host: c.host.clone(),
            ed_public: c.old_ed_public,
            pq_vk: c.old_pq_vk.clone(),
        };
        let new = HostPublic {
            host: c.host.clone(),
            ed_public: c.new_ed_public,
            pq_vk: c.new_pq_vk.clone(),
        };
        old.verify(&msg, &self.sig_old_ed, &self.sig_old_pq)?;
        new.verify(&msg, &self.sig_new_ed, &self.sig_new_pq)?;
        Ok(())
    }
}

/// A pinned/observed peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub ed_public: [u8; 32],
    pub pq_vk: Vec<u8>,
    pub fingerprint: String,
    pub first_seen_ms: u128,
    pub last_addr: String,
    /// Key generation at pin time (rotation, ADR-0007).
    #[serde(default)]
    pub generation: u32,
}

/// SSH-style known-peers store: TOFU by default, strict pinning optional.
#[derive(Debug)]
pub struct KnownPeers {
    path: PathBuf,
    inner: std::sync::Mutex<BTreeMap<String, PeerRecord>>,
    /// When true, hosts not explicitly pinned are rejected outright.
    pub deny_unknown: bool,
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

impl KnownPeers {
    /// Open (or create) the store at `path` (typically
    /// `<runtime>/fabric/known_peers.json`).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, FabricError> {
        let path = path.into();
        let inner = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|e| FabricError::Codec(e.to_string()))?
        } else {
            BTreeMap::new()
        };
        Ok(KnownPeers {
            path,
            inner: std::sync::Mutex::new(inner),
            deny_unknown: false,
        })
    }

    /// Verify a peer's signatures, applying the trust model. On success the
    /// peer is recorded (TOFU) with `addr`. A key change is a LOUD failure
    /// unless the peer presents a valid [`RotationStatement`] bridging the
    /// pinned keys to the presented ones (ADR-0007).
    pub fn verify_and_pin(
        &self,
        pubk: &HostPublic,
        transcript_msg: &[u8],
        ed_sig: &[u8],
        pq_sig: &[u8],
        addr: &str,
        rotation: Option<&RotationStatement>,
    ) -> Result<(), FabricError> {
        let fp = fingerprint(pubk);
        let mut updated: Option<PeerRecord> = None;
        {
            let map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            match map.get(&pubk.host) {
                Some(rec) => {
                    if rec.ed_public != pubk.ed_public || rec.pq_vk != pubk.pq_vk {
                        // Key change. Only a valid rotation bridging the
                        // pinned keys to these keys may replace the pin.
                        let stmt = rotation.ok_or_else(|| FabricError::PeerKeyChanged {
                            host: pubk.host.clone(),
                            expected: rec.fingerprint.clone(),
                            got: fp.clone(),
                        })?;
                        if stmt.core.host != pubk.host
                            || stmt.core.old_ed_public != rec.ed_public
                            || stmt.core.old_pq_vk != rec.pq_vk
                            || stmt.core.new_ed_public != pubk.ed_public
                            || stmt.core.new_pq_vk != pubk.pq_vk
                            || stmt.core.new_generation != rec.generation + 1
                        {
                            return Err(FabricError::PeerKeyChanged {
                                host: pubk.host.clone(),
                                expected: rec.fingerprint.clone(),
                                got: fp,
                            });
                        }
                        stmt.verify()?;
                        updated = Some(PeerRecord {
                            ed_public: pubk.ed_public,
                            pq_vk: pubk.pq_vk.clone(),
                            fingerprint: fp.clone(),
                            first_seen_ms: rec.first_seen_ms,
                            last_addr: rec.last_addr.clone(),
                            generation: stmt.core.new_generation,
                        });
                    }
                }
                None => {
                    if self.deny_unknown {
                        return Err(FabricError::UnknownPeer {
                            host: pubk.host.clone(),
                            fingerprint: fp,
                        });
                    }
                }
            }
        }
        // Signature verification happens outside the lock.
        pubk.verify(transcript_msg, ed_sig, pq_sig)?;
        {
            let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            match updated {
                Some(rec) => {
                    // Rotation already cryptographically checked above.
                    map.insert(pubk.host.clone(), rec);
                }
                None => {
                    map.entry(pubk.host.clone())
                        .or_insert_with(|| PeerRecord {
                            ed_public: pubk.ed_public,
                            pq_vk: pubk.pq_vk.clone(),
                            fingerprint: fp,
                            first_seen_ms: now_ms(),
                            last_addr: addr.to_string(),
                            generation: 0,
                        })
                        .last_addr = addr.to_string();
                }
            }
        }
        self.persist()
    }

    /// Explicitly pin a peer ahead of first contact (strict deployments).
    pub fn pin(&self, pubk: &HostPublic) -> Result<(), FabricError> {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(
            pubk.host.clone(),
            PeerRecord {
                ed_public: pubk.ed_public,
                pq_vk: pubk.pq_vk.clone(),
                fingerprint: fingerprint(pubk),
                first_seen_ms: now_ms(),
                last_addr: String::new(),
                generation: 0,
            },
        );
        drop(map);
        self.persist()
    }

    pub fn get(&self, host: &str) -> Option<PeerRecord> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(host)
            .cloned()
    }

    pub fn list(&self) -> Vec<(String, PeerRecord)> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn persist(&self) -> Result<(), FabricError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes =
            serde_json::to_vec_pretty(&*self.inner.lock().unwrap_or_else(|p| p.into_inner()))
                .map_err(|e| FabricError::Codec(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), FabricError> {
    getrandom::fill(buf).map_err(|e| FabricError::Crypto(format!("entropy unavailable: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("spx-id-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let id = HostIdentity::generate("alpha").unwrap();
        let pubk = id.public();
        let msg = b"transcript-bytes";
        let ed_sig = id.ed_signing().sign(msg).to_bytes();
        let pq_sig = id
            .pq_signing()
            .sign_deterministic(msg, b"sieveplate-sieve1")
            .unwrap()
            .encode()
            .to_vec();
        pubk.verify(msg, &ed_sig, &pq_sig).unwrap();
        // tamper → both fail
        let mut bad = ed_sig;
        bad[0] ^= 1;
        assert!(pubk.verify(msg, &bad, &pq_sig).is_err());
        assert!(pubk
            .verify(msg, &ed_sig, &pq_sig[..pq_sig.len() - 2])
            .is_err());
    }

    #[test]
    fn tofu_pin_and_key_change_detection() {
        let dir = tmp_path("tofu");
        let peers = KnownPeers::open(dir.join("peers.json")).unwrap();
        let a = HostIdentity::generate("alpha").unwrap();
        let msg = b"t";
        let sig = |id: &HostIdentity| {
            (
                id.ed_signing().sign(msg).to_bytes().to_vec(),
                id.pq_signing()
                    .sign_deterministic(msg, b"sieveplate-sieve1")
                    .unwrap()
                    .encode()
                    .to_vec(),
            )
        };
        let (e, p) = sig(&a);
        peers
            .verify_and_pin(&a.public(), msg, &e, &p, "10.0.0.1:1", None)
            .unwrap();
        assert!(peers.get("alpha").is_some());
        // same key: ok
        peers
            .verify_and_pin(&a.public(), msg, &e, &p, "10.0.0.1:1", None)
            .unwrap();
        // key change: loud failure
        let impostor = HostIdentity::generate("alpha").unwrap();
        let (e2, p2) = sig(&impostor);
        let err = peers
            .verify_and_pin(&impostor.public(), msg, &e2, &p2, "10.0.0.2:1", None)
            .unwrap_err();
        assert!(matches!(err, FabricError::PeerKeyChanged { .. }));
        // strict mode rejects unknown hosts
        let mut peers2 = KnownPeers::open(dir.join("peers2.json")).unwrap();
        peers2.deny_unknown = true;
        let b = HostIdentity::generate("beta").unwrap();
        let (eb, pb) = sig(&b);
        assert!(matches!(
            peers2.verify_and_pin(&b.public(), msg, &eb, &pb, "x", None),
            Err(FabricError::UnknownPeer { .. })
        ));
        // pinning first makes it work
        peers2.pin(&b.public()).unwrap();
        peers2
            .verify_and_pin(&b.public(), msg, &eb, &pb, "x", None)
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_format_is_frozen_v1() {
        // ADR-0007: the serialized identity format is contractual. This
        // golden string pins field names and their order; changing either
        // is a breaking format change and must bump IDENTITY_VERSION.
        let id = HostIdentity::generate("golden").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let expected_order = [
            "\"format\":\"sieveplate-identity\"",
            "\"version\":1",
            "\"host\":\"golden\"",
            "\"generation\":0",
            "\"ed_seed_hex\":",
            "\"pq_seed_hex\":",
        ];
        let mut pos = 0;
        for needle in expected_order {
            let at = json.find(needle).unwrap_or_else(|| {
                panic!("frozen field {needle} missing or out of order in {json}")
            });
            assert!(at >= pos, "field {needle} out of order in {json}");
            pos = at;
        }
        // Round-trip stability: parse(serialize(x)) == x.
        let back: HostIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.format, "sieveplate-identity");
        assert_eq!(back.version, 1);
        assert_eq!(back.ed_seed_hex, id.ed_seed_hex);
        assert_eq!(back.pq_seed_hex, id.pq_seed_hex);
        // Legacy files (pre-freeze, no format fields) still load.
        let legacy = format!(
            "{{\"host\":\"old\",\"ed_seed_hex\":\"{}\",\"pq_seed_hex\":\"{}\"}}",
            "a".repeat(64),
            "b".repeat(64)
        );
        let old: HostIdentity = serde_json::from_str(&legacy).unwrap();
        assert_eq!(old.format, "sieveplate-identity"); // defaulted
        assert_eq!(old.version, 1);
        assert_eq!(old.generation, 0);
    }

    #[test]
    fn rotation_statement_lifecycle() {
        let dir = tmp_path("rotate");
        let a = HostIdentity::load_or_create(&dir, "alpha").unwrap();
        assert_eq!(a.generation, 0);

        // Rotate: new identity persisted + statement signed by both gens.
        let (a2, stmt) = a.rotate(&dir).unwrap();
        assert_eq!(a2.generation, 1);
        assert_ne!(a2.ed_seed_hex, a.ed_seed_hex);
        assert!(stmt.verify().is_ok());
        // Statement persisted for offline peers.
        assert_eq!(HostIdentity::latest_rotation(&dir).unwrap().core, stmt.core);
        // Reloaded identity is the new one.
        let reloaded = HostIdentity::load_or_create(&dir, "alpha").unwrap();
        assert_eq!(reloaded.ed_seed_hex, a2.ed_seed_hex);

        // A peer that pinned gen 0 accepts the rotation and re-pins.
        let peers = KnownPeers::open(dir.join("peers.json")).unwrap();
        let msg = b"t";
        let sig_of = |id: &HostIdentity| {
            (
                id.ed_signing().sign(msg).to_bytes().to_vec(),
                id.pq_signing()
                    .sign_deterministic(msg, b"sieveplate-sieve1")
                    .unwrap()
                    .encode()
                    .to_vec(),
            )
        };
        let (e0, p0) = sig_of(&a);
        peers
            .verify_and_pin(&a.public(), msg, &e0, &p0, "addr", None)
            .unwrap();
        let (e1, p1) = sig_of(&a2);
        peers
            .verify_and_pin(&a2.public(), msg, &e1, &p1, "addr", Some(&stmt))
            .unwrap();
        let rec = peers.get("alpha").unwrap();
        assert_eq!(rec.generation, 1);
        assert_eq!(rec.ed_public, a2.public().ed_public);
        // And the new keys now verify normally.
        peers
            .verify_and_pin(&a2.public(), msg, &e1, &p1, "addr", None)
            .unwrap();

        let a3 = HostIdentity::load_or_create(&dir, "alpha").unwrap(); // gen 1 keys
        let (e3, p3) = sig_of(&a3);
        // Downgrade attack: present the OLD keys with the (still validly
        // signed) old statement — the pin is at gen 1, the statement
        // bridges 0 → 1, so it cannot bridge to the old keys again.
        assert!(peers
            .verify_and_pin(&a.public(), msg, &e0, &p0, "addr", Some(&stmt))
            .is_err());
        // Presenting the CURRENT keys + stale statement is harmless: keys
        // already match the pin, no rotation processing occurs.
        peers
            .verify_and_pin(&a3.public(), msg, &e3, &p3, "addr", Some(&stmt))
            .unwrap();

        // Tampered statement: old sig broken.
        let (a2b, mut bad) = a.rotate(&dir.join("rotate2")).unwrap();
        bad.sig_old_ed[0] ^= 1;
        assert!(bad.verify().is_err());
        let _ = a2b;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_persists_and_matches() {
        let dir = tmp_path("persist");
        let id1 = HostIdentity::load_or_create(&dir, "alpha").unwrap();
        let id2 = HostIdentity::load_or_create(&dir, "alpha").unwrap();
        assert_eq!(id1.ed_seed_hex, id2.ed_seed_hex);
        assert_eq!(id1.public().ed_public, id2.public().ed_public);
        assert_eq!(id1.public().pq_vk, id2.public().pq_vk);
        assert_eq!(fingerprint(&id1.public()), fingerprint(&id2.public()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
