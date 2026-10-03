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

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::{Signature as EdSignature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::FabricError;

/// A host's long-term signing material. Seeds are persisted; everything
/// else is derived on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub host: String,
    /// Ed25519 seed (32 bytes, hex).
    pub ed_seed_hex: String,
    /// ML-DSA-65 seed (32 bytes, hex).
    pub pq_seed_hex: String,
}

impl HostIdentity {
    /// Generate a fresh identity for `host`.
    pub fn generate(host: impl Into<String>) -> Result<Self, FabricError> {
        let mut ed_seed = [0u8; 32];
        let mut pq_seed = [0u8; 32];
        getrandom_fill(&mut ed_seed)?;
        getrandom_fill(&mut pq_seed)?;
        Ok(HostIdentity {
            host: host.into(),
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

/// A pinned/observed peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub ed_public: [u8; 32],
    pub pq_vk: Vec<u8>,
    pub fingerprint: String,
    pub first_seen_ms: u128,
    pub last_addr: String,
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
    /// peer is recorded (TOFU) with `addr`.
    pub fn verify_and_pin(
        &self,
        pubk: &HostPublic,
        transcript_msg: &[u8],
        ed_sig: &[u8],
        pq_sig: &[u8],
        addr: &str,
    ) -> Result<(), FabricError> {
        let fp = fingerprint(pubk);
        let map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match map.get(&pubk.host) {
            Some(rec) => {
                // Pinned: keys must match exactly (key change = loud failure).
                if rec.ed_public != pubk.ed_public || rec.pq_vk != pubk.pq_vk {
                    return Err(FabricError::PeerKeyChanged {
                        host: pubk.host.clone(),
                        expected: rec.fingerprint.clone(),
                        got: fp,
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
        drop(map);
        // Signature verification happens outside the lock.
        pubk.verify(transcript_msg, ed_sig, pq_sig)?;
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(pubk.host.clone())
            .or_insert_with(|| PeerRecord {
                ed_public: pubk.ed_public,
                pq_vk: pubk.pq_vk.clone(),
                fingerprint: fp,
                first_seen_ms: now_ms(),
                last_addr: addr.to_string(),
            })
            .last_addr = addr.to_string();
        drop(map);
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
    use ed25519_dalek::Signer as _;

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
            .verify_and_pin(&a.public(), msg, &e, &p, "10.0.0.1:1")
            .unwrap();
        assert!(peers.get("alpha").is_some());
        // same key: ok
        peers
            .verify_and_pin(&a.public(), msg, &e, &p, "10.0.0.1:1")
            .unwrap();
        // key change: loud failure
        let impostor = HostIdentity::generate("alpha").unwrap();
        let (e2, p2) = sig(&impostor);
        let err = peers
            .verify_and_pin(&impostor.public(), msg, &e2, &p2, "10.0.0.2:1")
            .unwrap_err();
        assert!(matches!(err, FabricError::PeerKeyChanged { .. }));
        // strict mode rejects unknown hosts
        let mut peers2 = KnownPeers::open(dir.join("peers2.json")).unwrap();
        peers2.deny_unknown = true;
        let b = HostIdentity::generate("beta").unwrap();
        let (eb, pb) = sig(&b);
        assert!(matches!(
            peers2.verify_and_pin(&b.public(), msg, &eb, &pb, "x"),
            Err(FabricError::UnknownPeer { .. })
        ));
        // pinning first makes it work
        peers2.pin(&b.public()).unwrap();
        peers2
            .verify_and_pin(&b.public(), msg, &eb, &pb, "x")
            .unwrap();
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
