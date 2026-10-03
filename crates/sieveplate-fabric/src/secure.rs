//! SIEVE1 — the secure host-to-host link protocol.
//!
//! Design goals (ADR-0004):
//! 1. **Identity verification**: both peers sign the handshake transcript
//!    with a hybrid signature *catena* — Ed25519 **and** ML-DSA-65 (FIPS
//!    204). A peer is authenticated only when BOTH verify, so a future
//!    quantum attacker cannot forge identity by breaking the classical
//!    key alone. Trust: TOFU pinning or strict pinning (`KnownPeers`).
//! 2. **Harvest-now-decrypt-later resistance**: session keys come from a
//!    hybrid KEM — X25519 ‖ ML-KEM-768 (FIPS 203) — joined by HKDF-SHA256.
//!    Neither a broken ECDLP nor a broken lattice alone reduces the joint
//!    secret.
//! 3. **Authenticated encryption** on every frame (ChaCha20-Poly1305) with
//!    per-direction monotonic sequence numbers bound into the nonce:
//!    replay and reordering are rejected loudly.
//! 4. **Session binding**: the handshake transcript hash is the AEAD
//!    associated data — frames cannot be replayed across connections.
//!
//! Handshake transcript (all frames serialized canonically; signature
//! frames are absorbed with EMPTY signature fields, then signed):
//!
//! ```text
//! I -> R : ClientHello { eph_x25519, ek_mlkem768 }
//! R -> I : ServerHello { id_R, eph_x25519, ct_mlkem768, sig_ed, sig_pq }   (sig over th1)
//! I -> R : ClientAuth   { id_I, sig_ed, sig_pq }                            (sig over th2)
//! R -> I : Ready
//! th1 = H(ch ‖ sh)          — binds key exchange
//! th2 = H(ch ‖ sh ‖ ca)     — binds client auth
//! ikm = x25519(ephI, ephR) ‖ mlkem_decap(ct, dkI)
//! okm = HKDF-SHA256(ikm, salt=th1, info="sieve1-hybrid")
//! ```
//!
//! This is deliberately small enough to audit line by line. It is NOT a
//! general TLS replacement; for hostile public networks prefer rustls.
//! SIEVE1 targets the cell-grid fabric: long-lived peers, pinned identities.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::Signer as _;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::FabricError;
use crate::identity::{HostIdentity, HostPublic, KnownPeers};
use ml_kem::KeyExport as _;

pub const PROTOCOL: &str = "sieve1-hybrid";
const OKM_LEN: usize = 32 + 32 + 12 + 12;
const MAX_HS_FRAME: usize = 1 << 20; // 1 MiB
/// ChaCha20-Poly1305 tag size.
pub const TAG: usize = 16;

// ---------------------------------------------------------------------------
// Directional cipher halves
// ---------------------------------------------------------------------------

struct Direction {
    cipher: ChaCha20Poly1305,
    nonce_base: [u8; 12],
    seq: u64,
    /// Session binding: transcript hash is AEAD associated data.
    aad: [u8; 32],
}

impl Direction {
    fn new(key: [u8; 32], nonce_base: [u8; 12], aad: [u8; 32]) -> Self {
        Direction {
            cipher: ChaCha20Poly1305::new(&Key::from(key)),
            nonce_base,
            seq: 0,
            aad,
        }
    }

    fn nonce_for(&self, seq: u64) -> Nonce {
        // 64-bit sequence zero-extended into the low 8 of 12 nonce bytes,
        // then XORed with the per-direction base.
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&seq.to_le_bytes());
        for (byte, base) in n.iter_mut().zip(self.nonce_base.iter()) {
            *byte ^= base;
        }
        Nonce::from(n)
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, FabricError> {
        let seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| FabricError::Crypto("sequence space exhausted".into()))?;
        self.seq = seq;
        // The sequence number is bound into the AEAD: a frame sealed for
        // seq N can never authenticate at any other position.
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(&self.aad);
        aad.extend_from_slice(&seq.to_le_bytes());
        self.cipher
            .encrypt(
                &self.nonce_for(seq),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| FabricError::Crypto("seal failed".into()))
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, FabricError> {
        // `seq` counts frames sent (1-based after seal's pre-increment);
        // the next frame we accept must carry exactly self.seq + 1.
        let expected = self.seq + 1;
        let mut aad = Vec::with_capacity(40);
        aad.extend_from_slice(&self.aad);
        aad.extend_from_slice(&expected.to_le_bytes());
        let pt = self
            .cipher
            .decrypt(
                &self.nonce_for(expected),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                // Most common cause: replay/reorder (tag is sequence-bound).
                FabricError::Replay {
                    expected,
                    frame_len: ciphertext.len(),
                }
            })?;
        self.seq += 1;
        Ok(pt)
    }
}

/// Sending half of an established secure channel (owned by the writer task).
pub struct SecureTx(Direction);

/// Receiving half of an established secure channel (owned by the reader task).
pub struct SecureRx(Direction);

impl SecureTx {
    /// Seal a frame payload (ciphertext includes the auth tag).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, FabricError> {
        self.0.seal(plaintext)
    }
}

impl SecureRx {
    /// Open a frame payload; rejects replay/reorder/tamper.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, FabricError> {
        self.0.open(ciphertext)
    }
}

/// Established channel: split into halves for the reader/writer tasks.
pub struct SecureChannel {
    pub tx: SecureTx,
    pub rx: SecureRx,
    pub peer: HostPublic,
}

// ---------------------------------------------------------------------------
// Handshake wire frames (length-prefixed bincode, NOT encrypted — like TLS)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
enum HsFrame {
    ClientHello {
        protocol: String,
        eph_x: [u8; 32],
        pq_ek: Vec<u8>,
    },
    ServerHello {
        public: HostPublic,
        eph_x: [u8; 32],
        pq_ct: Vec<u8>,
        ed_sig: Vec<u8>,
        pq_sig: Vec<u8>,
    },
    ClientAuth {
        public: HostPublic,
        ed_sig: Vec<u8>,
        pq_sig: Vec<u8>,
    },
    Ready,
    Abort {
        why: String,
    },
}

async fn write_hs<W: AsyncWriteExt + Unpin>(w: &mut W, frame: &HsFrame) -> Result<(), FabricError> {
    let body = bincode::serialize(frame).map_err(|e| FabricError::Codec(e.to_string()))?;
    if body.len() > MAX_HS_FRAME {
        return Err(FabricError::Codec("handshake frame too large".into()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

async fn read_hs<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<HsFrame, FabricError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HS_FRAME {
        return Err(FabricError::Codec("handshake frame too large".into()));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    bincode::deserialize(&body).map_err(|e| FabricError::Codec(e.to_string()))
}

fn hs_bytes(frame: &HsFrame) -> Vec<u8> {
    bincode::serialize(frame).unwrap_or_default()
}

fn sign_both(id: &HostIdentity, label: &str, transcript_hash: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(label.as_bytes());
    msg.extend_from_slice(transcript_hash);
    let ed_sig = id.ed_signing().sign(&msg).to_bytes().to_vec();
    let pq_sig = id
        .pq_signing()
        .sign_deterministic(&msg, b"sieveplate-sieve1")
        .expect("ML-DSA sign")
        .encode()
        .to_vec();
    (ed_sig, pq_sig)
}

#[derive(Clone)]
struct Transcript(Sha256);

impl Transcript {
    fn absorb(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    fn hash(&self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

/// Directional key material: two 32-byte keys + two 12-byte nonce bases.
pub type DirectionalKeys = ([u8; 32], [u8; 12], [u8; 32], [u8; 12]);

/// Derive directional keys. Returns (k_c2s, n_c2s, k_s2c, n_s2c).
fn derive_channel(ikm: &[u8], transcript_hash: &[u8; 32]) -> Result<DirectionalKeys, FabricError> {
    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), ikm);
    let mut okm = [0u8; OKM_LEN];
    hk.expand(PROTOCOL.as_bytes(), &mut okm)
        .map_err(|_| FabricError::Crypto("hkdf expand failed".into()))?;
    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    let mut n_c2s = [0u8; 12];
    let mut n_s2c = [0u8; 12];
    k_c2s.copy_from_slice(&okm[0..32]);
    k_s2c.copy_from_slice(&okm[32..64]);
    n_c2s.copy_from_slice(&okm[64..76]);
    n_s2c.copy_from_slice(&okm[76..88]);
    Ok((k_c2s, n_c2s, k_s2c, n_s2c))
}

fn entropy(buf: &mut [u8]) -> Result<(), FabricError> {
    getrandom::fill(buf).map_err(|e| FabricError::Crypto(format!("entropy unavailable: {e}")))
}

/// Ephemeral ML-KEM decapsulation key from 32 bytes of entropy.
fn ephemeral_kem_dk() -> Result<ml_kem::DecapsulationKey768, FabricError> {
    let mut seed = [0u8; 32];
    entropy(&mut seed)?;
    let mut kem_seed = [0u8; 64];
    let hk = Hkdf::<Sha256>::new(Some(b"sieveplate-kem-seed"), &seed);
    hk.expand(b"mlkem768-dk", &mut kem_seed)
        .map_err(|_| FabricError::Crypto("seed expand failed".into()))?;
    Ok(ml_kem::DecapsulationKey768::from_seed(kem_seed.into()))
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// Initiator (connecting host). `expected_host` pins the hostname we expect
/// — a responder announcing anything else fails immediately.
#[allow(clippy::too_many_lines)]
pub async fn initiator<R, W>(
    rd: &mut R,
    wr: &mut W,
    identity: &HostIdentity,
    peers: &KnownPeers,
    expected_host: &str,
) -> Result<SecureChannel, FabricError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // ---- 1. ClientHello ------------------------------------------------
    let eph = x25519_dalek::EphemeralSecret::random();
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    let dk = ephemeral_kem_dk()?;
    let ek = dk.encapsulation_key();
    let ch = HsFrame::ClientHello {
        protocol: PROTOCOL.to_string(),
        eph_x: *eph_pub.as_bytes(),
        pq_ek: ek.to_bytes().to_vec(),
    };
    let mut tr = Transcript(Sha256::new());
    tr.absorb(&hs_bytes(&ch));
    write_hs(wr, &ch).await?;

    // ---- 2. ServerHello: verify identity BEFORE using keys -------------
    let sh = match read_hs(rd).await? {
        s @ HsFrame::ServerHello { .. } => s,
        HsFrame::Abort { why } => return Err(FabricError::Handshake(why)),
        _ => return Err(FabricError::Handshake("expected ServerHello".into())),
    };
    let (public, sh_eph_x, pq_ct, ed_sig, pq_sig) = match &sh {
        HsFrame::ServerHello {
            public,
            eph_x,
            pq_ct,
            ed_sig,
            pq_sig,
        } => (
            public.clone(),
            *eph_x,
            pq_ct.clone(),
            ed_sig.clone(),
            pq_sig.clone(),
        ),
        _ => unreachable!(),
    };
    if public.host != expected_host {
        return Err(FabricError::Handshake(format!(
            "expected host '{expected_host}', got '{}'",
            public.host
        )));
    }
    // Transcript absorbs the canonical (empty-sig) form on BOTH sides.
    let sh_canon = hs_bytes(&HsFrame::ServerHello {
        public: public.clone(),
        eph_x: sh_eph_x,
        pq_ct: pq_ct.clone(),
        ed_sig: Vec::new(),
        pq_sig: Vec::new(),
    });
    tr.absorb(&sh_canon);
    let th1 = tr.hash();
    let mut auth_msg = b"server-auth".to_vec();
    auth_msg.extend_from_slice(&th1);
    peers.verify_and_pin(&public, &auth_msg, &ed_sig, &pq_sig, "")?;

    // ---- 3. Derive: hybrid X25519 + ML-KEM decapsulation ---------------
    let their_eph = x25519_dalek::PublicKey::from(sh_eph_x);
    let ss_x = eph.diffie_hellman(&their_eph);
    if !ss_x.was_contributory() {
        return Err(FabricError::Crypto(
            "degenerate X25519 shared secret".into(),
        ));
    }
    let ct_ref: &ml_kem::kem::Ciphertext<ml_kem::MlKem768> = pq_ct
        .as_slice()
        .try_into()
        .map_err(|_| FabricError::Crypto("bad ML-KEM ciphertext length".into()))?;
    let ss_pq = {
        use ml_kem::kem::Decapsulate;
        dk.decapsulate(ct_ref)
    };
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_x.as_bytes());
    ikm.extend_from_slice(ss_pq.as_slice());
    let (k_c2s, n_c2s, k_s2c, n_s2c) = derive_channel(&ikm, &th1)?;

    // ---- 4. ClientAuth --------------------------------------------------
    let ca_canon = hs_bytes(&HsFrame::ClientAuth {
        public: identity.public(),
        ed_sig: Vec::new(),
        pq_sig: Vec::new(),
    });
    tr.absorb(&ca_canon);
    let th2 = tr.hash();
    let (ed2, pq2) = sign_both(identity, "client-auth", &th2);
    write_hs(
        wr,
        &HsFrame::ClientAuth {
            public: identity.public(),
            ed_sig: ed2,
            pq_sig: pq2,
        },
    )
    .await?;
    match read_hs(rd).await? {
        HsFrame::Ready => {}
        HsFrame::Abort { why } => return Err(FabricError::Handshake(why)),
        _ => return Err(FabricError::Handshake("expected Ready".into())),
    }
    Ok(SecureChannel {
        tx: SecureTx(Direction::new(k_c2s, n_c2s, th1)),
        rx: SecureRx(Direction::new(k_s2c, n_s2c, th1)),
        peer: public,
    })
}

/// Responder (listening host).
pub async fn responder<R, W>(
    rd: &mut R,
    wr: &mut W,
    identity: &HostIdentity,
    peers: &KnownPeers,
) -> Result<SecureChannel, FabricError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // ---- 1. ClientHello --------------------------------------------------
    let ch = match read_hs(rd).await? {
        c @ HsFrame::ClientHello { .. } => c,
        HsFrame::Abort { why } => return Err(FabricError::Handshake(why)),
        _ => return Err(FabricError::Handshake("expected ClientHello".into())),
    };
    let (ch_eph_x, ch_ek) = match &ch {
        HsFrame::ClientHello {
            protocol,
            eph_x,
            pq_ek,
        } => {
            if protocol != PROTOCOL {
                let why = format!("protocol mismatch: {protocol}");
                let _ = write_hs(wr, &HsFrame::Abort { why: why.clone() }).await;
                return Err(FabricError::Handshake(why));
            }
            (*eph_x, pq_ek.clone())
        }
        _ => unreachable!(),
    };
    let mut tr = Transcript(Sha256::new());
    tr.absorb(&hs_bytes(&ch));

    // ---- 2. ServerHello: encapsulate to the client's KEM key + sign -----
    let eph = x25519_dalek::EphemeralSecret::random();
    let eph_pub = x25519_dalek::PublicKey::from(&eph);
    let ek_ref: &ml_kem::Key<ml_kem::EncapsulationKey768> = ch_ek
        .as_slice()
        .try_into()
        .map_err(|_| FabricError::Crypto("bad ML-KEM encapsulation key length".into()))?;
    let ek = ml_kem::EncapsulationKey768::new(ek_ref)
        .map_err(|_| FabricError::Crypto("invalid ML-KEM encapsulation key".into()))?;
    // Fresh random message per FIPS 203 encapsulation.
    let mut m = [0u8; 32];
    entropy(&mut m)?;
    let (pq_ct, ss_pq) = {
        let (ct, ss) = ek.encapsulate_deterministic(&m.into());
        (ct, ss)
    };
    let sh_canon = hs_bytes(&HsFrame::ServerHello {
        public: identity.public(),
        eph_x: *eph_pub.as_bytes(),
        pq_ct: pq_ct.as_slice().to_vec(),
        ed_sig: Vec::new(),
        pq_sig: Vec::new(),
    });
    tr.absorb(&sh_canon);
    let th1 = tr.hash();
    let (ed_sig, pq_sig) = sign_both(identity, "server-auth", &th1);
    write_hs(
        wr,
        &HsFrame::ServerHello {
            public: identity.public(),
            eph_x: *eph_pub.as_bytes(),
            pq_ct: pq_ct.as_slice().to_vec(),
            ed_sig: ed_sig.clone(),
            pq_sig: pq_sig.clone(),
        },
    )
    .await?;

    // ---- 3. ClientAuth: verify client identity --------------------------
    let ca = match read_hs(rd).await? {
        c @ HsFrame::ClientAuth { .. } => c,
        HsFrame::Abort { why } => return Err(FabricError::Handshake(why)),
        _ => return Err(FabricError::Handshake("expected ClientAuth".into())),
    };
    let (public, ed2, pq2) = match &ca {
        HsFrame::ClientAuth {
            public,
            ed_sig,
            pq_sig,
        } => (public.clone(), ed_sig.clone(), pq_sig.clone()),
        _ => unreachable!(),
    };
    tr.absorb(&hs_bytes(&HsFrame::ClientAuth {
        public: public.clone(),
        ed_sig: Vec::new(),
        pq_sig: Vec::new(),
    }));
    let th2 = tr.hash();
    let mut auth_msg = b"client-auth".to_vec();
    auth_msg.extend_from_slice(&th2);
    peers.verify_and_pin(&public, &auth_msg, &ed2, &pq2, "")?;
    write_hs(wr, &HsFrame::Ready).await?;

    // ---- 4. Derive --------------------------------------------------------
    let their_eph = x25519_dalek::PublicKey::from(ch_eph_x);
    let ss_x = eph.diffie_hellman(&their_eph);
    if !ss_x.was_contributory() {
        return Err(FabricError::Crypto(
            "degenerate X25519 shared secret".into(),
        ));
    }
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_x.as_bytes());
    ikm.extend_from_slice(ss_pq.as_slice());
    let (k_c2s, n_c2s, k_s2c, n_s2c) = derive_channel(&ikm, &th1)?;
    Ok(SecureChannel {
        // Responder sends on s2c, receives on c2s.
        tx: SecureTx(Direction::new(k_s2c, n_s2c, th1)),
        rx: SecureRx(Direction::new(k_c2s, n_c2s, th1)),
        peer: public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{HostIdentity, KnownPeers};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::duplex;

    static TAG_C: AtomicU64 = AtomicU64::new(0);

    fn fresh_peers() -> KnownPeers {
        let dir = std::env::temp_dir().join(format!(
            "spx-sec-{}-{}",
            std::process::id(),
            TAG_C.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        KnownPeers::open(dir.join("peers.json")).unwrap()
    }

    async fn run_pair(a: &HostIdentity, b: &HostIdentity) -> (SecureChannel, SecureChannel) {
        let peers_i = fresh_peers();
        let peers_r = fresh_peers();
        let (c2s, s2c) = duplex(1 << 20);
        let (mut i_rd, mut i_wr) = tokio::io::split(c2s);
        let (mut r_rd, mut r_wr) = tokio::io::split(s2c);
        let (i_ch, r_ch) = tokio::join!(
            initiator(&mut i_rd, &mut i_wr, a, &peers_i, "beta"),
            responder(&mut r_rd, &mut r_wr, b, &peers_r),
        );
        (i_ch.unwrap(), r_ch.unwrap())
    }

    #[tokio::test]
    async fn handshake_and_sealed_frames() {
        let a = HostIdentity::generate("alpha").unwrap();
        let b = HostIdentity::generate("beta").unwrap();
        let (mut ci, mut cr) = run_pair(&a, &b).await;
        assert_eq!(ci.peer.host, "beta");
        assert_eq!(cr.peer.host, "alpha");
        let sealed = ci.tx.seal(b"hello beta").unwrap();
        assert_eq!(cr.rx.open(&sealed).unwrap(), b"hello beta");
        let back = cr.tx.seal(b"hi alpha").unwrap();
        assert_eq!(ci.rx.open(&back).unwrap(), b"hi alpha");
        // Strict ordering on a reliable ordered stream: frames open in
        // sequence; a REPLAYED frame (already-consumed position) can never
        // re-open because its seq is bound into the AEAD.
        let s1 = ci.tx.seal(b"one").unwrap();
        let s2 = ci.tx.seal(b"two").unwrap();
        assert_eq!(cr.rx.open(&s1).unwrap(), b"one");
        assert_eq!(cr.rx.open(&s2).unwrap(), b"two");
        assert!(cr.rx.open(&s1).is_err(), "replay of an old frame must fail");
    }

    #[tokio::test]
    async fn tampered_frame_rejected() {
        let a = HostIdentity::generate("alpha").unwrap();
        let b = HostIdentity::generate("beta").unwrap();
        let (mut ci, mut cr) = run_pair(&a, &b).await;
        let mut sealed = ci.tx.seal(b"payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(cr.rx.open(&sealed).is_err());
    }

    #[tokio::test]
    async fn replayed_frame_rejected() {
        let a = HostIdentity::generate("alpha").unwrap();
        let b = HostIdentity::generate("beta").unwrap();
        let (mut ci, mut cr) = run_pair(&a, &b).await;
        let s1 = ci.tx.seal(b"first").unwrap();
        assert_eq!(cr.rx.open(&s1).unwrap(), b"first");
        // replay the same ciphertext: nonce has advanced → tag fails
        assert!(cr.rx.open(&s1).is_err());
    }

    #[tokio::test]
    async fn impostor_identity_rejected() {
        let a = HostIdentity::generate("alpha").unwrap();
        let b = HostIdentity::generate("beta").unwrap();
        let impostor = HostIdentity::generate("beta").unwrap();
        let peers_i = fresh_peers();
        let peers_r = fresh_peers();
        // Pin the REAL beta on the initiator side.
        let pin_msg = b"pin-probe";
        let ed = b.ed_signing().sign(pin_msg).to_bytes().to_vec();
        let pq = b
            .pq_signing()
            .sign_deterministic(pin_msg, b"sieveplate-sieve1")
            .unwrap()
            .encode()
            .to_vec();
        peers_i
            .verify_and_pin(&b.public(), pin_msg, &ed, &pq, "")
            .unwrap();

        let (c2s, s2c) = duplex(1 << 20);
        let (mut i_rd, mut i_wr) = tokio::io::split(c2s);
        let (mut r_rd, mut r_wr) = tokio::io::split(s2c);
        let d = std::time::Duration::from_secs(20);
        let (res_i, res_r) = tokio::join!(
            tokio::time::timeout(d, initiator(&mut i_rd, &mut i_wr, &a, &peers_i, "beta")),
            tokio::time::timeout(d, responder(&mut r_rd, &mut r_wr, &impostor, &peers_r)),
        );
        // The initiator MUST reject the impostor; the responder may run to
        // its timeout or error out when the initiator drops the link.
        assert!(
            res_i.is_err() || matches!(res_i, Ok(Err(_))),
            "impostor must not authenticate"
        );
        assert!(
            res_r.is_err() || matches!(res_r, Ok(Err(_))),
            "responder must not complete a session with a rejected peer"
        );
    }

    #[tokio::test]
    async fn unexpected_host_name_rejected() {
        let a = HostIdentity::generate("alpha").unwrap();
        let b = HostIdentity::generate("gamma").unwrap();
        let peers_i = fresh_peers();
        let peers_r = fresh_peers();
        let (c2s, s2c) = duplex(1 << 20);
        let (mut i_rd, mut i_wr) = tokio::io::split(c2s);
        let (mut r_rd, mut r_wr) = tokio::io::split(s2c);
        let d = std::time::Duration::from_secs(20);
        let (res_i, res_r) = tokio::join!(
            tokio::time::timeout(d, initiator(&mut i_rd, &mut i_wr, &a, &peers_i, "beta")),
            tokio::time::timeout(d, responder(&mut r_rd, &mut r_wr, &b, &peers_r)),
        );
        assert!(
            res_i.is_err() || matches!(res_i, Ok(Err(_))),
            "wrong host name must be rejected"
        );
        let _ = res_r;
    }
}
