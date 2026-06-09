use std::convert::{TryFrom, TryInto};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::types::HandshakeError;

// DH
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

// KEM
use super::crypto_params::*;
use super::messages::*;
use oqs;

// HASH & MAC
use blake2::Blake2s;
use hkdf::Hkdf;
use hmac::Hmac;

// AEAD
use aead::{Aead, NewAead, Payload};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::ChaCha20Poly1305;

use rand_core::{CryptoRng, RngCore};

use generic_array::typenum::*;
use generic_array::*;

use clear_on_drop::clear::Clear;
use clear_on_drop::clear_stack_on_return_fnonce;

use super::device::{Device, KeyState};
use super::messages::RiProof;
use super::messages::{session_index, NoiseInitiation, NoiseResponse, SessionId};
use super::messages::{TYPE_INITIATION, TYPE_RESPONSE};
use super::peer::{InitiationRatchet, Peer, ResponseRatchet, State};
use super::types::*;
use subtle::ConstantTimeEq;
use zerocopy::AsBytes;

use super::super::types::{Key, KeyPair};

type HMACBlake2s = Hmac<Blake2s>;
type TemporaryStateIntermediate = (PublicKey, [u8; 32], [u8; 32], ResponseRatchet, RiProof);
type TemporaryState = (
    SessionId,
    PublicKey,
    oqs::kem::PublicKey,
    [u8; 32],
    [u8; 32],
    ResponseRatchet,
    [u8; 32],
    [u8; 8],
);

const SIZE_CK: usize = 32;
const SIZE_HS: usize = SIZE_HASH;
const CLEAR_PAGES: usize = 1;

// C0 := HASH(lbl1) [cite: 96]
const INITIAL_CK: [u8; SIZE_CK] = [
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
];

// H0 := HASH(lbl1) [cite: 96]
const INITIAL_HS: [u8; SIZE_HS] = [
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32,
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
];

const ZERO_NONCE: [u8; 12] = [0u8; 12];
const EMPTY_RATCHET_SECRET: [u8; SIZE_RATCHET_KEM_SHARED_SECRET] =
    [0u8; SIZE_RATCHET_KEM_SHARED_SECRET];

macro_rules! SEAL {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(GenericArray::from_slice($key))
            .encrypt(&ZERO_NONCE.into(), Payload { msg: $pt, aad: $ad })
            .map(|ct| $ct.copy_from_slice(&ct))
            .unwrap()
    };
}

macro_rules! OPEN {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(GenericArray::from_slice($key))
            .decrypt(&ZERO_NONCE.into(), Payload { msg: $ct, aad: $ad })
            .map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    };
}

macro_rules! CHACHA20 {
    ($key:expr, $pt:expr) => {{
        let mut cipher = ChaCha20::new($key.into(), &ZERO_NONCE.into());
        let mut buffer = $pt.clone();
        cipher.apply_keystream(&mut buffer);
        buffer
    }};
}

#[inline(always)]
fn shared_secret(sk: &StaticSecret, pk: &PublicKey) -> Result<SharedSecret, HandshakeError> {
    let ss = sk.diffie_hellman(pk);
    if ss.as_bytes().ct_eq(&[0u8; 32]).into() {
        Err(HandshakeError::InvalidSharedSecret)
    } else {
        Ok(ss)
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn ri_key_u64(ri_key: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*ri_key)
}

fn ri_secret(ri_key: &[u8; 8], ck: &[u8; 32], h7: &[u8; 32]) -> [u8; 32] {
    HASH!(ri_key, ck, h7)
}

fn ri_target(ri_key: &[u8; 8], secret: &[u8; 32]) -> u64 {
    let hash = HASH!(ri_key, secret);
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&hash[..8]);
    (u64::from_le_bytes(raw) % 10_000) + 1
}

fn ri_key_for_epoch(manual: Option<[u8; 8]>, k_ri: &[u8; SIZE_HASH]) -> [u8; 8] {
    manual.unwrap_or_else(|| {
        let hash = HASH!(b"hybrid-wireguard-ri-v2.3", k_ri);
        let mut key = [0u8; 8];
        key.copy_from_slice(&hash[..8]);
        key
    })
}

fn generate_ri_proof<R: RngCore + CryptoRng>(
    rng: &mut R,
    ri_key: &[u8; 8],
    secret: &[u8; 32],
) -> RiProof {
    let target = ri_target(ri_key, secret);
    let delta = (rng.next_u32() % 9_999 + 1) as u16;
    let sigma = ((target - 1 + delta as u64) % 10_000) + 1;

    let mut chosen = [false; 10_001];
    chosen[sigma as usize] = true;
    let mut a = 0u64;
    let mut count = 0usize;
    while count < 99 {
        let candidate = (rng.next_u32() % 10_000 + 1) as usize;
        if !chosen[candidate] {
            chosen[candidate] = true;
            a ^= candidate as u64;
            count += 1;
        }
    }

    let sum_s = a ^ sigma;
    let f = ri_key_u64(ri_key) ^ sum_s;
    let mut proof = RiProof::default();
    proof.f.set(f);
    proof.a.set(a);
    proof.delta.set(delta);
    proof.ts.set(unix_secs());
    proof
}

fn verify_ri_proof(
    ri_key: &[u8; 8],
    secret: &[u8; 32],
    proof: &RiProof,
    err: HandshakeError,
) -> Result<(), HandshakeError> {
    if !bool::from(proof.reserved.ct_eq(&[0u8; 6])) {
        return Err(err);
    }

    let now = unix_secs();
    let ts = proof.ts.get();
    let skew = if now >= ts { now - ts } else { ts - now };
    if skew > 120 {
        return Err(err);
    }

    let delta = proof.delta.get();
    if delta == 0 || delta >= 10_000 {
        return Err(err);
    }

    let sigma = (proof.f.get() ^ ri_key_u64(ri_key)) ^ proof.a.get();
    if !(1..=10_000).contains(&sigma) {
        return Err(err);
    }

    let recovered = ((sigma - 1 + 10_000 - delta as u64) % 10_000) + 1;
    let expected = ri_target(ri_key, secret);
    if !bool::from(recovered.to_le_bytes().ct_eq(&expected.to_le_bytes())) {
        return Err(err);
    }
    Ok(())
}

fn mode_epoch_bytes(mode: u32, epoch: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&mode.to_le_bytes());
    out[4..].copy_from_slice(&epoch.to_le_bytes());
    out
}

fn auth_tag(key: &[u8], label: &[u8], hs: &[u8; 32]) -> [u8; SIZE_AUTH] {
    let out: [u8; 32] = HMAC!(key, label, hs).into();
    out
}

fn pack_ri_proof(ri: &RiProof) -> [u8; SIZE_RI_PROOF] {
    let mut out = [0u8; SIZE_RI_PROOF];
    out[..8].copy_from_slice(&ri.f.get().to_le_bytes());
    out[8..16].copy_from_slice(&ri.a.get().to_le_bytes());
    out[16..18].copy_from_slice(&ri.delta.get().to_le_bytes());
    out[18..26].copy_from_slice(&ri.ts.get().to_le_bytes());
    out[26..SIZE_RI_PROOF].copy_from_slice(&ri.reserved);
    out
}

fn unpack_ri_proof(src: &[u8]) -> RiProof {
    let mut ri = RiProof::default();
    ri.f.set(u64::from_le_bytes(src[..8].try_into().unwrap()));
    ri.a.set(u64::from_le_bytes(src[8..16].try_into().unwrap()));
    ri.delta
        .set(u16::from_le_bytes(src[16..18].try_into().unwrap()));
    ri.ts
        .set(u64::from_le_bytes(src[18..26].try_into().unwrap()));
    ri.reserved.copy_from_slice(&src[26..SIZE_RI_PROOF]);
    ri
}

fn pack_identity_plain(pk_hash: &[u8; SIZE_HASH], ri: &RiProof) -> [u8; SIZE_IDENTITY_PLAIN] {
    let mut out = [0u8; SIZE_IDENTITY_PLAIN];
    out[..SIZE_HASH].copy_from_slice(pk_hash);
    out[SIZE_HASH..SIZE_HASH + SIZE_RI_PROOF].copy_from_slice(&pack_ri_proof(ri));
    let version_offset = SIZE_HASH + SIZE_RI_PROOF;
    out[version_offset..version_offset + 4].copy_from_slice(&PROTOCOL_VERSION_V2_3.to_le_bytes());
    out[version_offset + 4..version_offset + 8].copy_from_slice(&0u32.to_le_bytes());
    out
}

fn unpack_identity_plain(
    plain: &[u8; SIZE_IDENTITY_PLAIN],
) -> Result<([u8; SIZE_HASH], RiProof), HandshakeError> {
    let mut pk_hash = [0u8; SIZE_HASH];
    pk_hash.copy_from_slice(&plain[..SIZE_HASH]);

    let base = SIZE_HASH;
    let ri = unpack_ri_proof(&plain[base..base + SIZE_RI_PROOF]);

    let version_offset = SIZE_HASH + SIZE_RI_PROOF;
    let version = u32::from_le_bytes(
        plain[version_offset..version_offset + 4]
            .try_into()
            .unwrap(),
    );
    if version != PROTOCOL_VERSION_V2_3 {
        return Err(HandshakeError::InvalidMessageFormat);
    }
    Ok((pk_hash, ri))
}

fn pack_confirm_plain(
    next_epoch: u64,
    ri: &RiProof,
    next_pub: &[u8; SIZE_RATCHET_KEM_PUB_KEY],
    next_kid: &[u8; SIZE_KID],
) -> [u8; SIZE_CONFIRM_PLAIN] {
    let mut out = [0u8; SIZE_CONFIRM_PLAIN];
    out[..8].copy_from_slice(&next_epoch.to_le_bytes());
    let mut off = 8;
    out[off..off + SIZE_RI_PROOF].copy_from_slice(&pack_ri_proof(ri));
    off += SIZE_RI_PROOF;
    out[off..off + SIZE_RATCHET_KEM_PUB_KEY].copy_from_slice(next_pub);
    off += SIZE_RATCHET_KEM_PUB_KEY;
    out[off..off + SIZE_KID].copy_from_slice(next_kid);
    off += SIZE_KID;
    out[off..off + 4].copy_from_slice(&PROTOCOL_VERSION_V2_3.to_le_bytes());
    out[off + 4..off + 8].copy_from_slice(&0u32.to_le_bytes());
    out
}

fn unpack_confirm_plain(
    plain: &[u8; SIZE_CONFIRM_PLAIN],
) -> Result<(u64, RiProof, [u8; SIZE_RATCHET_KEM_PUB_KEY], [u8; SIZE_KID]), HandshakeError> {
    let next_epoch = u64::from_le_bytes(plain[..8].try_into().unwrap());
    let mut off = 8;
    let ri = unpack_ri_proof(&plain[off..off + SIZE_RI_PROOF]);
    off += SIZE_RI_PROOF;

    let mut next_pub = [0u8; SIZE_RATCHET_KEM_PUB_KEY];
    next_pub.copy_from_slice(&plain[off..off + SIZE_RATCHET_KEM_PUB_KEY]);
    off += SIZE_RATCHET_KEM_PUB_KEY;

    let mut next_kid = [0u8; SIZE_KID];
    next_kid.copy_from_slice(&plain[off..off + SIZE_KID]);
    off += SIZE_KID;

    let version = u32::from_le_bytes(plain[off..off + 4].try_into().unwrap());
    if version != PROTOCOL_VERSION_V2_3 {
        return Err(HandshakeError::InvalidConfirm);
    }
    Ok((next_epoch, ri, next_pub, next_kid))
}

fn derive_kid(
    rk: &[u8; SIZE_HASH],
    epoch: u64,
    pubkey: &[u8; SIZE_RATCHET_KEM_PUB_KEY],
) -> [u8; SIZE_KID] {
    let pub_hash = HASH!(pubkey);
    let kid_full = MAC!(rk, b"kid", &epoch.to_le_bytes(), &pub_hash);
    let mut kid = [0u8; SIZE_KID];
    kid.copy_from_slice(&kid_full);
    kid
}

fn mix_v23_material(
    ck: &[u8; 32],
    rk: &[u8; SIZE_HASH],
    k_ri: &[u8; SIZE_HASH],
    ss_r: &[u8; SIZE_RATCHET_KEM_SHARED_SECRET],
    h_id: &[u8; SIZE_HASH],
    hs: &[u8; 32],
    mode: u32,
    epoch: u64,
) -> [u8; 32] {
    let mode_epoch = mode_epoch_bytes(mode, epoch);
    let material = HASH!(
        b"hybrid-wireguard-v2.3-session-key",
        rk,
        k_ri,
        ss_r,
        h_id,
        hs,
        &mode_epoch
    );
    KDF1!(ck, &material)
}

fn derive_next_roots(
    rk: &[u8; SIZE_HASH],
    k_ri: &[u8; SIZE_HASH],
    k_out: &[u8; 32],
    ss_r: &[u8; SIZE_RATCHET_KEM_SHARED_SECRET],
    ss_i: &[u8; 32],
    th: &[u8; 32],
    next_kid: &[u8; SIZE_KID],
    next_epoch: u64,
) -> ([u8; SIZE_HASH], [u8; SIZE_HASH]) {
    let next_epoch_bytes = next_epoch.to_le_bytes();
    let next_rk = HASH!(
        b"recovery-ratchet",
        rk,
        k_out,
        ss_r,
        ss_i,
        th,
        &next_epoch_bytes
    );
    let next_k_ri = HASH!(b"ri-ratchet", k_ri, k_out, th, next_kid, &next_epoch_bytes);
    (next_rk, next_k_ri)
}

pub(super) fn verify_response_hash(msg: &NoiseResponse) -> Result<(), HandshakeError> {
    let expected = HASH!(&msg.f_ephemeral_ct_pq);
    if !bool::from(msg.f_hash_ephemeral_pq.ct_eq(&expected)) {
        return Err(HandshakeError::DecryptionFailure);
    }
    Ok(())
}

pub(super) fn create_initiation<R: RngCore + CryptoRng, O>(
    rng: &mut R,
    keyst: &KeyState,
    peer: &Peer<O>,
    local_sid: SessionId,
    ri_key: &[u8; 8],
    msg: &mut NoiseInitiation,
) -> Result<(), HandshakeError> {
    log::debug!("create initiation");

    if peer.ss.ct_eq(&[0u8; 32]).into() {
        return Err(HandshakeError::InvalidSharedSecret);
    }

    let ratchet = peer.ratchet.lock().initiation_snapshot();

    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        let mut ck = INITIAL_CK;
        let mut hs = INITIAL_HS;
        let mode_epoch = mode_epoch_bytes(ratchet.mode, ratchet.epoch);

        // H1 = HASH(H0 || Sc_r || S_pq_r)
        hs = HASH!(&hs, b"Hybrid-WireGuard-v2.3", &peer.pk_hash, &mode_epoch);
        ck = KDF1!(&ck, &mode_epoch);

        msg.f_type.set(TYPE_INITIATION as u32);
        msg.f_mode.set(ratchet.mode);
        msg.f_epoch.set(ratchet.epoch);
        msg.f_sender = local_sid;

        // (ec_i, Ec_i) <- DH.gen(), (epq_i, E_pq_i) <- KEM.gen() [cite: 32]
        let eph_sk = StaticSecret::new(&mut *rng);
        let eph_pk = PublicKey::from(&eph_sk);
        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();
        let (eph_pk_pq, eph_sk_pq) = kemalg.keypair().unwrap();
        let eph_pk_pq_bytes =
            <[u8; SIZE_EPHEMERAL_KEM_PUB_KEY]>::try_from(eph_pk_pq.as_ref()).unwrap();

        // C2 = KDF_1(C1, Ec_i || E_pq_i) [cite: 99]
        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_PUB_KEY];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(eph_pk.as_bytes());
        concat_pk[SIZE_X25519_POINT..].copy_from_slice(&eph_pk_pq_bytes);
        ck = KDF1!(&ck, &concat_pk);

        msg.f_ephemeral = *eph_pk.as_bytes();
        msg.f_ephemeral_pq = eph_pk_pq_bytes;

        // H2 = HASH(H1 || Ec_i || E_pq_i)
        hs = HASH!(&hs, msg.f_ephemeral, msg.f_ephemeral_pq);

        let mut ss_r = EMPTY_RATCHET_SECRET;
        msg.f_ratchet_kid = ratchet.remote_kid;
        if let Some(remote_pub) = ratchet.remote_pub {
            let kemalg_ratchet = oqs::kem::Kem::new(RATCHET_KEM_ALG).unwrap();
            let rpk = kemalg_ratchet
                .public_key_from_bytes(&remote_pub)
                .ok_or(HandshakeError::RatchetStateMissing)?
                .to_owned();
            let (ct_r, shared) = kemalg_ratchet.encapsulate(&rpk).unwrap();
            msg.f_ratchet_ct =
                <[u8; SIZE_RATCHET_KEM_CIPHERTEXT]>::try_from(ct_r.as_ref()).unwrap();
            ss_r.copy_from_slice(shared.as_ref());
        } else if ratchet.mode == MODE_RATCHET {
            return Err(HandshakeError::RatchetStateMissing);
        }

        let ratchet_mix = HASH!(
            b"kem-r-public",
            &mode_epoch,
            &msg.f_ratchet_kid,
            &msg.f_ratchet_ct
        );
        ck = KDF1!(&ck, &ratchet_mix);
        hs = HASH!(&hs, &msg.f_ratchet_kid, &msg.f_ratchet_ct);

        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
        let (static_ct_pq, shk1) = kemalg_static.encapsulate(&peer.pk_pq).unwrap();
        let static_ct_pq_bytes =
            <[u8; SIZE_STATIC_KEM_CIPHERTEXT]>::try_from(static_ct_pq.as_ref()).unwrap();
        let shared_dh_ephemeral_static = shared_secret(&eph_sk, &peer.pk)?.to_bytes();
        let k: [u8; 32] = KDF1!(&[0u8; 32], &shared_dh_ephemeral_static);
        msg.f_static_ct_pq = CHACHA20!(&k, &static_ct_pq_bytes);

        // C3, k3 = KDF_2(C2, dheisr || shk1) [cite: 99]
        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_STATIC_KEM_SHARED_SECRET];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_ephemeral_static);
        concat[SIZE_X25519_POINT..].copy_from_slice(shk1.as_ref());
        let (ck_next, key) = KDF2!(&ck, &concat);
        ck = ck_next;

        // H3 = HASH(H2 || ct1enc)
        hs = HASH!(&hs, &msg.f_static_ct_pq);

        // C4, k4 = KDF2(C3, dhsisr || hash_static_pq_send || H_id || PSK)
        let mut concat2 = [0u8; SIZE_X25519_POINT + 32 + SIZE_HASH + SIZE_PSK];
        concat2[..SIZE_X25519_POINT].copy_from_slice(&peer.ss);
        concat2[SIZE_X25519_POINT..SIZE_X25519_POINT + 32]
            .copy_from_slice(&peer.hash_static_pq_send);
        concat2[SIZE_X25519_POINT + 32..SIZE_X25519_POINT + 32 + SIZE_HASH]
            .copy_from_slice(&peer.h_id_send);
        concat2[SIZE_X25519_POINT + 32 + SIZE_HASH..].copy_from_slice(peer.psk.as_bytes());
        let (ck_next2, key2) = KDF2!(&ck, &concat2);
        ck = ck_next2;

        let ri_i_secret = ri_secret(ri_key, &ck, &hs);
        let ri_i = generate_ri_proof(rng, ri_key, &ri_i_secret);
        let identity_plain = pack_identity_plain(&keyst.pk_hash, &ri_i);
        SEAL!(&key, &hs, &identity_plain, &mut msg.f_identity);

        // H4 = HASH(H3 || static)
        hs = HASH!(&hs, &msg.f_identity[..]);

        let mut k_send_old = peer.k_send.lock();
        *k_send_old = *k_send_old + 1;

        SEAL!(&key2, &hs, &k_send_old.to_be_bytes(), &mut msg.f_timestamp);
        hs = HASH!(&hs, &msg.f_timestamp);

        msg.f_auth = auth_tag(&key2, b"auth_i", &hs);
        hs = HASH!(&hs, &msg.f_auth);

        ck = mix_v23_material(
            &ck,
            &ratchet.rk,
            &ratchet.k_ri,
            &ss_r,
            &peer.h_id_send,
            &hs,
            ratchet.mode,
            ratchet.epoch,
        );

        *peer.state.lock() = State::InitiationSent {
            hs: hs.into(),
            ck: ck.into(),
            mode: ratchet.mode,
            epoch: ratchet.epoch,
            rk: ratchet.rk,
            k_ri: ratchet.k_ri,
            ss_r,
            eph_sk,
            eph_sk_pq,
            eph_pk_pq: eph_pk_pq_bytes,
            local: session_index(&local_sid),
            local_sid,
        };

        Ok(())
    })
}

pub(super) fn consume_initiation_first_part<'a, O>(
    device: &'a Device<O>,
    keyst: &KeyState,
    msg: &NoiseInitiation,
) -> Result<(&'a Peer<O>, [u8; SIZE_HASH], TemporaryStateIntermediate), HandshakeError> {
    log::debug!("consume initiation - Stage 1 (identify peer)");

    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        let mut ck = INITIAL_CK;
        let mut hs = INITIAL_HS;
        let mode = msg.f_mode.get();
        if !matches!(mode, MODE_BOOTSTRAP | MODE_RATCHET | MODE_RESYNC) {
            return Err(HandshakeError::InvalidMode);
        }
        let epoch = msg.f_epoch.get();
        let mode_epoch = mode_epoch_bytes(mode, epoch);

        // H1
        hs = HASH!(&hs, b"Hybrid-WireGuard-v2.3", keyst.pk_hash, &mode_epoch);
        ck = KDF1!(&ck, &mode_epoch);

        // C2
        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_PUB_KEY];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(&msg.f_ephemeral);
        concat_pk[SIZE_X25519_POINT..].copy_from_slice(&msg.f_ephemeral_pq);
        ck = KDF1!(&ck, &concat_pk);

        // H2
        hs = HASH!(&hs, &msg.f_ephemeral, &msg.f_ephemeral_pq);

        let ratchet_mix = HASH!(
            b"kem-r-public",
            &mode_epoch,
            &msg.f_ratchet_kid,
            &msg.f_ratchet_ct
        );
        ck = KDF1!(&ck, &ratchet_mix);
        hs = HASH!(&hs, &msg.f_ratchet_kid, &msg.f_ratchet_ct);

        let eph_r_pk = PublicKey::from(msg.f_ephemeral);
        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();

        // dheisr
        let shared_dh_ephemera_static = shared_secret(&keyst.sk, &eph_r_pk)?.to_bytes();

        let k: [u8; 32] = KDF1!(&[0u8; 32], &shared_dh_ephemera_static);
        let ct1_decrypt = CHACHA20!(&k, &msg.f_static_ct_pq);
        let ct1 = kemalg_static
            .ciphertext_from_bytes(&ct1_decrypt)
            .ok_or(HandshakeError::DecryptionFailure)?
            .to_owned();

        let shk1 = kemalg_static
            .decapsulate(&keyst.sk_pq, &ct1)
            .map_err(|_| HandshakeError::DecryptionFailure)?;

        // C3, k3
        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_STATIC_KEM_SHARED_SECRET];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_ephemera_static);
        let bytes = <[u8; SIZE_STATIC_KEM_SHARED_SECRET]>::try_from(shk1.as_ref()).unwrap();
        concat[SIZE_X25519_POINT..].copy_from_slice(&bytes);
        let (ck_next, key) = KDF2!(&ck, &concat);
        ck = ck_next;

        // H3
        hs = HASH!(&hs, &msg.f_static_ct_pq);

        let mut identity_plain = [0u8; SIZE_IDENTITY_PLAIN];

        OPEN!(&key, &hs, &mut identity_plain, &msg.f_identity)?;
        let (pk_hash, ri_i) = unpack_identity_plain(&identity_plain)?;

        let peer = device.lookup_pk(&pk_hash)?;
        let response_ratchet =
            peer.ratchet
                .lock()
                .response_snapshot(mode, epoch, &msg.f_ratchet_kid)?;

        Ok((peer, pk_hash, (eph_r_pk, hs, ck, response_ratchet, ri_i)))
    })
}

pub(super) fn consume_initiation_second_part<'a, O>(
    device: &'a Device<O>,
    msg: &NoiseInitiation,
    state: TemporaryStateIntermediate,
    peer: &'a Peer<O>,
    manual_ri_key: Option<[u8; 8]>,
) -> Result<TemporaryState, HandshakeError> {
    log::debug!("consume initiation - Part 2");

    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        let (eph_r_pk, mut hs, mut ck, ratchet, ri_i) = state;
        let ri_key = ri_key_for_epoch(manual_ri_key, &ratchet.k_ri);

        if peer.ss.ct_eq(&[0u8; 32]).into() {
            return Err(HandshakeError::InvalidSharedSecret);
        }

        // C4, k4 = KDF2(C3, dhsisr || hash_static_pq_recv || H_id || PSK)
        let mut concat2 = [0u8; SIZE_X25519_POINT + 32 + SIZE_HASH + SIZE_PSK];
        concat2[..SIZE_X25519_POINT].copy_from_slice(&peer.ss);
        concat2[SIZE_X25519_POINT..SIZE_X25519_POINT + 32]
            .copy_from_slice(&peer.hash_static_pq_recv);
        concat2[SIZE_X25519_POINT + 32..SIZE_X25519_POINT + 32 + SIZE_HASH]
            .copy_from_slice(&peer.h_id_recv);
        concat2[SIZE_X25519_POINT + 32 + SIZE_HASH..].copy_from_slice(peer.psk.as_bytes());
        let (ck_next, key) = KDF2!(&ck, &concat2);
        ck = ck_next;

        let ri_i_secret = ri_secret(&ri_key, &ck, &hs);
        verify_ri_proof(&ri_key, &ri_i_secret, &ri_i, HandshakeError::InvalidTi)?;

        // H4 = HASH(H3 || enc_id)
        hs = HASH!(&hs, &msg.f_identity[..]);

        let mut k_received: [u8; 16] = [0u8; 16];

        OPEN!(&key, &hs, &mut k_received, &msg.f_timestamp)?;

        // H5
        hs = HASH!(&hs, &msg.f_timestamp);

        let expected_auth = auth_tag(&key, b"auth_i", &hs);
        if !bool::from(expected_auth.ct_eq(&msg.f_auth)) {
            return Err(HandshakeError::DecryptionFailure);
        }

        peer.check_replay_flood(device, u128::from_be_bytes(k_received))?;

        hs = HASH!(&hs, &msg.f_auth);

        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();
        let eph_r_pk_pq = kemalg
            .public_key_from_bytes(&msg.f_ephemeral_pq)
            .ok_or(HandshakeError::InvalidMessageFormat)?
            .to_owned();

        let mut ss_r = EMPTY_RATCHET_SECRET;
        if ratchet.mode == MODE_RATCHET {
            let secret = ratchet
                .local_secret
                .ok_or(HandshakeError::RatchetStateMissing)?;
            let kemalg_ratchet = oqs::kem::Kem::new(RATCHET_KEM_ALG).unwrap();
            let sk = kemalg_ratchet
                .secret_key_from_bytes(&secret)
                .ok_or(HandshakeError::RatchetStateMissing)?
                .to_owned();
            let ct = kemalg_ratchet
                .ciphertext_from_bytes(&msg.f_ratchet_ct)
                .ok_or(HandshakeError::DecryptionFailure)?
                .to_owned();
            let shared = kemalg_ratchet
                .decapsulate(&sk, &ct)
                .map_err(|_| HandshakeError::DecryptionFailure)?;
            ss_r.copy_from_slice(shared.as_ref());
        }

        ck = mix_v23_material(
            &ck,
            &ratchet.rk,
            &ratchet.k_ri,
            &ss_r,
            &peer.h_id_recv,
            &hs,
            ratchet.mode,
            ratchet.epoch,
        );

        Ok((
            msg.f_sender,
            eph_r_pk,
            eph_r_pk_pq,
            hs,
            ck,
            ratchet,
            ss_r,
            ri_key,
        ))
    })
}

pub(super) fn create_response<R: RngCore + CryptoRng, O>(
    rng: &mut R,
    peer: &Peer<O>,
    local_sid: SessionId,
    state: TemporaryState,
    msg: &mut NoiseResponse,
) -> Result<KeyPair, HandshakeError> {
    log::debug!("create response");
    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        let (receiver, eph_r_pk, eph_r_pk_pq, mut hs, mut ck, ratchet, ss_r, ri_key) = state;
        let sidi = receiver;
        let sidr = local_sid;

        msg.f_type.set(TYPE_RESPONSE as u32);
        msg.f_mode.set(ratchet.mode);
        msg.f_epoch.set(ratchet.epoch);
        msg.f_sender = sidr;
        msg.f_receiver = sidi;

        let eph_sk = StaticSecret::new(&mut *rng);
        let eph_pk = PublicKey::from(&eph_sk);
        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();
        let (eph_ct_pq, shk_master) = kemalg.encapsulate(&eph_r_pk_pq).unwrap();

        msg.f_ephemeral = *eph_pk.as_bytes();
        msg.f_ephemeral_ct_pq =
            <[u8; SIZE_EPHEMERAL_KEM_CIPHERTEXT]>::try_from(eph_ct_pq.as_ref()).unwrap();

        let hash_ephemeral_pq = HASH!(&msg.f_ephemeral_ct_pq);
        msg.f_hash_ephemeral_pq.copy_from_slice(&hash_ephemeral_pq);

        let mut ctx = [0u8; SIZE_SESSION_ID + SIZE_SESSION_ID + SIZE_EPHEMERAL_KEM_PUB_KEY + 32];
        ctx[..SIZE_SESSION_ID].copy_from_slice(&sidi);
        ctx[SIZE_SESSION_ID..SIZE_SESSION_ID * 2].copy_from_slice(&sidr);
        ctx[SIZE_SESSION_ID * 2..SIZE_SESSION_ID * 2 + SIZE_EPHEMERAL_KEM_PUB_KEY]
            .copy_from_slice(eph_r_pk_pq.as_ref());
        ctx[SIZE_SESSION_ID * 2 + SIZE_EPHEMERAL_KEM_PUB_KEY..].copy_from_slice(&hash_ephemeral_pq);

        let hkdf = Hkdf::<Blake2s>::new(Some(&ctx), shk_master.as_ref());
        let mut shk2_raw = [0u8; 32];
        let mut shk_ee = [0u8; 32];
        hkdf.expand(b"hybrid-wg-shk2", &mut shk2_raw).unwrap();
        hkdf.expand(b"hybrid-wg-shk-ee", &mut shk_ee).unwrap();

        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
        let (static_ct_pq, shk3_raw) = kemalg_static.encapsulate(&peer.pk_pq).unwrap();

        let shk2 = HASH!(&shk2_raw, &shk_ee);
        let shk3 = HASH!(shk3_raw.as_ref(), &shk_ee);

        let shared_dh_static_ephemeral = shared_secret(&eph_sk, &peer.pk)?.to_bytes();
        let k_se: [u8; 32] = KDF1!(&[0u8; 32], &shared_dh_static_ephemeral);
        let static_ct_pq_bytes =
            <[u8; SIZE_STATIC_KEM_CIPHERTEXT]>::try_from(static_ct_pq.as_ref()).unwrap();
        msg.f_static_ct_pq = CHACHA20!(&k_se, &static_ct_pq_bytes);

        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT + SIZE_HASH];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(eph_pk.as_bytes());
        concat_pk[SIZE_X25519_POINT..SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT]
            .copy_from_slice(&msg.f_ephemeral_ct_pq);
        concat_pk[SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT..]
            .copy_from_slice(&hash_ephemeral_pq);
        ck = KDF1!(&ck, &concat_pk);

        hs = HASH!(
            &hs,
            &msg.f_ephemeral,
            &msg.f_ephemeral_ct_pq,
            &msg.f_static_ct_pq,
            &hash_ephemeral_pq
        );

        let mut concat_k = [0u8; SIZE_X25519_POINT + 32];
        concat_k[..SIZE_X25519_POINT]
            .copy_from_slice(shared_secret(&eph_sk, &eph_r_pk)?.as_bytes());
        concat_k[SIZE_X25519_POINT..].copy_from_slice(&shk2);
        ck = KDF1!(&ck, &concat_k);

        let mut concat = [0u8; SIZE_X25519_POINT + 32];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_static_ephemeral);
        concat[SIZE_X25519_POINT..].copy_from_slice(&shk3);
        ck = KDF1!(&ck, &concat);

        let h7 = HASH!(&hs, &shk_ee);
        let (ck_next, tau, key): ([u8; 32], [u8; 32], [u8; 32]) = KDF3!(&ck, &peer.psk);
        ck = ck_next;

        hs = HASH!(&h7, &tau);

        let next_epoch = ratchet.epoch + 1;
        let kemalg_ratchet = oqs::kem::Kem::new(RATCHET_KEM_ALG).unwrap();
        let (next_pub, next_secret) = kemalg_ratchet.keypair().unwrap();
        let next_pub_bytes = <[u8; SIZE_RATCHET_KEM_PUB_KEY]>::try_from(next_pub.as_ref()).unwrap();
        let next_secret_bytes =
            <[u8; SIZE_RATCHET_KEM_SECRET_KEY]>::try_from(next_secret.as_ref()).unwrap();
        let next_kid = derive_kid(&ratchet.rk, next_epoch, &next_pub_bytes);

        let ri_r_secret = ri_secret(&ri_key, &ck, &h7);
        let ri_r = generate_ri_proof(rng, &ri_key, &ri_r_secret);
        let confirm_plain = pack_confirm_plain(next_epoch, &ri_r, &next_pub_bytes, &next_kid);

        SEAL!(&key, &hs, &confirm_plain, &mut msg.f_confirm);
        hs = HASH!(&hs, &msg.f_confirm);

        msg.f_auth = auth_tag(&key, b"auth_r", &hs);
        hs = HASH!(&hs, &msg.f_auth);

        let k_out = HASH!(b"session-key", &ck, &hs);
        let (next_rk, next_k_ri) = derive_next_roots(
            &ratchet.rk,
            &ratchet.k_ri,
            &k_out,
            &ss_r,
            &shk2,
            &hs,
            &next_kid,
            next_epoch,
        );

        peer.ratchet.lock().stage_responder(
            &ratchet,
            next_epoch,
            next_secret_bytes,
            next_kid,
            next_rk,
            next_k_ri,
        );

        let (key_recv_ga, key_send_ga): (GenericArray<u8, U32>, GenericArray<u8, U32>) =
            KDF2!(&ck, b"transport");
        let key_recv: [u8; 32] = key_recv_ga.into();
        let key_send: [u8; 32] = key_send_ga.into();

        Ok(KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: Key {
                id: session_index(&sidi),
                key: key_send.into(),
            },
            recv: Key {
                id: session_index(&sidr),
                key: key_recv.into(),
            },
        })
    })
}

pub(super) fn consume_response<'a, O>(
    keyst: &KeyState,
    msg: &NoiseResponse,
    peer: &'a Peer<O>,
    ri_key: &[u8; 8],
) -> Result<Output<'a, O>, HandshakeError> {
    log::debug!("consume response");
    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();

        let (
            mut hs,
            mut ck,
            local,
            local_sid,
            mode,
            epoch,
            rk,
            k_ri,
            ss_r,
            eph_sk,
            eph_sk_pq,
            eph_pk_pq_bytes,
        ) = match *peer.state.lock() {
            State::InitiationSent {
                hs,
                ck,
                local,
                local_sid,
                mode,
                epoch,
                rk,
                k_ri,
                ss_r,
                ref eph_sk,
                ref eph_sk_pq,
                ref eph_pk_pq,
            } => {
                let hs_arr: [u8; 32] = hs.into();
                let ck_arr: [u8; 32] = ck.into();
                Ok((
                    hs_arr,
                    ck_arr,
                    local,
                    local_sid,
                    mode,
                    epoch,
                    rk,
                    k_ri,
                    ss_r,
                    StaticSecret::from(eph_sk.to_bytes()),
                    kemalg
                        .secret_key_from_bytes(eph_sk_pq.as_ref())
                        .unwrap()
                        .to_owned(),
                    *eph_pk_pq,
                ))
            }
            _ => Err(HandshakeError::InvalidState),
        }?;

        if !bool::from(local_sid.ct_eq(&msg.f_receiver)) {
            return Err(HandshakeError::UnknownReceiverId);
        }
        if msg.f_mode.get() != mode || msg.f_epoch.get() != epoch {
            return Err(HandshakeError::InvalidEpoch);
        }
        let sidi = local_sid;
        let sidr = msg.f_sender;

        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT + SIZE_HASH];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(&msg.f_ephemeral);
        concat_pk[SIZE_X25519_POINT..SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT]
            .copy_from_slice(&msg.f_ephemeral_ct_pq);
        concat_pk[SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT..]
            .copy_from_slice(&msg.f_hash_ephemeral_pq);
        ck = KDF1!(&ck, &concat_pk);

        hs = HASH!(
            &hs,
            &msg.f_ephemeral,
            &msg.f_ephemeral_ct_pq,
            &msg.f_static_ct_pq,
            &msg.f_hash_ephemeral_pq
        );

        let ct2 = kemalg
            .ciphertext_from_bytes(&msg.f_ephemeral_ct_pq)
            .ok_or(HandshakeError::DecryptionFailure)?
            .to_owned();
        let shk_master = kemalg
            .decapsulate(&eph_sk_pq, &ct2)
            .map_err(|_| HandshakeError::DecryptionFailure)?;
        let eph_r_pk = PublicKey::from(msg.f_ephemeral);

        let mut ctx = [0u8; SIZE_SESSION_ID + SIZE_SESSION_ID + SIZE_EPHEMERAL_KEM_PUB_KEY + 32];
        ctx[..SIZE_SESSION_ID].copy_from_slice(&sidi);
        ctx[SIZE_SESSION_ID..SIZE_SESSION_ID * 2].copy_from_slice(&sidr);
        ctx[SIZE_SESSION_ID * 2..SIZE_SESSION_ID * 2 + SIZE_EPHEMERAL_KEM_PUB_KEY]
            .copy_from_slice(&eph_pk_pq_bytes);
        ctx[SIZE_SESSION_ID * 2 + SIZE_EPHEMERAL_KEM_PUB_KEY..]
            .copy_from_slice(&msg.f_hash_ephemeral_pq);

        let hkdf = Hkdf::<Blake2s>::new(Some(&ctx), shk_master.as_ref());
        let mut shk2_raw = [0u8; 32];
        let mut shk_ee = [0u8; 32];
        hkdf.expand(b"hybrid-wg-shk2", &mut shk2_raw).unwrap();
        hkdf.expand(b"hybrid-wg-shk-ee", &mut shk_ee).unwrap();

        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
        let shared_dh_static_ephemeral = shared_secret(&keyst.sk, &eph_r_pk)?.to_bytes();
        let k_se: [u8; 32] = KDF1!(&[0u8; 32], &shared_dh_static_ephemeral);

        let ct3_decrypt = CHACHA20!(&k_se, &msg.f_static_ct_pq);
        let ct3 = kemalg_static
            .ciphertext_from_bytes(&ct3_decrypt)
            .ok_or(HandshakeError::DecryptionFailure)?
            .to_owned();
        let shk3_raw = kemalg_static
            .decapsulate(&keyst.sk_pq, &ct3)
            .map_err(|_| HandshakeError::DecryptionFailure)?;

        let shk2 = HASH!(&shk2_raw, &shk_ee);
        let shk3_bytes =
            <[u8; SIZE_STATIC_KEM_SHARED_SECRET]>::try_from(shk3_raw.as_ref()).unwrap();
        let shk3 = HASH!(&shk3_bytes, &shk_ee);

        let mut concat_k = [0u8; SIZE_X25519_POINT + 32];
        concat_k[..SIZE_X25519_POINT]
            .copy_from_slice(shared_secret(&eph_sk, &eph_r_pk)?.as_bytes());
        concat_k[SIZE_X25519_POINT..].copy_from_slice(&shk2);
        ck = KDF1!(&ck, &concat_k);

        let mut concat = [0u8; SIZE_X25519_POINT + 32];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_static_ephemeral);
        concat[SIZE_X25519_POINT..].copy_from_slice(&shk3);
        ck = KDF1!(&ck, &concat);

        let h7 = HASH!(&hs, &shk_ee);
        let (ck_next, tau, key) = KDF3!(&ck, &peer.psk);
        ck = ck_next;

        hs = HASH!(&h7, &tau);

        let mut confirm_plain = [0u8; SIZE_CONFIRM_PLAIN];
        OPEN!(&key, &hs, &mut confirm_plain, &msg.f_confirm)?;
        let (next_epoch, ri_r, next_pub, next_kid) = unpack_confirm_plain(&confirm_plain)?;
        if next_epoch != epoch + 1 {
            return Err(HandshakeError::InvalidConfirm);
        }
        hs = HASH!(&hs, &msg.f_confirm);

        let expected_auth = auth_tag(&key, b"auth_r", &hs);
        if !bool::from(expected_auth.ct_eq(&msg.f_auth)) {
            return Err(HandshakeError::DecryptionFailure);
        }
        hs = HASH!(&hs, &msg.f_auth);

        let ri_r_secret = ri_secret(ri_key, &ck, &h7);
        verify_ri_proof(ri_key, &ri_r_secret, &ri_r, HandshakeError::InvalidTr)?;

        let k_out = HASH!(b"session-key", &ck, &hs);
        let (next_rk, next_k_ri) =
            derive_next_roots(&rk, &k_ri, &k_out, &ss_r, &shk2, &hs, &next_kid, next_epoch);

        let birth = Instant::now();
        let (key_send, key_recv): (GenericArray<u8, U32>, GenericArray<u8, U32>) =
            KDF2!(&ck, b"transport");

        let mut state = peer.state.lock();
        let update = match *state {
            State::InitiationSent {
                eph_sk: ref old_eph_sk,
                eph_sk_pq: ref old_eph_sk_pq,
                ..
            } => {
                let c1 = old_eph_sk.to_bytes().ct_eq(&eph_sk.to_bytes());
                let old_sk_bytes: [u8; SIZE_EPHEMERAL_KEM_SECRET_KEY] =
                    <[u8; SIZE_EPHEMERAL_KEM_SECRET_KEY]>::try_from(old_eph_sk_pq.as_ref())
                        .unwrap();
                let cur_sk_bytes: [u8; SIZE_EPHEMERAL_KEM_SECRET_KEY] =
                    <[u8; SIZE_EPHEMERAL_KEM_SECRET_KEY]>::try_from(eph_sk_pq.as_ref()).unwrap();
                let c2 = old_sk_bytes.ct_eq(&cur_sk_bytes);
                bool::from(c1 & c2)
            }
            _ => false,
        };

        if update {
            *state = State::Reset;
            peer.ratchet
                .lock()
                .commit_initiator(next_epoch, next_pub, next_kid, next_rk, next_k_ri);
            let remote = session_index(&msg.f_sender);

            Ok((
                Some(&peer.opaque),
                None,
                Some(KeyPair {
                    birth,
                    initiator: true,
                    send: Key {
                        id: remote,
                        key: key_send.into(),
                    },
                    recv: Key {
                        id: local,
                        key: key_recv.into(),
                    },
                }),
            ))
        } else {
            Err(HandshakeError::InvalidState)
        }
    })
}
