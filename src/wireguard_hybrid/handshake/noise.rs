use std::convert::TryFrom;
use std::time::Instant;

// DH
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

// KEM
use super::crypto_params::*;
use super::messages::*;
use oqs;

// HASH & MAC
use blake2::Blake2s;
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
use super::messages::{NoiseInitiation, NoiseResponse};
use super::messages::{TYPE_INITIATION, TYPE_RESPONSE};
use super::peer::{Peer, State};
use super::timestamp;
use super::types::*;
use subtle::ConstantTimeEq;
use zerocopy::AsBytes;

use super::super::types::{Key, KeyPair};

// HMAC hasher (generic construction)

type HMACBlake2s = Hmac<Blake2s>;

// convenient alias to pass state temporarily into device.rs and back

type TemporaryStateIntermediate = (PublicKey, GenericArray<u8, U32>, GenericArray<u8, U32>);

type TemporaryState = (
    u32,
    PublicKey,
    oqs::kem::PublicKey,
    GenericArray<u8, U32>,
    GenericArray<u8, U32>,
);

const SIZE_CK: usize = 32;
const SIZE_HS: usize = SIZE_HASH;

// number of pages to clear after sensitive call
const CLEAR_PAGES: usize = 1;

// C := Hash(Construction)
const INITIAL_CK: [u8; SIZE_CK] = [
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
];

// H := Hash(C || Identifier)
const INITIAL_HS: [u8; SIZE_HS] = [
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32,
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
];

const ZERO_NONCE: [u8; 12] = [0u8; 12];

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

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
    const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

    /* Sanity check precomputed initial chain key
     */
    #[test]
    fn precomputed_chain_key() {
        assert_eq!(INITIAL_CK[..], HASH!(CONSTRUCTION)[..]);
    }

    /* Sanity check precomputed initial hash transcript
     */
    #[test]
    fn precomputed_hash() {
        assert_eq!(INITIAL_HS[..], HASH!(INITIAL_CK, IDENTIFIER)[..]);
    }

    /* Sanity check the HKDF macro
     *
     * Test vectors generated using WireGuard-Go
     */
    #[test]
    fn hkdf() {
        let tests: Vec<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], [u8; 32])> = vec![
            (
                vec![],
                vec![],
                [
                    0x83, 0x87, 0xb4, 0x6b, 0xf4, 0x3e, 0xcc, 0xfc, 0xf3, 0x49, 0x55, 0x2a, 0x09,
                    0x5d, 0x83, 0x15, 0xc4, 0x05, 0x5b, 0xeb, 0x90, 0x20, 0x8f, 0xb1, 0xbe, 0x23,
                    0xb8, 0x94, 0xbc, 0x2e, 0xd5, 0xd0,
                ],
                [
                    0x58, 0xa0, 0xe5, 0xf6, 0xfa, 0xef, 0xcc, 0xf4, 0x80, 0x7b, 0xff, 0x1f, 0x05,
                    0xfa, 0x8a, 0x92, 0x17, 0x94, 0x57, 0x62, 0x04, 0x0b, 0xce, 0xc2, 0xf4, 0xb4,
                    0xa6, 0x2b, 0xdf, 0xe0, 0xe8, 0x6e,
                ],
                [
                    0x0c, 0xe6, 0xea, 0x98, 0xec, 0x54, 0x8f, 0x8e, 0x28, 0x1e, 0x93, 0xe3, 0x2d,
                    0xb6, 0x56, 0x21, 0xc4, 0x5e, 0xb1, 0x8d, 0xc6, 0xf0, 0xa7, 0xad, 0x94, 0x17,
                    0x86, 0x10, 0xa2, 0xf7, 0x33, 0x8e,
                ],
            ),
            (
                vec![0xde, 0xad, 0xbe, 0xef],
                vec![],
                [
                    0x55, 0x32, 0x9d, 0xc8, 0x0e, 0x69, 0x0f, 0xd8, 0x6b, 0xd9, 0x66, 0x1f, 0x08,
                    0x51, 0xc9, 0xb3, 0x68, 0x6d, 0xf2, 0xb1, 0xfd, 0xa0, 0x34, 0x7b, 0xc3, 0xd2,
                    0x79, 0x58, 0x25, 0x4b, 0x32, 0xc6,
                ],
                [
                    0x8d, 0xfc, 0x6d, 0x33, 0xa8, 0x11, 0x8f, 0xfe, 0x40, 0x8b, 0x31, 0xdd, 0xac,
                    0x25, 0xf7, 0x2a, 0xee, 0x91, 0x15, 0xa4, 0x5b, 0x69, 0xba, 0x17, 0x6a, 0xd0,
                    0x12, 0xb2, 0x43, 0x83, 0x4f, 0xee,
                ],
                [
                    0xd6, 0x9e, 0x85, 0x2a, 0x28, 0x96, 0x56, 0x9e, 0xa5, 0x4a, 0x67, 0x96, 0x9a,
                    0xa1, 0x80, 0x02, 0x87, 0x92, 0x1d, 0xac, 0x53, 0xce, 0x6d, 0xb4, 0xb4, 0xe1,
                    0x21, 0x92, 0xf2, 0x63, 0xc4, 0xc4,
                ],
            ),
        ];

        for (key, input, t0, t1, t2) in &tests {
            let tt0 = KDF1!(key, input);
            debug_assert_eq!(tt0[..], t0[..]);

            let (tt0, tt1) = KDF2!(key, input);
            debug_assert_eq!(tt0[..], t0[..]);
            debug_assert_eq!(tt1[..], t1[..]);

            let (tt0, tt1, tt2) = KDF3!(key, input);
            debug_assert_eq!(tt0[..], t0[..]);
            debug_assert_eq!(tt1[..], t1[..]);
            debug_assert_eq!(tt2[..], t2[..]);
        }
    }
}

// Computes an X25519 shared secret.
//
// This function wraps dalek to add a zero-check.
// This is not recommended by the Noise specification,
// but implemented in the kernel with which we strive for absolute equivalent behavior.
#[inline(always)]
fn shared_secret(sk: &StaticSecret, pk: &PublicKey) -> Result<SharedSecret, HandshakeError> {
    let ss = sk.diffie_hellman(pk);
    if ss.as_bytes().ct_eq(&[0u8; 32]).into() {
        Err(HandshakeError::InvalidSharedSecret)
    } else {
        Ok(ss)
    }
}

pub(super) fn create_initiation<R: RngCore + CryptoRng, O>(
    rng: &mut R,
    keyst: &KeyState,
    peer: &Peer<O>,
    local: u32,
    msg: &mut NoiseInitiation,
) -> Result<(), HandshakeError> {
    log::debug!("create initiation");

    // check for zero shared-secret (see "shared_secret" note).
    if peer.ss.ct_eq(&[0u8; 32]).into() {
        return Err(HandshakeError::InvalidSharedSecret);
    }

    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        // initialize state

        let ck = INITIAL_CK;
        let hs = INITIAL_HS;
        let hs = HASH!(&hs, &peer.pk_hash);

        msg.f_type.set(TYPE_INITIATION as u32);
        msg.f_sender.set(local); // from us

        // (E_priv, E_pub) := DH-Generate()

        let eph_sk = StaticSecret::new(rng);
        let eph_pk = PublicKey::from(&eph_sk);

        // Ephemeral Kem keys

        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();
        let (eph_pk_pq, eph_sk_pq) = kemalg.keypair().unwrap();
        let eph_pk_pq_bytes =
            <[u8; SIZE_EPHEMERAL_KEM_PUB_KEY]>::try_from(eph_pk_pq.as_ref()).unwrap();

        // C := Kdf(C, E_pub || E_pub_pq)

        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_PUB_KEY];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(eph_pk.as_bytes());
        concat_pk[SIZE_X25519_POINT..].copy_from_slice(&eph_pk_pq_bytes);
        let ck = KDF1!(&ck, &concat_pk);

        // msg.ephemeral := E_pub

        msg.f_ephemeral = *eph_pk.as_bytes();

        // msg.ephemeral_pq := E_pub_pq

        msg.f_ephemeral_pq = eph_pk_pq_bytes;

        // (msg.static_ct_pq, shk1) = encapsulate(static public key of the responder)

        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
        let (static_ct_pq, shk1) = kemalg_static.encapsulate(&peer.pk_pq).unwrap();
        let static_ct_pq_bytes =
            <[u8; SIZE_STATIC_KEM_CIPHERTEXT]>::try_from(static_ct_pq.as_ref()).unwrap();

        let shared_dh_ephemeral_static = shared_secret(&eph_sk, &peer.pk)?.to_bytes();
        let k = KDF1!(&[0u8; 32], &shared_dh_ephemeral_static);
        msg.f_static_ct_pq = CHACHA20!(&k, &static_ct_pq_bytes);
        // msg.f_static_ct_pq = static_ct_pq_bytes;

        // H := HASH(H, msg.ephemeral, msg.ephemeral_pq)

        let hs = HASH!(&hs, msg.f_ephemeral, msg.f_ephemeral_pq);

        // (C, k) := Kdf2(C, DH(E_priv, S_pub) || shk1)

        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_STATIC_KEM_SHARED_SECRET];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_ephemeral_static);
        let bytes = <[u8; SIZE_STATIC_KEM_SHARED_SECRET]>::try_from(shk1.as_ref()).unwrap();
        concat[SIZE_X25519_POINT..].copy_from_slice(&bytes);
        let (ck, key) = KDF2!(&ck, &concat);

        // msg.static := Aead(k, 0, S_pub, H)

        let key_hash = &keyst.pk_hash;
        if key_hash.as_bytes().len() != SIZE_HASH {
            return Err(HandshakeError::InvalidHashSize);
        }

        // let key_hash = HASH!(&keyst.pk.as_bytes());
        SEAL!(
            &key,
            &hs,                 // ad
            key_hash.as_bytes(), // pt
            &mut msg.f_static    // ct || tag
        );

        // H := Hash(H || msg.static)

        let hs = HASH!(&hs, &msg.f_static[..]);

        // (C, k) := Kdf2(C, DH(S_priv, S_pub) || HASH(spki_pq || spkr_pq) || psk)

        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_HASH + SIZE_PSK];
        concat[..SIZE_X25519_POINT].copy_from_slice(&peer.ss);
        concat[SIZE_X25519_POINT..SIZE_X25519_POINT + SIZE_HASH]
            .copy_from_slice(&peer.hash_static_pq_send);
        concat[SIZE_X25519_POINT + SIZE_HASH..].copy_from_slice(peer.psk.as_bytes());
        let (ck, key) = KDF2!(&ck, &concat);

        // msg.timestamp := Aead(k, 0, Timestamp(), H)

        let mut k_send_old = peer.k_send.lock();
        // println!("K_SEND = {k_send_old}");
        *k_send_old = *k_send_old + 1;

        SEAL!(
            &key,
            &hs,                       // ad
            &k_send_old.to_be_bytes(), // pt
            &mut msg.f_timestamp       // ct || tag
        );

        // H := Hash(H || msg.timestamp)

        let hs = HASH!(&hs, &msg.f_timestamp);

        // update state of peer

        *peer.state.lock() = State::InitiationSent {
            hs,
            ck,
            eph_sk,
            eph_sk_pq,
            local,
        };

        Ok(())
    })
}

pub(super) fn consume_initiation_first_part<'a, O>(
    device: &'a Device<O>,
    keyst: &KeyState,
    msg: &NoiseInitiation,
) -> Result<(&'a Peer<O>, [u8; SIZE_HASH], TemporaryStateIntermediate), HandshakeError> {
    log::debug!("consume initiation");

    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        // initialize new state

        let ck = INITIAL_CK;
        let hs = INITIAL_HS;
        let hs = HASH!(&hs, keyst.pk_hash);

        // C := Kdf(C, E_pub || E_pub_pq)
        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_PUB_KEY];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(&msg.f_ephemeral);
        concat_pk[SIZE_X25519_POINT..].copy_from_slice(&msg.f_ephemeral_pq);
        let ck = KDF1!(&ck, &concat_pk);

        // H := HASH(H, msg.ephemeral, msg.ephemeral_pq)

        let hs = HASH!(&hs, &msg.f_ephemeral, &msg.f_ephemeral_pq);

        // (C, k) := Kdf2(C, DH(E_pub, S_priv) || shk1)

        let eph_r_pk = PublicKey::from(msg.f_ephemeral);
        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();

        let shared_dh_ephemera_static = shared_secret(&keyst.sk, &eph_r_pk)?.to_bytes();
        let k = KDF1!(&[0u8; 32], &shared_dh_ephemera_static);
        let ct1_decrypt = CHACHA20!(&k, &msg.f_static_ct_pq);
        let ct1 = kemalg_static
            .ciphertext_from_bytes(&ct1_decrypt)
            .unwrap()
            .to_owned();
        // let ct1 = kemalg_static.ciphertext_from_bytes(&msg.f_static_ct_pq).unwrap().to_owned();

        let shk1 = kemalg_static.decapsulate(&keyst.sk_pq, &ct1).unwrap();

        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_STATIC_KEM_SHARED_SECRET];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_ephemera_static);
        let bytes = <[u8; SIZE_STATIC_KEM_SHARED_SECRET]>::try_from(shk1.as_ref()).unwrap();
        concat[SIZE_X25519_POINT..].copy_from_slice(&bytes);
        let (ck, key) = KDF2!(&ck, &concat);

        // msg.static := Aead(k, 0, S_pub, H)

        let mut pk_hash = [0u8; SIZE_HASH];

        OPEN!(
            &key,
            &hs,           // ad
            &mut pk_hash,  // pt
            &msg.f_static  // ct || tag
        )?;

        let peer = device.lookup_pk(&pk_hash)?;

        Ok((peer, pk_hash, (eph_r_pk, hs, ck)))
    })
}

pub(super) fn consume_initiation_second_part<'a, O>(
    device: &'a Device<O>,
    msg: &NoiseInitiation,
    state: TemporaryStateIntermediate, // state from "consume_initiation_first_part"
    peer: &'a Peer<O>,
) -> Result<TemporaryState, HandshakeError> {
    log::debug!("consume initiation");

    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        // unpack state

        let (eph_r_pk, hs, ck) = state;

        // check for zero shared-secret (see "shared_secret" note).

        if peer.ss.ct_eq(&[0u8; 32]).into() {
            return Err(HandshakeError::InvalidSharedSecret);
        }

        // reset initiation state

        *peer.state.lock() = State::Reset;

        // H := Hash(H || msg.static)

        let hs = HASH!(&hs, &msg.f_static[..]);

        // (C, k) := Kdf2(C, DH(S_priv, S_pub) || psk)

        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_HASH + SIZE_PSK];
        concat[..SIZE_X25519_POINT].copy_from_slice(&peer.ss);
        concat[SIZE_X25519_POINT..SIZE_X25519_POINT + SIZE_HASH]
            .copy_from_slice(&peer.hash_static_pq_recv);
        concat[SIZE_X25519_POINT + SIZE_HASH..].copy_from_slice(peer.psk.as_bytes());
        let (ck, key) = KDF2!(&ck, &concat);

        // msg.timestamp := Aead(k, 0, Timestamp(), H)

        let mut k_received: [u8; 16] = [0u8; 16];

        OPEN!(
            &key,
            &hs,              // ad
            &mut k_received,  // pt
            &msg.f_timestamp  // ct || tag
        )?;

        // check and update timestamp

        peer.check_replay_flood(device, u128::from_be_bytes(k_received))?;

        // H := Hash(H || msg.timestamp)

        let hs = HASH!(&hs, &msg.f_timestamp);

        // return state (to create response)

        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();
        let eph_r_pk_pq = kemalg
            .public_key_from_bytes(&msg.f_ephemeral_pq)
            .unwrap()
            .to_owned();

        Ok((msg.f_sender.get(), eph_r_pk, eph_r_pk_pq, hs, ck))
    })
}

pub(super) fn create_response<R: RngCore + CryptoRng, O>(
    rng: &mut R,
    peer: &Peer<O>,
    local: u32,              // sending identifier
    state: TemporaryState,   // state from "consume_initiation"
    msg: &mut NoiseResponse, // resulting response
) -> Result<KeyPair, HandshakeError> {
    log::debug!("create response");
    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        // unpack state

        let (receiver, eph_r_pk, eph_r_pk_pq, hs, ck) = state;

        msg.f_type.set(TYPE_RESPONSE as u32);
        msg.f_sender.set(local); // from us
        msg.f_receiver.set(receiver); // to the sender of the initiation

        // (E_priv, E_pub) := DH-Generate()

        let eph_sk = StaticSecret::new(rng);
        let eph_pk = PublicKey::from(&eph_sk);

        // (msg.ephemeral_ct_pq, shk2) = encapsulate(ephemeral public key of the initiator)

        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();
        let (eph_ct_pq, shk2) = kemalg.encapsulate(&eph_r_pk_pq).unwrap();
        let eph_ct_pq_bytes =
            <[u8; SIZE_EPHEMERAL_KEM_CIPHERTEXT]>::try_from(eph_ct_pq.as_ref()).unwrap();

        msg.f_ephemeral_ct_pq = eph_ct_pq_bytes;

        // (msg.static_ct_pq, shk3) = encapsulate(static public key of the initiator)

        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
        let (static_ct_pq, shk3) = kemalg_static.encapsulate(&peer.pk_pq).unwrap();
        let static_ct_pq_bytes =
            <[u8; SIZE_STATIC_KEM_CIPHERTEXT]>::try_from(static_ct_pq.as_ref()).unwrap();

        let shared_dh_static_ephemeral = shared_secret(&eph_sk, &peer.pk)?.to_bytes();
        let k = KDF1!(&[0u8; 32], &shared_dh_static_ephemeral);
        msg.f_static_ct_pq = CHACHA20!(&k, &static_ct_pq_bytes);
        // msg.f_static_ct_pq = static_ct_pq_bytes;

        // C := Kdf1(C, E_pub || msg.ephemeral_ct_pq)

        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(eph_pk.as_bytes());
        concat_pk[SIZE_X25519_POINT..].copy_from_slice(&eph_ct_pq_bytes);
        let ck = KDF1!(&ck, &concat_pk);

        // msg.ephemeral := E_pub

        msg.f_ephemeral = *eph_pk.as_bytes();

        // H := Hash(H || msg.ephemeral || msg.ephemeral_ct_pq)

        let hs = HASH!(&hs, &msg.f_ephemeral, &msg.f_ephemeral_ct_pq);

        // C := Kdf1(C, DH(E_priv, E_pub) || shk2)

        let shk2_bytes = <[u8; SIZE_EPHEMERAL_KEM_SHARED_SECRET]>::try_from(shk2.as_ref()).unwrap();
        let mut concat_k = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_SHARED_SECRET];
        concat_k[..SIZE_X25519_POINT]
            .copy_from_slice(shared_secret(&eph_sk, &eph_r_pk)?.as_bytes());
        concat_k[SIZE_X25519_POINT..].copy_from_slice(&shk2_bytes);

        let ck = KDF1!(&ck, &concat_k);

        // C := Kdf1(C, DH(E_priv, S_pub) || shk3)

        let shk3_bytes = <[u8; SIZE_STATIC_KEM_SHARED_SECRET]>::try_from(shk3.as_ref()).unwrap();
        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_STATIC_KEM_SHARED_SECRET];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_static_ephemeral);
        concat[SIZE_X25519_POINT..].copy_from_slice(&shk3_bytes);

        let ck = KDF1!(&ck, &concat);

        // (C, tau, k) := Kdf3(C, Q)

        let (ck, tau, key) = KDF3!(&ck, &peer.psk);

        // H := Hash(H || tau)

        let hs = HASH!(&hs, tau);

        // msg.empty := Aead(k, 0, [], H)

        SEAL!(
            &key,
            &hs,              // ad
            &[],              // pt
            &mut msg.f_empty  // \epsilon || tag
        );

        // Not strictly needed
        // let hs = HASH!(&hs, &msg.f_empty_tag);

        // derive key-pair

        let (key_recv, key_send) = KDF2!(&ck, &[]);

        // return unconfirmed key-pair

        Ok(KeyPair {
            birth: Instant::now(),
            initiator: false,
            send: Key {
                id: receiver,
                key: key_send.into(),
            },
            recv: Key {
                id: local,
                key: key_recv.into(),
            },
        })
    })
}

/* The state lock is released while processing the message to
 * allow concurrent processing of potential responses to the initiation,
 * in order to better mitigate DoS from malformed response messages.
 */
pub(super) fn consume_response<'a, O>(
    keyst: &KeyState,
    msg: &NoiseResponse,
    peer: &'a Peer<O>,
) -> Result<Output<'a, O>, HandshakeError> {
    log::debug!("consume response");
    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        // retrieve peer and copy initiation state
        // let peer = device.lookup_id(msg.f_receiver.get())?;

        let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();

        let (hs, ck, local, eph_sk, eph_sk_pq) = match *peer.state.lock() {
            State::InitiationSent {
                hs,
                ck,
                local,
                ref eph_sk,
                ref eph_sk_pq,
            } => Ok((
                hs,
                ck,
                local,
                StaticSecret::from(eph_sk.to_bytes()),
                kemalg
                    .secret_key_from_bytes(eph_sk_pq.as_ref())
                    .unwrap()
                    .to_owned(),
            )),
            _ => Err(HandshakeError::InvalidState),
        }?;

        // C := Kdf1(C, E_pub || msg.ephemeral_ct_pq)
        let mut concat_pk = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_CIPHERTEXT];
        concat_pk[..SIZE_X25519_POINT].copy_from_slice(&msg.f_ephemeral);
        concat_pk[SIZE_X25519_POINT..].copy_from_slice(&msg.f_ephemeral_ct_pq);
        let ck = KDF1!(&ck, &concat_pk);

        // H := Hash(H || msg.ephemeral || msg.ephemeral_ct_pq)

        let hs = HASH!(&hs, &msg.f_ephemeral, &msg.f_ephemeral_ct_pq);

        // C := Kdf1(C, DH(E_priv, E_pub) || shk2)

        let ct2 = kemalg
            .ciphertext_from_bytes(&msg.f_ephemeral_ct_pq)
            .unwrap()
            .to_owned();
        let shk2 = kemalg.decapsulate(&eph_sk_pq, &ct2).unwrap();
        let eph_r_pk = PublicKey::from(msg.f_ephemeral);

        let shk2_bytes = <[u8; SIZE_EPHEMERAL_KEM_SHARED_SECRET]>::try_from(shk2.as_ref()).unwrap();
        let mut concat_k = [0u8; SIZE_X25519_POINT + SIZE_EPHEMERAL_KEM_SHARED_SECRET];
        concat_k[..SIZE_X25519_POINT]
            .copy_from_slice(shared_secret(&eph_sk, &eph_r_pk)?.as_bytes());
        concat_k[SIZE_X25519_POINT..].copy_from_slice(&shk2_bytes);

        let ck = KDF1!(&ck, &concat_k);

        // C := Kdf1(C, DH(E_pub, S_priv) || shk3)

        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();

        let shared_dh_static_ephemeral = shared_secret(&keyst.sk, &eph_r_pk)?.to_bytes();
        let k = KDF1!(&[0u8; 32], &shared_dh_static_ephemeral);
        let ct3_decrypt = CHACHA20!(&k, &msg.f_static_ct_pq);
        let ct3 = kemalg_static
            .ciphertext_from_bytes(&ct3_decrypt)
            .unwrap()
            .to_owned();
        // let ct3 = kemalg_static.ciphertext_from_bytes(&msg.f_static_ct_pq).unwrap().to_owned();

        let shk3 = kemalg_static.decapsulate(&keyst.sk_pq, &ct3).unwrap();

        let shk3_bytes = <[u8; SIZE_STATIC_KEM_SHARED_SECRET]>::try_from(shk3.as_ref()).unwrap();
        let mut concat = [0u8; SIZE_X25519_POINT + SIZE_STATIC_KEM_SHARED_SECRET];
        concat[..SIZE_X25519_POINT].copy_from_slice(&shared_dh_static_ephemeral);
        concat[SIZE_X25519_POINT..].copy_from_slice(&shk3_bytes);

        let ck = KDF1!(&ck, &concat);

        // (C, tau, k) := Kdf3(C, Q)

        let (ck, tau, key) = KDF3!(&ck, &peer.psk);

        // H := Hash(H || tau)

        let hs = HASH!(&hs, tau);

        // msg.empty := Aead(k, 0, [], H)

        OPEN!(
            &key,
            &hs,          // ad
            &mut [],      // pt
            &msg.f_empty  // \epsilon || tag
        )?;

        // derive key-pair

        let birth = Instant::now();
        let (key_send, key_recv) = KDF2!(&ck, &[]);

        // check for new initiation sent while lock released

        let mut state = peer.state.lock();
        let update = match *state {
            State::InitiationSent {
                eph_sk: ref old,
                eph_sk_pq: ref old_pq,
                ..
            } => {
                let c1 = old.to_bytes().ct_eq(&eph_sk.to_bytes());
                let old_sk_bytes: [u8; SIZE_EPHEMERAL_KEM_SECRET_KEY] =
                    <[u8; SIZE_EPHEMERAL_KEM_SECRET_KEY]>::try_from(old_pq.as_ref()).unwrap();
                let eph_sk_bytes: [u8; SIZE_EPHEMERAL_KEM_SECRET_KEY] =
                    <[u8; SIZE_EPHEMERAL_KEM_SECRET_KEY]>::try_from(eph_sk_pq.as_ref()).unwrap();
                let c2 = old_sk_bytes.ct_eq(&eph_sk_bytes);
                (c1 & c2).into()
            }
            _ => false,
        };

        if update {
            // null the initiation state
            // (to avoid replay of this response message)
            *state = State::Reset;
            let remote = msg.f_sender.get();

            // return confirmed key-pair
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
