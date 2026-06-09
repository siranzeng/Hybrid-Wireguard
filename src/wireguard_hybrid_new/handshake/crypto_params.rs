use crate::wireguard_hybrid_new::handshake::types::{HandshakeError, PQError};
use oqs;

// Post-Quantum Algorithm choices

pub const EPHEMERAL_KEM_ALG: oqs::kem::Algorithm = oqs::kem::Algorithm::MlKem512;

pub const SIZE_EPHEMERAL_KEM_PUB_KEY: usize = 800;
pub const SIZE_EPHEMERAL_KEM_SECRET_KEY: usize = 1632;
pub const SIZE_EPHEMERAL_KEM_CIPHERTEXT: usize = 768;
pub const SIZE_EPHEMERAL_KEM_SHARED_SECRET: usize = 32;

pub const RATCHET_KEM_ALG: oqs::kem::Algorithm = EPHEMERAL_KEM_ALG;
pub const SIZE_RATCHET_KEM_PUB_KEY: usize = SIZE_EPHEMERAL_KEM_PUB_KEY;
pub const SIZE_RATCHET_KEM_SECRET_KEY: usize = SIZE_EPHEMERAL_KEM_SECRET_KEY;
pub const SIZE_RATCHET_KEM_CIPHERTEXT: usize = SIZE_EPHEMERAL_KEM_CIPHERTEXT;
pub const SIZE_RATCHET_KEM_SHARED_SECRET: usize = SIZE_EPHEMERAL_KEM_SHARED_SECRET;
pub const SIZE_KID: usize = 16;

pub fn check_ephemeral_kem_sizes() -> Result<(), PQError> {
    let kemalg = oqs::kem::Kem::new(EPHEMERAL_KEM_ALG).unwrap();
    if SIZE_EPHEMERAL_KEM_PUB_KEY != kemalg.length_public_key() {
        return Err(PQError::InvalidEphemeralKemPublicKeySize);
    }
    if SIZE_EPHEMERAL_KEM_SECRET_KEY != kemalg.length_secret_key() {
        return Err(PQError::InvalidEphemeralKemSecretKeySize);
    }
    if SIZE_EPHEMERAL_KEM_CIPHERTEXT != kemalg.length_ciphertext() {
        return Err(PQError::InvalidEphemeralKemCiphertextSize);
    }
    if SIZE_EPHEMERAL_KEM_SHARED_SECRET != kemalg.length_shared_secret() {
        return Err(PQError::InvalidEphemeralKemSecretSize);
    }
    Ok(())
}

pub const STATIC_KEM_ALG: oqs::kem::Algorithm = oqs::kem::Algorithm::ClassicMcEliece460896;

pub const SIZE_STATIC_KEM_PUB_KEY: usize = 524160;
pub const SIZE_STATIC_KEM_SECRET_KEY: usize = 13608;
pub const SIZE_STATIC_KEM_CIPHERTEXT: usize = 156;
pub const SIZE_STATIC_KEM_SHARED_SECRET: usize = 32;

pub fn check_static_kem_sizes() -> Result<(), PQError> {
    let kemalg = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
    if SIZE_STATIC_KEM_PUB_KEY != kemalg.length_public_key() {
        return Err(PQError::InvalidStaticKemPublicKeySize);
    }
    if SIZE_STATIC_KEM_SECRET_KEY != kemalg.length_secret_key() {
        return Err(PQError::InvalidStaticKemSecretKeySize);
    }
    if SIZE_STATIC_KEM_CIPHERTEXT != kemalg.length_ciphertext() {
        return Err(PQError::InvalidStaticKemCiphertextSize);
    }
    if SIZE_STATIC_KEM_SHARED_SECRET != kemalg.length_shared_secret() {
        return Err(PQError::InvalidStaticKemSecretSize);
    }
    Ok(())
}

#[test]
fn check_sizes() {
    check_static_kem_sizes().unwrap();
    check_ephemeral_kem_sizes().unwrap();
}

// Other crypto parameters
pub const SIZE_NONCE: usize = 12; // chacha20 nonce (96-bit)
pub const SIZE_XNONCE: usize = 24; // xchacha20 nonce (192-bit) for CookieReply
pub const SIZE_MAC: usize = 16; // 128-bit MAC output for keyed-Blake2s
pub const SIZE_TAG: usize = 16; // Poly1305 authentication tag size

pub const SIZE_X25519_POINT: usize = 32; // x25519 public key
pub const SIZE_HASH: usize = 32;
pub const SIZE_PSK: usize = 32;
pub const SIZE_SESSION_ID: usize = 32;

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::Digest;
        let mut hsh = Blake2s::new();
        $(
            hsh.update($input);
        )*
        let res: [u8; 32] = hsh.finalize().into();
        res
    }};
}

macro_rules! MAC {
    ( $key:expr, $($input:expr),* ) => {{
        use blake2::VarBlake2s;
        use blake2::digest::{Update, VariableOutput};
        let mut tag = [0u8; SIZE_MAC];
        let mut mac = VarBlake2s::new_keyed($key, SIZE_MAC);
        $(
            mac.update($input);
        )*
        mac.finalize_variable(|buf| tag.copy_from_slice(buf));
        tag
    }};
}

// SE: ChaCha20 pure stream cipher (used strictly for KEM Ciphertext Enc/Dec)
macro_rules! SE_CRYPT {
    ($key:expr, $nonce:expr, $data:expr) => {{
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20::ChaCha20;
        let mut cipher = ChaCha20::new(
            GenericArray::from_slice($key),
            GenericArray::from_slice($nonce),
        );
        cipher.apply_keystream($data); // encrypt/decrypt in place
    }};
}

// AEAD: Standard ChaCha20Poly1305 (96-bit nonce, used for static/time/empty fields)
macro_rules! SEAL {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice($key));
        let ct = cipher
            .encrypt(
                GenericArray::from_slice($nonce),
                Payload { msg: $pt, aad: $ad },
            )
            .unwrap();
        debug_assert_eq!(ct.len(), $pt.len() + SIZE_TAG);
        $ct.copy_from_slice(&ct);
    }};
}

macro_rules! OPEN {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
        debug_assert_eq!($ct.len(), $pt.len() + SIZE_TAG);
        ChaCha20Poly1305::new(GenericArray::from_slice($key))
            .decrypt(
                GenericArray::from_slice($nonce),
                Payload { msg: $ct, aad: $ad },
            )
            .map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    }};
}

// CookieAEAD: XChaCha20Poly1305 (192-bit nonce, used strictly for CookieReply construction)
macro_rules! XSEAL {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        use aead::{AeadInPlace, NewAead};
        use chacha20poly1305::XChaCha20Poly1305;
        let ct = XChaCha20Poly1305::new(GenericArray::from_slice($key))
            .encrypt(
                GenericArray::from_slice($nonce),
                Payload { msg: $pt, aad: $ad },
            )
            .unwrap();
        debug_assert_eq!(ct.len(), $pt.len() + SIZE_TAG);
        $ct.copy_from_slice(&ct);
    }};
}

macro_rules! XOPEN {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        use aead::{AeadInPlace, NewAead};
        use chacha20poly1305::XChaCha20Poly1305;
        debug_assert_eq!($ct.len(), $pt.len() + SIZE_TAG);
        XChaCha20Poly1305::new(GenericArray::from_slice($key))
            .decrypt(
                GenericArray::from_slice($nonce),
                Payload { msg: $ct, aad: $ad },
            )
            .map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    }};
}

macro_rules! HMAC {
    ($key:expr, $($input:expr),*) => {{
        use hmac::{Mac, NewMac};
        let mut mac = HMACBlake2s::new_varkey($key).unwrap();
        $(
            mac.update($input);
        )*
        mac.finalize().into_bytes()
    }};
}

// Base HKDF using HMAC-Blake2s for specific info/salt contexts
macro_rules! HKDF {
    ($ikm:expr, $salt:expr, $info:expr, $out_len:expr) => {{
        use hkdf::Hkdf;
        // blake2::Blake2s as the underlying hash function
        let hk = Hkdf::<blake2::Blake2s>::new(Some($salt), $ikm);
        let mut okm = vec![0u8; $out_len];
        hk.expand($info, &mut okm).unwrap();
        okm
    }};
}

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        t0.clear();
        t1.into()
    }};
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        t0.clear();
        (t1.into(), t2)
    }};
}

macro_rules! KDF3 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        let t3 = HMAC!(&t0, &t2, &[0x3]);
        t0.clear();

        let out1: [u8; 32] = t1.into();
        let out2: [u8; 32] = t2.into();
        let out3: [u8; 32] = t3.into();
        (out1, out2, out3)
    }};
}
pub(crate) use HASH;
pub(crate) use HKDF;
pub(crate) use HMAC;
pub(crate) use KDF1;
pub(crate) use KDF2;
pub(crate) use KDF3;
pub(crate) use MAC;
pub(crate) use OPEN;
pub(crate) use SEAL;
pub(crate) use SE_CRYPT;
pub(crate) use XOPEN;
pub(crate) use XSEAL;
