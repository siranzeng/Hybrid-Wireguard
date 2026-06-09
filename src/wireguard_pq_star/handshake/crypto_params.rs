use crate::wireguard_pq_star::handshake::types::{HandshakeError, PQError};
use oqs;
// Post-Quantum Algorithm choices

// EPHEMERAL KEM: KYBER 512 PARAMS
pub const EPHEMERAL_KEM_ALG: oqs::kem::Algorithm = oqs::kem::Algorithm::MlKem512;

pub const SIZE_EPHEMERAL_KEM_PUB_KEY: usize = 800;

pub const SIZE_EPHEMERAL_KEM_SECRET_KEY: usize = 1632;
pub const SIZE_EPHEMERAL_KEM_CIPHERTEXT: usize = 768;

pub const SIZE_EPHEMERAL_KEM_SHARED_SECRET: usize = 32;

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

// STATIC KEM: CLASSIC MCELIECE 460896 PARAMS

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
pub const SIZE_XNONCE: usize = 24; // xchacha20 nonce
pub const SIZE_HASH: usize = 32;

pub const SIZE_PSK: usize = 32;

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::Digest;
        let mut hsh = Blake2s::new();
        $(
            hsh.update($input);
        )*
        hsh.finalize()
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

macro_rules! XSEAL {
    ($key:expr, $nonce:expr, $ad:expr, $pt:expr, $ct:expr) => {{
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

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        t0.clear();
        t1
    }};
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        t0.clear();
        (t1, t2)
    }};
}

macro_rules! KDF3 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        let t3 = HMAC!(&t0, &t2, &[0x3]);
        t0.clear();
        (t1, t2, t3)
    }};
}

pub(crate) use HASH;
pub(crate) use HMAC;
pub(crate) use KDF1;
pub(crate) use KDF2;
pub(crate) use KDF3;
pub(crate) use MAC;
pub(crate) use XOPEN;
pub(crate) use XSEAL;
