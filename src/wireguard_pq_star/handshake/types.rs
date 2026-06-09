use super::super::types::KeyPair;

use std::error::Error;
use std::fmt;

/* Internal types for the noise IKpsk2 implementation */

// config error

#[derive(Debug)]
pub struct ConfigError(String);

impl ConfigError {
    pub fn new(s: &str) -> Self {
        ConfigError(s.to_string())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigError({})", self.0)
    }
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        &self.0
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

// handshake error

#[derive(Debug)]
pub enum HandshakeError {
    DecryptionFailure,
    UnknownPublicKey,
    UnknownReceiverId,
    InvalidMessageFormat,
    InvalidSharedSecret,
    OldTimestamp,
    InvalidState,
    InvalidMac1,
    RateLimited,
    InitiationFlood,
    InvalidHashSize,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::InvalidSharedSecret => write!(f, "Zero shared secret"),
            HandshakeError::DecryptionFailure => write!(f, "Failed to AEAD:OPEN"),
            HandshakeError::UnknownPublicKey => write!(f, "Unknown public key"),
            HandshakeError::UnknownReceiverId => {
                write!(f, "Receiver id not allocated to any handshake")
            }
            HandshakeError::InvalidMessageFormat => write!(f, "Invalid handshake message format"),
            HandshakeError::OldTimestamp => write!(f, "Timestamp is less/equal to the newest"),
            HandshakeError::InvalidState => write!(f, "Message does not apply to handshake state"),
            HandshakeError::InvalidMac1 => write!(f, "Message has invalid mac1 field"),
            HandshakeError::RateLimited => write!(f, "Message was dropped by rate limiter"),
            HandshakeError::InitiationFlood => {
                write!(f, "Message was dropped because of initiation flood")
            }
            HandshakeError::InvalidHashSize => {
                write!(f, "Hash size invalid for initiation message creation")
            }
        }
    }
}

impl Error for HandshakeError {
    fn description(&self) -> &str {
        "Generic Handshake Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug)]
pub enum PQError {
    InvalidEphemeralKemPublicKeySize,
    InvalidEphemeralKemSecretKeySize,
    InvalidEphemeralKemCiphertextSize,
    InvalidEphemeralKemSecretSize,
    InvalidStaticKemPublicKeySize,
    InvalidStaticKemSecretKeySize,
    InvalidStaticKemCiphertextSize,
    InvalidStaticKemSecretSize,
}

impl fmt::Display for PQError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PQError::InvalidEphemeralKemPublicKeySize => write!(f, "Invalid Ephemeral Kem public key size, check liboqs version and update the constant var SIZE_EPHEMERAL_KEM_PUB_KEY accordingly"),
            PQError::InvalidEphemeralKemSecretKeySize => write!(f, "Invalid Ephemeral Kem secret key size, check liboqs version and update the constant var SIZE_EPHEMERAL_KEM_SECRET_KEY accordingly"),
            PQError::InvalidEphemeralKemCiphertextSize => write!(f, "Invalid Ephemeral Kem ciphertext size, check liboqs version and update the constant var SIZE_EPHEMERAL_KEM_CIPHERTEXT accordingly"),
            PQError::InvalidEphemeralKemSecretSize => write!(f, "Invalid Ephemeral Kem secret size, check liboqs version and update the constant var SIZE_EPHEMERAL_KEM_SHARED_SECRET accordingly"),
            PQError::InvalidStaticKemPublicKeySize => write!(f, "Invalid Static Kem public key size, check liboqs version and update the constant var SIZE_STATIC_KEM_PUB_KEY accordingly"),
            PQError::InvalidStaticKemSecretKeySize => write!(f, "Invalid Static Kem secret key size, check liboqs version and update the constant var SIZE_STATIC_KEM_SECRET_KEY accordingly"),
            PQError::InvalidStaticKemCiphertextSize =>  write!(f, "Invalid Static Kem ciphertext size, check liboqs version and update the constant var SIZE_STATIC_KEM_CIPHERTEXT accordingly"),
            PQError::InvalidStaticKemSecretSize => write!(f, "Invalid Static Kem secret size, check liboqs version and update the constant var SIZE_STATIC_KEM_SHARED_SECRET accordingly"),
        }
    }
}

impl Error for PQError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
    fn description(&self) -> &str {
        "Generic PQ Error"
    }
}

pub type Output<'a, O> = (
    Option<&'a O>,   // external identifier associated with peer
    Option<Vec<u8>>, // message to send
    Option<KeyPair>, // resulting key-pair of successful handshake
);

// preshared key

pub type Psk = [u8; 32];
