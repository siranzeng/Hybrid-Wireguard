#[cfg(test)]
use hex;

#[cfg(test)]
use std::fmt;

use std::mem;

use super::types::*;
use crate::wireguard_hybrid_new::handshake::crypto_params::{
    SIZE_EPHEMERAL_KEM_CIPHERTEXT, SIZE_EPHEMERAL_KEM_PUB_KEY, SIZE_HASH, SIZE_KID,
    SIZE_RATCHET_KEM_CIPHERTEXT, SIZE_RATCHET_KEM_PUB_KEY, SIZE_SESSION_ID,
    SIZE_STATIC_KEM_CIPHERTEXT, SIZE_X25519_POINT, SIZE_XNONCE,
};
use byteorder::LittleEndian;
use zerocopy::byteorder::{U16, U32, U64};
use zerocopy::{AsBytes, ByteSlice, FromBytes, LayoutVerified};

const SIZE_MAC: usize = 16;
const SIZE_TAG: usize = 16; // poly1305 tag
const SIZE_COOKIE: usize = 16;
const SIZE_TIMESTAMP: usize = 16;
pub const SIZE_AUTH: usize = SIZE_HASH;
pub const SIZE_RI_PROOF: usize = 32;
pub const SIZE_IDENTITY_PLAIN: usize = SIZE_HASH + SIZE_RI_PROOF + 4 + 4;
pub const SIZE_ENC_ID: usize = SIZE_IDENTITY_PLAIN + SIZE_TAG;
pub const SIZE_CONFIRM_PLAIN: usize =
    8 + SIZE_RI_PROOF + SIZE_RATCHET_KEM_PUB_KEY + SIZE_KID + 4 + 4;
pub const SIZE_ENC_CONFIRM: usize = SIZE_CONFIRM_PLAIN + SIZE_TAG;

pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;
pub const TYPE_COOKIE_REPLY: u32 = 3;
pub const MODE_BOOTSTRAP: u32 = 0;
pub const MODE_RATCHET: u32 = 1;
pub const MODE_RESYNC: u32 = 2;
pub const PROTOCOL_VERSION_V2_3: u32 = 0x0002_0003;

pub type SessionId = [u8; SIZE_SESSION_ID];

#[inline(always)]
pub fn session_index(sid: &SessionId) -> u32 {
    u32::from_le_bytes([sid[0], sid[1], sid[2], sid[3]])
}

const fn max(a: usize, b: usize) -> usize {
    let m: usize = (a > b) as usize;
    m * a + (1 - m) * b
}

pub const MAX_HANDSHAKE_MSG_SIZE: usize = max(
    max(mem::size_of::<Response>(), mem::size_of::<Initiation>()),
    mem::size_of::<CookieReply>(),
);

/* =========================================
Inner sub-messages
========================================= */

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct NoiseInitiation {
    pub f_type: U32<LittleEndian>,
    pub f_mode: U32<LittleEndian>,
    pub f_epoch: U64<LittleEndian>,
    pub f_sender: SessionId,
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_ephemeral_pq: [u8; SIZE_EPHEMERAL_KEM_PUB_KEY],
    pub f_ratchet_kid: [u8; SIZE_KID],
    pub f_ratchet_ct: [u8; SIZE_RATCHET_KEM_CIPHERTEXT],
    pub f_static_ct_pq: [u8; SIZE_STATIC_KEM_CIPHERTEXT],
    pub f_identity: [u8; SIZE_ENC_ID],
    pub f_timestamp: [u8; SIZE_TIMESTAMP + SIZE_TAG],
    pub f_auth: [u8; SIZE_AUTH],
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct NoiseResponse {
    pub f_type: U32<LittleEndian>,
    pub f_mode: U32<LittleEndian>,
    pub f_epoch: U64<LittleEndian>,
    pub f_sender: SessionId,
    pub f_receiver: SessionId,
    pub f_ephemeral: [u8; SIZE_X25519_POINT],
    pub f_ephemeral_ct_pq: [u8; SIZE_EPHEMERAL_KEM_CIPHERTEXT],
    pub f_static_ct_pq: [u8; SIZE_STATIC_KEM_CIPHERTEXT],
    pub f_hash_ephemeral_pq: [u8; 32],
    pub f_confirm: [u8; SIZE_ENC_CONFIRM],
    pub f_auth: [u8; SIZE_AUTH],
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct MacsFooter {
    pub f_mac1: [u8; SIZE_MAC],
    pub f_mac2: [u8; SIZE_MAC],
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct RiProof {
    pub f: U64<LittleEndian>,
    pub a: U64<LittleEndian>,
    pub delta: U16<LittleEndian>,
    pub ts: U64<LittleEndian>,
    pub reserved: [u8; 6],
}

/* =========================================
Handshake messages
========================================= */

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct Initiation {
    pub noise: NoiseInitiation, // inner message
    pub macs: MacsFooter,       // m1, m2
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct Response {
    pub noise: NoiseResponse,
    pub macs: MacsFooter, // m1, m2
}

#[repr(packed)]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub struct CookieReply {
    pub f_type: U32<LittleEndian>,
    pub f_receiver: SessionId,
    pub f_nonce: [u8; SIZE_XNONCE],
    pub f_cookie: [u8; SIZE_COOKIE + SIZE_TAG],
}

/* Zero copy parsing of handshake messages */

impl Initiation {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.noise.f_type.get() != (TYPE_INITIATION as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }
        Ok(msg)
    }
}

impl Response {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.noise.f_type.get() != (TYPE_RESPONSE as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }
        Ok(msg)
    }
}

impl CookieReply {
    pub fn parse<B: ByteSlice>(bytes: B) -> Result<LayoutVerified<B, Self>, HandshakeError> {
        let msg: LayoutVerified<B, Self> =
            LayoutVerified::new(bytes).ok_or(HandshakeError::InvalidMessageFormat)?;

        if msg.f_type.get() != (TYPE_COOKIE_REPLY as u32) {
            return Err(HandshakeError::InvalidMessageFormat);
        }
        Ok(msg)
    }
}

/* Default values */

impl Default for Initiation {
    fn default() -> Self {
        Self {
            noise: Default::default(),
            macs: Default::default(),
        }
    }
}

impl Default for Response {
    fn default() -> Self {
        Self {
            noise: Default::default(),
            macs: Default::default(),
        }
    }
}

impl Default for CookieReply {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_COOKIE_REPLY as u32),
            f_receiver: [0u8; SIZE_SESSION_ID],
            f_nonce: [0u8; SIZE_XNONCE],
            f_cookie: [0u8; SIZE_COOKIE + SIZE_TAG],
        }
    }
}

impl Default for MacsFooter {
    fn default() -> Self {
        Self {
            f_mac1: [0u8; SIZE_MAC],
            f_mac2: [0u8; SIZE_MAC],
        }
    }
}

impl Default for NoiseInitiation {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_INITIATION as u32),
            f_mode: <U32<LittleEndian>>::new(MODE_BOOTSTRAP),
            f_epoch: <U64<LittleEndian>>::ZERO,
            f_sender: [0u8; SIZE_SESSION_ID],
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_ephemeral_pq: [0u8; SIZE_EPHEMERAL_KEM_PUB_KEY],
            f_ratchet_kid: [0u8; SIZE_KID],
            f_ratchet_ct: [0u8; SIZE_RATCHET_KEM_CIPHERTEXT],
            f_static_ct_pq: [0u8; SIZE_STATIC_KEM_CIPHERTEXT],
            f_identity: [0u8; SIZE_ENC_ID],
            f_timestamp: [0u8; SIZE_TIMESTAMP + SIZE_TAG],
            f_auth: [0u8; SIZE_AUTH],
        }
    }
}

impl Default for NoiseResponse {
    fn default() -> Self {
        Self {
            f_type: <U32<LittleEndian>>::new(TYPE_RESPONSE as u32),
            f_mode: <U32<LittleEndian>>::new(MODE_BOOTSTRAP),
            f_epoch: <U64<LittleEndian>>::ZERO,
            f_sender: [0u8; SIZE_SESSION_ID],
            f_receiver: [0u8; SIZE_SESSION_ID],
            f_ephemeral: [0u8; SIZE_X25519_POINT],
            f_ephemeral_ct_pq: [0u8; SIZE_EPHEMERAL_KEM_CIPHERTEXT],
            f_static_ct_pq: [0u8; SIZE_STATIC_KEM_CIPHERTEXT],
            f_hash_ephemeral_pq: [0u8; 32],
            f_confirm: [0u8; SIZE_ENC_CONFIRM],
            f_auth: [0u8; SIZE_AUTH],
        }
    }
}

impl Default for RiProof {
    fn default() -> Self {
        Self {
            f: <U64<LittleEndian>>::ZERO,
            a: <U64<LittleEndian>>::ZERO,
            delta: <U16<LittleEndian>>::ZERO,
            ts: <U64<LittleEndian>>::ZERO,
            reserved: [0u8; 6],
        }
    }
}

/* Debug formatting */

#[cfg(test)]
impl fmt::Debug for Initiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Initiation {{ {:?} || {:?} }}", self.noise, self.macs)
    }
}

#[cfg(test)]
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Response {{ {:?} || {:?} }}", self.noise, self.macs)
    }
}

#[cfg(test)]
impl fmt::Debug for CookieReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CookieReply {{ type = {}, receiver = {}, nonce = {}, cookie = {}  }}",
            self.f_type,
            hex::encode(&self.f_receiver[..]),
            hex::encode(&self.f_nonce[..]),
            hex::encode(&self.f_cookie[..]),
        )
    }
}

#[cfg(test)]
impl fmt::Debug for NoiseInitiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "NoiseInitiation {{ type = {}, mode = {}, epoch = {}, sender = {}, ephemeral = {}, kid = {}, ctR = {}, identity = {}, timestamp = {}, auth = {} }}",
            self.f_type.get(),
            self.f_mode.get(),
            self.f_epoch.get(),
            hex::encode(&self.f_sender[..]),
            hex::encode(&self.f_ephemeral[..]),
            hex::encode(&self.f_ratchet_kid[..]),
            hex::encode(&self.f_ratchet_ct[..]),
            hex::encode(&self.f_identity[..]),
            hex::encode(&self.f_timestamp[..]),
            hex::encode(&self.f_auth[..]),
        )
    }
}

#[cfg(test)]
impl fmt::Debug for NoiseResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "NoiseResponse {{ type = {}, mode = {}, epoch = {}, sender = {}, receiver = {}, ephemeral = {}, confirm = {}, auth = {} }}",
            self.f_type,
            self.f_mode.get(),
            self.f_epoch.get(),
            hex::encode(&self.f_sender[..]),
            hex::encode(&self.f_receiver[..]),
            hex::encode(&self.f_ephemeral[..]),
            hex::encode(&self.f_confirm[..]),
            hex::encode(&self.f_auth[..]),
        )
    }
}

#[cfg(test)]
impl fmt::Debug for RiProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RiProof {{ f = {}, a = {}, delta = {}, ts = {} }}",
            self.f.get(),
            self.a.get(),
            self.delta.get(),
            self.ts.get()
        )
    }
}

#[cfg(test)]
impl fmt::Debug for MacsFooter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Macs {{ mac1 = {}, mac2 = {} }}",
            hex::encode(&self.f_mac1[..]),
            hex::encode(&self.f_mac2[..])
        )
    }
}

/* Equality */

#[cfg(test)]
macro_rules! eq_as_bytes {
    ($type:path) => {
        impl PartialEq for $type {
            fn eq(&self, other: &Self) -> bool {
                self.as_bytes() == other.as_bytes()
            }
        }
        impl Eq for $type {}
    };
}

#[cfg(test)]
eq_as_bytes!(Initiation);
#[cfg(test)]
eq_as_bytes!(Response);
#[cfg(test)]
eq_as_bytes!(CookieReply);
#[cfg(test)]
eq_as_bytes!(MacsFooter);
#[cfg(test)]
eq_as_bytes!(NoiseInitiation);
#[cfg(test)]
eq_as_bytes!(NoiseResponse);
#[cfg(test)]
eq_as_bytes!(RiProof);
