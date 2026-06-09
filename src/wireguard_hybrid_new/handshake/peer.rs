use spin::Mutex;
use std::convert::TryFrom;

use std::mem;
use std::time::{Duration, Instant};

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use clear_on_drop::clear::Clear;

use super::device::Device;
use super::macs;
use super::timestamp;
use super::types::*;

use blake2::Blake2s;

use super::messages::{SessionId, MODE_BOOTSTRAP, MODE_RATCHET, MODE_RESYNC};
use crate::wireguard_hybrid_new::handshake::crypto_params::{
    HASH, SIZE_EPHEMERAL_KEM_PUB_KEY, SIZE_HASH, SIZE_KID, SIZE_RATCHET_KEM_PUB_KEY,
    SIZE_RATCHET_KEM_SECRET_KEY, SIZE_STATIC_KEM_PUB_KEY,
};
use oqs;

const TIME_BETWEEN_INITIATIONS: Duration = Duration::from_millis(20);

// Represents the state of a peer.
//
// This type is only for internal use and not exposed.
pub(super) struct Peer<O> {
    // opaque type which identifies a peer
    pub opaque: O,

    // mutable state
    pub state: Mutex<State>,
    pub timestamp: Mutex<Option<timestamp::TAI64N>>,
    pub last_initiation_consumption: Mutex<Option<Instant>>,

    // state related to DoS mitigation fields
    pub macs: Mutex<macs::Generator>,
    pub macs_validator: Mutex<macs::Validator>,

    // constant state
    pub ss: [u8; 32],               // precomputed DH(static, static)
    pub psk: Psk,                   // psk of peer
    pub pk: PublicKey,              // static ECDH public key
    pub pk_pq: oqs::kem::PublicKey, // static KEM public key
    pub pk_hash: [u8; SIZE_HASH],
    pub own_pk_hash: [u8; SIZE_HASH],

    pub hash_static_pq_send: [u8; SIZE_HASH],
    pub hash_static_pq_recv: [u8; SIZE_HASH],
    pub h_id_send: [u8; SIZE_HASH],
    pub h_id_recv: [u8; SIZE_HASH],
    pub ratchet: Mutex<RatchetState>,

    // replacement of the time-based anti-replay (timestamp),
    // using an unsigned integer counter
    pub k_send: Mutex<u128>,
    pub k_recv: Mutex<u128>,
}

pub enum State {
    Reset,
    InitiationSent {
        local: u32, // local id assigned
        local_sid: SessionId,
        mode: u32,
        epoch: u64,
        eph_sk: StaticSecret,
        eph_sk_pq: oqs::kem::SecretKey,
        eph_pk_pq: [u8; SIZE_EPHEMERAL_KEM_PUB_KEY],
        rk: [u8; SIZE_HASH],
        k_ri: [u8; SIZE_HASH],
        ss_r: [u8; SIZE_HASH],

        hs: [u8; 32],
        ck: [u8; 32],
    },
}

impl Drop for State {
    fn drop(&mut self) {
        if let State::InitiationSent {
            hs,
            ck,
            rk,
            k_ri,
            ss_r,
            ..
        } = self
        {
            // eph_sk already cleared by dalek-x25519
            hs.clear();
            ck.clear();
            rk.clear();
            k_ri.clear();
            ss_r.clear();
        }
    }
}

#[derive(Clone)]
pub(super) struct InitiationRatchet {
    pub mode: u32,
    pub epoch: u64,
    pub rk: [u8; SIZE_HASH],
    pub k_ri: [u8; SIZE_HASH],
    pub remote_kid: [u8; SIZE_KID],
    pub remote_pub: Option<[u8; SIZE_RATCHET_KEM_PUB_KEY]>,
}

pub(super) struct ResponseRatchet {
    pub slot: ResponseRatchetSlot,
    pub mode: u32,
    pub epoch: u64,
    pub rk: [u8; SIZE_HASH],
    pub k_ri: [u8; SIZE_HASH],
    pub local_kid: Option<[u8; SIZE_KID]>,
    pub local_secret: Option<[u8; SIZE_RATCHET_KEM_SECRET_KEY]>,
}

#[derive(Clone, Copy)]
pub(super) enum ResponseRatchetSlot {
    Current,
    Pending,
}

struct PendingResponderRatchet {
    epoch: u64,
    rk: [u8; SIZE_HASH],
    k_ri: [u8; SIZE_HASH],
    local_kid: [u8; SIZE_KID],
    local_secret: [u8; SIZE_RATCHET_KEM_SECRET_KEY],
}

impl PendingResponderRatchet {
    fn clear(&mut self) {
        self.rk.clear();
        self.k_ri.clear();
        self.local_secret.clear();
    }
}

pub(super) struct RatchetState {
    pub epoch: u64,
    pub rk: [u8; SIZE_HASH],
    pub k_ri: [u8; SIZE_HASH],
    pub remote_kid: Option<[u8; SIZE_KID]>,
    pub remote_pub: Option<[u8; SIZE_RATCHET_KEM_PUB_KEY]>,
    pub local_kid: Option<[u8; SIZE_KID]>,
    pub local_secret: Option<[u8; SIZE_RATCHET_KEM_SECRET_KEY]>,
    pending_local: Option<PendingResponderRatchet>,
}

impl RatchetState {
    fn derive_root(
        label: &[u8],
        own_pk_hash: &[u8; SIZE_HASH],
        peer_pk_hash: &[u8; SIZE_HASH],
        psk: &Psk,
    ) -> [u8; SIZE_HASH] {
        if own_pk_hash <= peer_pk_hash {
            HASH!(label, own_pk_hash, peer_pk_hash, psk)
        } else {
            HASH!(label, peer_pk_hash, own_pk_hash, psk)
        }
    }

    pub fn new(own_pk_hash: &[u8; SIZE_HASH], peer_pk_hash: &[u8; SIZE_HASH], psk: &Psk) -> Self {
        Self {
            epoch: 0,
            rk: Self::derive_root(b"hybrid-wireguard-v2.3-rk", own_pk_hash, peer_pk_hash, psk),
            k_ri: Self::derive_root(b"hybrid-wireguard-v2.3-kri", own_pk_hash, peer_pk_hash, psk),
            remote_kid: None,
            remote_pub: None,
            local_kid: None,
            local_secret: None,
            pending_local: None,
        }
    }

    pub fn reset(
        &mut self,
        own_pk_hash: &[u8; SIZE_HASH],
        peer_pk_hash: &[u8; SIZE_HASH],
        psk: &Psk,
    ) {
        if let Some(mut secret) = self.local_secret.take() {
            secret.clear();
        }
        if let Some(mut pending) = self.pending_local.take() {
            pending.clear();
        }
        self.epoch = 0;
        self.rk = Self::derive_root(b"hybrid-wireguard-v2.3-rk", own_pk_hash, peer_pk_hash, psk);
        self.k_ri = Self::derive_root(b"hybrid-wireguard-v2.3-kri", own_pk_hash, peer_pk_hash, psk);
        self.remote_kid = None;
        self.remote_pub = None;
        self.local_kid = None;
    }

    pub fn initiation_snapshot(&self) -> InitiationRatchet {
        if let (Some(kid), Some(pubkey)) = (self.remote_kid, self.remote_pub) {
            InitiationRatchet {
                mode: MODE_RATCHET,
                epoch: self.epoch,
                rk: self.rk,
                k_ri: self.k_ri,
                remote_kid: kid,
                remote_pub: Some(pubkey),
            }
        } else {
            InitiationRatchet {
                mode: if self.epoch == 0 {
                    MODE_BOOTSTRAP
                } else {
                    MODE_RESYNC
                },
                epoch: self.epoch,
                rk: self.rk,
                k_ri: self.k_ri,
                remote_kid: [0u8; SIZE_KID],
                remote_pub: None,
            }
        }
    }

    pub fn response_snapshot(
        &self,
        mode: u32,
        epoch: u64,
        kid: &[u8; SIZE_KID],
    ) -> Result<ResponseRatchet, HandshakeError> {
        match mode {
            MODE_BOOTSTRAP => {
                if epoch != 0 || self.epoch != 0 {
                    return Err(HandshakeError::InvalidEpoch);
                }
                Ok(ResponseRatchet {
                    slot: ResponseRatchetSlot::Current,
                    mode,
                    epoch,
                    rk: self.rk,
                    k_ri: self.k_ri,
                    local_kid: None,
                    local_secret: None,
                })
            }
            MODE_RESYNC => {
                if epoch == self.epoch {
                    Ok(ResponseRatchet {
                        slot: ResponseRatchetSlot::Current,
                        mode,
                        epoch,
                        rk: self.rk,
                        k_ri: self.k_ri,
                        local_kid: None,
                        local_secret: None,
                    })
                } else if let Some(pending) = &self.pending_local {
                    if epoch != pending.epoch {
                        return Err(HandshakeError::InvalidEpoch);
                    }
                    Ok(ResponseRatchet {
                        slot: ResponseRatchetSlot::Pending,
                        mode,
                        epoch,
                        rk: pending.rk,
                        k_ri: pending.k_ri,
                        local_kid: Some(pending.local_kid),
                        local_secret: Some(pending.local_secret),
                    })
                } else {
                    Err(HandshakeError::InvalidEpoch)
                }
            }
            MODE_RATCHET => {
                if epoch == self.epoch {
                    let expected = self.local_kid.ok_or(HandshakeError::InvalidRatchetKid)?;
                    if expected != *kid {
                        return Err(HandshakeError::InvalidRatchetKid);
                    }
                    Ok(ResponseRatchet {
                        slot: ResponseRatchetSlot::Current,
                        mode,
                        epoch,
                        rk: self.rk,
                        k_ri: self.k_ri,
                        local_kid: Some(expected),
                        local_secret: self.local_secret,
                    })
                } else if let Some(pending) = &self.pending_local {
                    if epoch != pending.epoch {
                        return Err(HandshakeError::InvalidEpoch);
                    }
                    if pending.local_kid != *kid {
                        return Err(HandshakeError::InvalidRatchetKid);
                    }
                    Ok(ResponseRatchet {
                        slot: ResponseRatchetSlot::Pending,
                        mode,
                        epoch,
                        rk: pending.rk,
                        k_ri: pending.k_ri,
                        local_kid: Some(pending.local_kid),
                        local_secret: Some(pending.local_secret),
                    })
                } else {
                    Err(HandshakeError::InvalidEpoch)
                }
            }
            _ => Err(HandshakeError::InvalidMode),
        }
    }

    pub fn commit_initiator(
        &mut self,
        next_epoch: u64,
        next_pub: [u8; SIZE_RATCHET_KEM_PUB_KEY],
        next_kid: [u8; SIZE_KID],
        next_rk: [u8; SIZE_HASH],
        next_k_ri: [u8; SIZE_HASH],
    ) {
        self.epoch = next_epoch;
        self.rk = next_rk;
        self.k_ri = next_k_ri;
        self.remote_pub = Some(next_pub);
        self.remote_kid = Some(next_kid);
    }

    pub fn stage_responder(
        &mut self,
        accepted: &ResponseRatchet,
        next_epoch: u64,
        next_secret: [u8; SIZE_RATCHET_KEM_SECRET_KEY],
        next_kid: [u8; SIZE_KID],
        next_rk: [u8; SIZE_HASH],
        next_k_ri: [u8; SIZE_HASH],
    ) {
        if matches!(accepted.slot, ResponseRatchetSlot::Pending) {
            if let Some(mut old) = self.local_secret.take() {
                old.clear();
            }
            self.epoch = accepted.epoch;
            self.rk = accepted.rk;
            self.k_ri = accepted.k_ri;
            self.local_kid = accepted.local_kid;
            self.local_secret = accepted.local_secret;
            if let Some(mut pending) = self.pending_local.take() {
                pending.clear();
            }
        }

        if let Some(mut old) = self.pending_local.replace(PendingResponderRatchet {
            epoch: next_epoch,
            rk: next_rk,
            k_ri: next_k_ri,
            local_kid: next_kid,
            local_secret: next_secret,
        }) {
            old.clear();
        }
    }
}

impl<O> Peer<O> {
    /// Create a new Peer.
    ///
    /// - `pk` / `pk_pq`           : peer's DH and KEM public keys
    /// - `own_pk` / `own_pk_pq`   : this device's own DH and KEM public keys
    ///   (used to derive the macs_validator key = HASH(own_pk, own_pk_pq))
    /// - `ss`                     : pre-computed DH(own_sk, peer_pk)
    pub fn new(
        pk: PublicKey,
        pk_pq: oqs::kem::PublicKey,
        own_pk: &PublicKey,
        own_pk_pq: &oqs::kem::PublicKey,
        own_cookie_root_secret: &[u8; SIZE_HASH],
        ss: [u8; 32],
        opaque: O,
    ) -> Self {
        // mac1_key and cookie_key for the Generator (initiator side) are derived
        // from the PEER's combined public-key hash — this is the responder's identity,
        // which both parties can compute independently without a PSK.
        let peer_pk_hash: [u8; SIZE_HASH] = HASH!(pk.as_bytes(), pk_pq.as_ref());

        // The Validator (responder side) uses the DEVICE's own combined key hash,
        // which equals the initiator's peer_pk_hash when viewed from the other side.
        let own_pk_hash: [u8; SIZE_HASH] = HASH!(own_pk.as_bytes(), own_pk_pq.as_ref());
        let zero_psk = [0u8; 32];

        Self {
            opaque,
            // Generator uses peer (server) key hash — ensures cookie_key matches
            // the device_validator on the responder side.
            macs: Mutex::new(macs::Generator::new(&[0u8; 32], &peer_pk_hash)),
            // Validator uses own key hash — symmetrically matches the initiator's
            // Generator that was initialised with this device's public key hash.
            macs_validator: Mutex::new(macs::Validator::new(
                &[0u8; 32],
                &own_pk_hash,
                own_cookie_root_secret,
            )),
            state: Mutex::new(State::Reset),
            timestamp: Mutex::new(None),
            last_initiation_consumption: Mutex::new(None),
            ss,

            hash_static_pq_send: HASH!(own_pk_pq.as_ref(), pk_pq.as_ref()),
            hash_static_pq_recv: HASH!(pk_pq.as_ref(), own_pk_pq.as_ref()),
            h_id_send: HASH!(
                own_pk.as_bytes(),
                own_pk_pq.as_ref(),
                pk.as_bytes(),
                pk_pq.as_ref()
            ),
            h_id_recv: HASH!(
                pk.as_bytes(),
                pk_pq.as_ref(),
                own_pk.as_bytes(),
                own_pk_pq.as_ref()
            ),
            ratchet: Mutex::new(RatchetState::new(&own_pk_hash, &peer_pk_hash, &zero_psk)),
            psk: [0u8; 32],
            pk_hash: peer_pk_hash,
            own_pk_hash,
            pk,
            pk_pq,
            k_send: Mutex::new(0),
            k_recv: Mutex::new(0),
        }
    }

    pub fn set_psk(&mut self, psk: Psk) {
        // PSK is mixed exclusively into the Noise handshake key schedule.
        // mac1 / cookie keys are derived from static public keys (not PSK)
        // so that the responder can validate mac1 and send a CookieReply before
        // knowing the initiator's identity.
        self.macs.lock().set_mac1_key(&psk);
        self.macs_validator.lock().set_mac1_key(&psk);
        self.psk = psk;
        self.ratchet
            .lock()
            .reset(&self.own_pk_hash, &self.pk_hash, &self.psk);
    }

    pub fn reset_state(&self) -> Option<u32> {
        match mem::replace(&mut *self.state.lock(), State::Reset) {
            State::InitiationSent { local, .. } => Some(local),
            _ => None,
        }
    }

    /// Set the mutable state of the peer conditioned on the timestamp being newer
    ///
    /// # Arguments
    ///
    /// * st_new - The updated state of the peer
    /// * ts_new - The associated timestamp
    pub fn check_replay_flood(
        &self,
        device: &Device<O>,
        k_received: u128,
    ) -> Result<(), HandshakeError> {
        let mut state = self.state.lock();
        let mut k_recv_old = self.k_recv.lock();

        let mut last_initiation_consumption = self.last_initiation_consumption.lock();

        // check replay attack
        if k_received <= *k_recv_old {
            return Err(HandshakeError::OldTimestamp);
        }

        // check flood attack
        if let Some(last) = *last_initiation_consumption {
            if last.elapsed() < TIME_BETWEEN_INITIATIONS {
                return Err(HandshakeError::InitiationFlood);
            }
        }

        // reset state
        if let State::InitiationSent { local, .. } = *state {
            device.release(local)
        }

        // update replay & flood protection
        *state = State::Reset;
        *k_recv_old = k_received;
        *last_initiation_consumption = Some(Instant::now());
        Ok(())
    }
}
