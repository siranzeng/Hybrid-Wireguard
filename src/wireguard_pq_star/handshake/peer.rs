use spin::Mutex;
use std::convert::TryFrom;

use std::mem;
use std::time::{Duration, Instant};

use generic_array::typenum::U32;
use generic_array::GenericArray;

use clear_on_drop::clear::Clear;

use super::device::Device;
use super::macs;
use super::timestamp;
use super::types::*;

use blake2::Blake2s;

use crate::wireguard_pq_star::handshake::crypto_params::{
    HASH, SIZE_HASH, SIZE_STATIC_KEM_PUB_KEY,
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
    pub psk: Psk,                   // psk of peer
    pub pk_pq: oqs::kem::PublicKey, // static KEM public key
    pub pk_hash: [u8; SIZE_HASH],

    pub hash_static_pq_send: [u8; SIZE_HASH],
    pub hash_static_pq_recv: [u8; SIZE_HASH],

    // replacement of the time-based anti-replay (timestamp),
    // using an unsigned integer counter
    pub k_send: Mutex<u128>,
    pub k_recv: Mutex<u128>,
}

pub enum State {
    Reset,
    InitiationSent {
        local: u32, // local id assigned
        eph_sk_pq: oqs::kem::SecretKey,
        hs: GenericArray<u8, U32>,
        ck: GenericArray<u8, U32>,
    },
}

impl Drop for State {
    fn drop(&mut self) {
        if let State::InitiationSent { hs, ck, .. } = self {
            // eph_sk already cleared by dalek-x25519
            hs.clear();
            ck.clear();
        }
    }
}

impl<O> Peer<O> {
    pub fn new(pk_pq: oqs::kem::PublicKey, own_pk_pq: &oqs::kem::PublicKey, opaque: O) -> Self {
        Self {
            opaque,
            macs: Mutex::new(macs::Generator::new(&[0u8; 32])),
            macs_validator: Mutex::new(macs::Validator::new(&[0u8; 32])),
            state: Mutex::new(State::Reset),
            timestamp: Mutex::new(None),
            last_initiation_consumption: Mutex::new(None),
            hash_static_pq_send: HASH!(
                <[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(own_pk_pq.as_ref()).unwrap(),
                <[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(pk_pq.as_ref()).unwrap()
            )
            .into(),
            hash_static_pq_recv: HASH!(
                <[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(pk_pq.as_ref()).unwrap(),
                <[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(own_pk_pq.as_ref()).unwrap()
            )
            .into(),
            psk: [0u8; 32],
            pk_hash: HASH!(<[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(pk_pq.as_ref()).unwrap())
                .into(),
            pk_pq: pk_pq,
            k_send: Mutex::new(0),
            k_recv: Mutex::new(0),
        }
    }

    pub fn set_psk(&mut self, psk: Psk) {
        self.psk = psk;
        self.macs = Mutex::new(macs::Generator::new(&self.psk));
        self.macs_validator = Mutex::new(macs::Validator::new(&self.psk));
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
        //println!("K_RECEIVED = {k_received}, K_RECV_OLD = {k_recv_old}");

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
