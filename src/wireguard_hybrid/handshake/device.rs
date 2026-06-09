use byteorder::{ByteOrder, LittleEndian};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::collections::hash_map;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;
use zerocopy::AsBytes;

use rand::Rng;
use rand_core::{CryptoRng, RngCore};

use clear_on_drop::clear::Clear;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use super::macs;
use super::messages::{CookieReply, Initiation, Response};
use super::messages::{TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE};
use super::noise;
use super::peer::Peer;
use super::ratelimiter::RateLimiter;
use super::types::*;

use super::crypto_params::*;

const MAX_PEER_PER_DEVICE: usize = 1 << 20;

// HASH
use blake2::Blake2s;

pub struct KeyState {
    pub(super) sk: StaticSecret,           // static secret key
    pub(super) pk: PublicKey,              // static public key
    pub(super) sk_pq: oqs::kem::SecretKey, // static secret key
    pub(super) pk_pq: oqs::kem::PublicKey, // static public key
    pub(super) pk_hash: [u8; SIZE_HASH],   // public keys hash
                                           // macs: macs::Validator,       // validator for the mac fields
}

/// The device is generic over an "opaque" type
/// which can be used to associate the public key with this value.
/// (the instance is a Peer object in the parent module)
pub struct Device<O> {
    keyst: Option<KeyState>,
    id_map: DashMap<u32, [u8; SIZE_HASH]>, // concurrent map
    pk_map: HashMap<[u8; SIZE_HASH], Peer<O>>,
    limiter: Mutex<RateLimiter>,
}

pub struct Iter<'a, O> {
    iter: hash_map::Iter<'a, [u8; SIZE_HASH], Peer<O>>,
}

impl<'a, O> Iterator for Iter<'a, O> {
    type Item = (&'a [u8; SIZE_HASH], &'a O);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(pk_hash, peer)| (pk_hash, &peer.opaque))
    }
}

/* These methods enable the Device to act as a map
 * from public keys to the set of contained opaque values.
 *
 * It also abstracts away the problem of PublicKey not being hashable.
 */
impl<O> Device<O> {
    pub fn clear(&mut self) {
        self.id_map.clear();
        self.pk_map.clear();
    }

    pub fn hash_static_keys(pk: &PublicKey, pk_pq: &oqs::kem::PublicKey) -> [u8; SIZE_HASH] {
        HASH!(
            pk.as_bytes(),
            <[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(pk_pq.as_ref()).unwrap()
        )
        .into()
    }

    pub fn len(&self) -> usize {
        self.pk_map.len()
    }

    /// Enables enumeration of (public key, opaque) pairs
    /// without exposing internal peer type.
    pub fn iter(&self) -> Iter<O> {
        Iter {
            iter: self.pk_map.iter(),
        }
    }

    /// Enables lookup by public key without exposing internal peer type.
    pub fn get(&self, pk_hash: &[u8; SIZE_HASH]) -> Option<&O> {
        self.pk_map.get(pk_hash).map(|peer| &peer.opaque)
    }

    pub fn contains_key(&self, pk_hash: &[u8; SIZE_HASH]) -> bool {
        self.pk_map.contains_key(pk_hash)
    }
}

/* A mutable reference to the device needs to be held during configuration.
 * Wrapping the device in a RwLock enables peer config after "configuration time"
 */
impl<O> Device<O> {
    /// Initialize a new handshake state machine
    pub fn new() -> Device<O> {
        Device {
            keyst: None,
            id_map: DashMap::new(),
            pk_map: HashMap::new(),
            limiter: Mutex::new(RateLimiter::new()),
        }
    }

    fn update_ss(&mut self) -> (Vec<u32>, Option<[u8; SIZE_HASH]>) {
        let mut same = None;
        let mut ids = Vec::with_capacity(self.pk_map.len());
        for (pk_hash, peer) in self.pk_map.iter_mut() {
            if let Some(key) = self.keyst.as_ref() {
                if &key.pk_hash == pk_hash {
                    same = Some(pk_hash.clone());
                    peer.ss.clear()
                } else {
                    let pk = peer.pk;
                    peer.ss = *key.sk.diffie_hellman(&pk).as_bytes();
                }
            } else {
                peer.ss.clear();
            }
            if let Some(id) = peer.reset_state() {
                ids.push(id)
            }
        }

        (ids, same)
    }

    /// Update the secret key of the device
    ///
    /// # Arguments
    ///
    /// * `sk` - (x25519 scalar representing the local private key, the kem secret key, the kem public key)
    pub fn set_sk(&mut self, sk: Option<(StaticSecret, oqs::kem::SecretKey, oqs::kem::PublicKey)>) {
        // update secret and public key
        self.keyst = sk.map(|sk| {
            let pk = PublicKey::from(&sk.0);
            // let macs = macs::Validator::new(&pk, &sk.2);

            KeyState {
                pk,
                pk_hash: Device::<O>::hash_static_keys(&pk, &sk.2),
                sk: sk.0,
                sk_pq: sk.1,
                pk_pq: sk.2,
                // macs,
            }
        });

        // recalculate / erase the shared secrets for every peer
        let (ids, same) = self.update_ss();

        // release ids from aborted handshakes
        for id in ids {
            self.release(id)
        }

        // if we found a peer matching the device public key
        // remove it and return its value to the caller
        same.map(|pk_hash| {
            self.pk_map.remove(&pk_hash);
        });
    }

    /// Return the secret key of the device
    ///
    /// # Returns
    ///
    /// The secret keys (x25519 scalar, kem secret key)
    pub fn get_sk(&self) -> Option<(&StaticSecret, &oqs::kem::SecretKey, &oqs::kem::PublicKey)> {
        self.keyst
            .as_ref()
            .map(|key| (&key.sk, &key.sk_pq, &key.pk_pq))
    }

    /// Add a new public key to the state machine
    /// To remove public keys, you must create a new machine instance
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key to add
    /// * `pk_pq` - The PQ public key to add
    /// * `identifier` - Associated identifier which can be used to distinguish the peers
    pub fn add(
        &mut self,
        pk: &PublicKey,
        pk_pq: &oqs::kem::PublicKey,
        opaque: O,
    ) -> Result<(), ConfigError> {
        // ensure less than 2^20 peers
        if self.pk_map.len() > MAX_PEER_PER_DEVICE {
            return Err(ConfigError::new("Too many peers for device"));
        }

        let pk_hash = Device::<O>::hash_static_keys(pk, pk_pq);
        // error if public key matches device
        if let Some(key) = self.keyst.as_ref() {
            if &pk_hash == &key.pk_hash {
                return Err(ConfigError::new("Public key of peer matches the device"));
            }
        }

        // pre-compute shared secret and add to pk_map
        self.pk_map.insert(
            pk_hash,
            Peer::new(
                pk.clone(),
                pk_pq.clone(),
                &self.keyst.as_ref().unwrap().pk_pq,
                self.keyst
                    .as_ref()
                    .map(|key| *key.sk.diffie_hellman(pk).as_bytes())
                    .unwrap_or([0u8; 32]),
                opaque,
            ),
        );

        Ok(())
    }

    /// Remove a peer by public key
    /// To remove public keys, you must create a new machine instance
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer to remove
    /// * `pk_pq` - The PQ public key of the peer to remove
    ///
    /// # Returns
    ///
    /// The call might fail if the public key is not found
    pub fn remove(&mut self, pk_hash: &[u8; SIZE_HASH]) -> Result<(), ConfigError> {
        // remove the peer
        self.pk_map
            .remove(pk_hash)
            .ok_or_else(|| ConfigError::new("Public key not in device"))?;

        // remove every id entry for the peer in the public key map
        // O(n) operations, however it is rare: only when removing peers.
        self.id_map.retain(|_, v| v != pk_hash);
        Ok(())
    }

    /// Add a psk to the peer
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer
    /// * `pk_pq` - The PQ public key of the peer
    /// * `psk` - The psk to set / unset
    ///
    /// # Returns
    ///
    /// The call might fail if the public key is not found
    pub fn set_psk(&mut self, pk_hash: &[u8; SIZE_HASH], psk: Psk) -> Result<(), ConfigError> {
        match self.pk_map.get_mut(pk_hash) {
            Some(mut peer) => {
                peer.set_psk(psk);
                // peer.psk = psk;
                Ok(())
            }
            _ => Err(ConfigError::new("No such public key")),
        }
    }

    /// Return the psk for the peer
    ///
    /// # Arguments
    ///
    /// * `pk` - The public key of the peer
    /// * `pk_pq` - The PQ public key of the peer
    ///
    /// # Returns
    ///
    /// A 32 byte array holding the PSK
    ///
    /// The call might fail if the public key is not found
    pub fn get_psk(&self, pk: &[u8; SIZE_HASH]) -> Result<Psk, ConfigError> {
        match self.pk_map.get(pk) {
            Some(peer) => Ok(peer.psk),
            _ => Err(ConfigError::new("No such public key")),
        }
    }

    /// Release an id back to the pool
    ///
    /// # Arguments
    ///
    /// * `id` - The (sender) id to release
    pub fn release(&self, id: u32) {
        let old = self.id_map.remove(&id);
        assert!(old.is_some(), "released id not allocated");
    }

    /// Begin a new handshake
    ///
    /// # Arguments
    ///
    /// * `pk`    - Public key of peer to initiate handshake for
    /// * `pk_pq` - PQ Public key of peer to initiate handshake for
    pub fn begin<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pk_hash: &[u8; SIZE_HASH],
    ) -> Result<Vec<u8>, HandshakeError> {
        match (self.keyst.as_ref(), self.pk_map.get(pk_hash)) {
            (_, None) => Err(HandshakeError::UnknownPublicKey),
            (None, _) => Err(HandshakeError::UnknownPublicKey),
            (Some(keyst), Some(peer)) => {
                let local = self.allocate(rng, peer.pk_hash.clone());
                let mut msg = Initiation::default();

                // create noise part of initation
                noise::create_initiation(rng, keyst, peer, local, &mut msg.noise)?;

                // add macs to initation
                peer.macs
                    .lock()
                    .generate(msg.noise.as_bytes(), &mut msg.macs);

                Ok(msg.as_bytes().to_owned())
            }
        }
    }

    /// Process a handshake message.
    ///
    /// # Arguments
    ///
    /// * `msg` - Byte slice containing the message (untrusted input)
    pub fn process<'a, R: RngCore + CryptoRng>(
        &'a self,
        rng: &mut R,             // rng instance to sample randomness from
        msg: &[u8],              // message buffer
        src: Option<SocketAddr>, // optional source endpoint, set when "under load"
    ) -> Result<Output<'a, O>, HandshakeError> {
        // ensure type read in-range
        if msg.len() < 4 {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        // obtain reference to key state
        // if no key is configured return a noop.
        let keyst = match self.keyst.as_ref() {
            Some(key) => key,
            None => {
                return Ok((None, None, None));
            }
        };

        // de-multiplex the message type field
        match LittleEndian::read_u32(msg) {
            TYPE_INITIATION => {
                // parse message
                let msg = Initiation::parse(msg)?;

                // check mac1 field
                // let now = Instant::now();
                // consume the initiation (first part)
                let (peer, pk_hash, st_intermediate) =
                    noise::consume_initiation_first_part(self, keyst, &msg.noise)?;
                peer.macs_validator
                    .lock()
                    .check_mac1(msg.noise.as_bytes(), &msg.macs)?;
                // keyst.macs.check_mac1(msg.noise.as_bytes(), &msg.macs)?;
                // println!("time for checking mac1 = {} ms", now.elapsed().as_secs_f64() * 1000.0);

                // address validation & DoS mitigation
                if let Some(src) = src {
                    // check mac2 field
                    if !peer
                        .macs_validator
                        .lock()
                        .check_mac2(msg.noise.as_bytes(), &src, &msg.macs)
                    {
                        let mut reply = Default::default();
                        peer.macs_validator.lock().create_cookie_reply(
                            rng,
                            msg.noise.f_sender.get(),
                            &src,
                            &msg.macs,
                            &mut reply,
                        );
                        return Ok((None, Some(reply.as_bytes().to_owned()), None));
                    }

                    // check ratelimiter
                    if !self.limiter.lock().unwrap().allow(&src.ip()) {
                        return Err(HandshakeError::RateLimited);
                    }
                }

                // consume the initiation (second part)
                // let now = Instant::now();
                let st =
                    noise::consume_initiation_second_part(self, &msg.noise, st_intermediate, peer)?;
                // let t = now.elapsed().as_secs_f64() * 1000.0;
                // println!("time for init process = {t} ms");

                // allocate new index for response
                let local = self.allocate(rng, pk_hash);

                // prepare memory for response, TODO: take slice for zero allocation
                let mut resp = Response::default();

                // create response (release id on error)
                let keys =
                    noise::create_response(rng, peer, local, st, &mut resp.noise).map_err(|e| {
                        self.release(local);
                        e
                    })?;

                // add macs to response
                peer.macs
                    .lock()
                    .generate(resp.noise.as_bytes(), &mut resp.macs);

                // return unconfirmed keypair and the response as vector
                Ok((
                    Some(&peer.opaque),
                    Some(resp.as_bytes().to_owned()),
                    Some(keys),
                ))
            }
            TYPE_RESPONSE => {
                let msg = Response::parse(msg)?;

                // check mac1 field
                // retrieve peer and copy initiation state
                let peer = self.lookup_id(msg.noise.f_receiver.get())?;
                peer.macs_validator
                    .lock()
                    .check_mac1(msg.noise.as_bytes(), &msg.macs)?;

                // address validation & DoS mitigation
                if let Some(src) = src {
                    // check mac2 field
                    if !peer
                        .macs_validator
                        .lock()
                        .check_mac2(msg.noise.as_bytes(), &src, &msg.macs)
                    {
                        let mut reply = Default::default();
                        peer.macs_validator.lock().create_cookie_reply(
                            rng,
                            msg.noise.f_sender.get(),
                            &src,
                            &msg.macs,
                            &mut reply,
                        );
                        return Ok((None, Some(reply.as_bytes().to_owned()), None));
                    }

                    // check ratelimiter
                    if !self.limiter.lock().unwrap().allow(&src.ip()) {
                        return Err(HandshakeError::RateLimited);
                    }
                }

                // consume inner playload
                noise::consume_response(keyst, &msg.noise, peer)
            }
            TYPE_COOKIE_REPLY => {
                let msg = CookieReply::parse(msg)?;

                // lookup peer
                let peer = self.lookup_id(msg.f_receiver.get())?;

                // validate cookie reply
                peer.macs.lock().process(&msg)?;

                // this prompts no new message and
                // DOES NOT cryptographically verify the peer
                Ok((None, None, None))
            }
            _ => Err(HandshakeError::InvalidMessageFormat),
        }
    }

    // Internal function
    //
    // Return the peer associated with the public key
    pub(super) fn lookup_pk(&self, pk_hash: &[u8; SIZE_HASH]) -> Result<&Peer<O>, HandshakeError> {
        self.pk_map
            .get(pk_hash)
            .ok_or(HandshakeError::UnknownPublicKey)
    }

    // Internal function
    //
    // Return the peer currently associated with the receiver identifier
    pub(super) fn lookup_id(&self, id: u32) -> Result<&Peer<O>, HandshakeError> {
        // obtain a read reference to entry in the id_map
        let hpk = self
            .id_map
            .get(&id)
            .ok_or(HandshakeError::UnknownReceiverId)?;

        // lookup the public key from the pk map
        match self.pk_map.get(hpk.as_bytes()) {
            Some(peer) => Ok(peer),
            _ => unreachable!(),
        }
    }

    // Internal function
    //
    // Allocated a new receiver identifier for the peer.
    // Implemented via rejection sampling.
    fn allocate<R: RngCore + CryptoRng>(&self, rng: &mut R, pk_hash: [u8; SIZE_HASH]) -> u32 {
        loop {
            let id = rng.gen();

            // read lock the shard and do quick check
            if self.id_map.contains_key(&id) {
                continue;
            }

            // write lock the shard and insert
            if let Entry::Vacant(entry) = self.id_map.entry(id) {
                entry.insert(pk_hash);
                return id;
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    proptest! {
        #[test]
        fn unique_shared_secrets(sk_bs: [u8; SIZE_X25519_POINT], pk1_bs: [u8; SIZE_X25519_POINT], pk2_bs: [u8; SIZE_X25519_POINT]) {

            let sk = StaticSecret::from(sk_bs);
            let pk1 = PublicKey::from(pk1_bs);
            let pk2 = PublicKey::from(pk2_bs);
            assert_eq!(pk1.as_bytes(), &pk1_bs);
            assert_eq!(pk2.as_bytes(), &pk2_bs);

            let kemalg = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
            let (pk_pq, sk_pq) = kemalg.keypair().unwrap();
            let (pk1_pq, sk1_pq) = kemalg.keypair().unwrap();
            let (pk2_pq, sk2_pq) = kemalg.keypair().unwrap();

            let mut dev : Device<u32> = Device::new();
            dev.set_sk(Some((sk, sk_pq, pk_pq)));

            let hash1 = Device::<u32>::hash_static_keys(&pk1, &pk1_pq);

            dev.add(&pk1, &pk1_pq, 1).unwrap();
            if dev.add(&pk2, &pk2_pq, 0).is_err() {
                assert_eq!(pk1_bs, pk2_bs);
                assert_eq!(*dev.get(&hash1).unwrap(), 1);
            }


            // every shared secret is unique
            let mut ss: HashSet<[u8; 32]> = HashSet::new();
            for peer in dev.pk_map.values() {
                ss.insert(peer.ss);
            }
            assert_eq!(ss.len(), dev.len());
        }
    }
}
