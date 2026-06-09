use super::*;

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use hex;
use oqs::init;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};

use super::messages::{
    session_index, CookieReply, Initiation, Response, MODE_BOOTSTRAP, MODE_RATCHET, MODE_RESYNC,
};
use crate::wireguard_hybrid_new::handshake::crypto_params::{SIZE_HASH, STATIC_KEM_ALG};
use crate::wireguard_hybrid_new::handshake::types::HandshakeError;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

fn setup_devices<R: RngCore + CryptoRng, O: Default>(
    rng1: &mut R,
    rng2: &mut R,
    rng3: &mut R,
) -> (
    PublicKey,
    oqs::kem::PublicKey,
    [u8; SIZE_HASH],
    Device<O>,
    PublicKey,
    oqs::kem::PublicKey,
    [u8; SIZE_HASH],
    Device<O>,
) {
    // generate new key pairs

    let kemalg = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();

    let sk1 = StaticSecret::new(rng1);
    let pk1 = PublicKey::from(&sk1);
    let (pk1_pq, sk1_pq) = kemalg.keypair().unwrap();

    let hash1 = Device::<O>::hash_static_keys(&pk1, &pk1_pq);

    let sk2 = StaticSecret::new(rng2);
    let pk2 = PublicKey::from(&sk2);
    let (pk2_pq, sk2_pq) = kemalg.keypair().unwrap();

    let hash2 = Device::<O>::hash_static_keys(&pk2, &pk2_pq);

    // pick random psk

    let mut psk = [0u8; 32];
    rng3.fill_bytes(&mut psk[..]);

    // initialize devices on both ends

    let mut dev1 = Device::new();
    let mut dev2 = Device::new();

    dev1.set_sk(Some((sk1, sk1_pq, pk1_pq.clone())));
    dev2.set_sk(Some((sk2, sk2_pq, pk2_pq.clone())));

    dev1.add(&pk2, &pk2_pq, O::default()).unwrap();
    dev2.add(&pk1, &pk1_pq, O::default()).unwrap();

    dev1.set_psk(&hash2, psk).unwrap();
    dev2.set_psk(&hash1, psk).unwrap();

    (pk1, pk1_pq, hash1, dev1, pk2, pk2_pq, hash2, dev2)
}

fn wait() {
    thread::sleep(Duration::from_millis(20));
}

fn assert_transport_keys_match(
    initiator: &crate::wireguard_hybrid_new::types::KeyPair,
    responder: &crate::wireguard_hybrid_new::types::KeyPair,
) {
    assert!(initiator.initiator, "initiator key-pair is not confirmed");
    assert!(!responder.initiator, "responder key-pair is confirmed");
    assert_eq!(initiator.send, responder.recv, "KeyI.send != KeyR.recv");
    assert_eq!(initiator.recv, responder.send, "KeyI.recv != KeyR.send");
}

/* Test longest possible handshake interaction (7 messages):
 *
 * 1. I -> R (initiation)
 * 2. I <- R (cookie reply)
 * 3. I -> R (initiation)
 * 4. I <- R (response)
 * 5. I -> R (cookie reply)
 * 6. I -> R (initiation)
 * 7. I <- R (response)
 */
#[test]
fn handshake_under_load() {
    let (_pk1, pk1_pq, pk1_hash, dev1, pk2, pk2_pq, pk2_hash, dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let src1: SocketAddr = "172.16.0.1:8080".parse().unwrap();
    let src2: SocketAddr = "172.16.0.2:7070".parse().unwrap();
    dev2.gradient_dos_checker.update_global_cpu_usage(0.75);

    // 1. device-1 : create first initiation
    let msg_init = dev1.begin(&mut OsRng, &pk2_hash).unwrap();

    // 2. device-2 : responds with CookieReply
    let msg_cookie = match dev2.process(&mut OsRng, &msg_init, Some(src1)).unwrap() {
        (None, Some(msg), None) => msg,
        _ => panic!("unexpected response"),
    };

    // device-1 : processes CookieReply (no response)
    match dev1.process(&mut OsRng, &msg_cookie, Some(src2)).unwrap() {
        (None, None, None) => (),
        _ => panic!("unexpected response"),
    }

    // avoid initiation flood detection
    wait();

    // 3. device-1 : create second initiation
    let msg_init = dev1.begin(&mut OsRng, &pk2_hash).unwrap();

    // 4. device-2 : responds with noise response
    let msg_response = match dev2.process(&mut OsRng, &msg_init, Some(src1)).unwrap() {
        (Some(_), Some(msg), Some(kp)) => {
            assert_eq!(kp.initiator, false);
            msg
        }
        _ => panic!("unexpected response"),
    };

    // 5. device-1 : responds with CookieReply
    let msg_cookie = match dev1.process(&mut OsRng, &msg_response, Some(src2)).unwrap() {
        (None, Some(msg), None) => msg,
        _ => panic!("unexpected response"),
    };

    // device-2 : processes CookieReply (no response)
    match dev2.process(&mut OsRng, &msg_cookie, Some(src1)).unwrap() {
        (None, None, None) => (),
        _ => panic!("unexpected response"),
    }

    // avoid initiation flood detection
    wait();

    // 6. device-1 : create third initiation
    let msg_init = dev1.begin(&mut OsRng, &pk2_hash).unwrap();

    // 7. device-2 : responds with noise response
    let (msg_response, kp1) = match dev2.process(&mut OsRng, &msg_init, Some(src1)).unwrap() {
        (Some(_), Some(msg), Some(kp)) => {
            assert_eq!(kp.initiator, false);
            (msg, kp)
        }
        _ => panic!("unexpected response"),
    };

    // device-1 : process noise response
    let kp2 = match dev1.process(&mut OsRng, &msg_response, Some(src2)).unwrap() {
        (Some(_), None, Some(kp)) => {
            assert_eq!(kp.initiator, true);
            kp
        }
        _ => panic!("unexpected response"),
    };

    assert_eq!(kp1.send, kp2.recv);
    assert_eq!(kp1.recv, kp2.send);
}

#[test]
fn initiation_with_source_requires_cookie_before_expensive_processing() {
    let (_pk1, _pk1_pq, _pk1_hash, dev1, _pk2, _pk2_pq, pk2_hash, dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let src1: SocketAddr = "172.16.0.10:8080".parse().unwrap();
    let src2: SocketAddr = "172.16.0.20:7070".parse().unwrap();

    let msg_init = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let msg_cookie = match dev2.process(&mut OsRng, &msg_init, Some(src1)).unwrap() {
        (None, Some(msg), None) => msg,
        _ => panic!("initiation without cookie should only return CookieReply"),
    };
    CookieReply::parse(&msg_cookie[..]).expect("failed to parse CookieReply");

    match dev1.process(&mut OsRng, &msg_cookie, Some(src2)).unwrap() {
        (None, None, None) => (),
        _ => panic!("CookieReply should not produce a transport key"),
    }

    wait();

    let msg_init = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    match dev2.process(&mut OsRng, &msg_init, Some(src1)).unwrap() {
        (Some(_), Some(_), Some(kp)) => assert_eq!(kp.initiator, false),
        _ => panic!("initiation with valid cookie should produce a response"),
    }
}

#[test]
fn response_hash_tamper_fails() {
    let (_pk1, _pk1_pq, _pk1_hash, dev1, _pk2, _pk2_pq, pk2_hash, dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let msg1 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let (_, msg2, _) = dev2
        .process(&mut OsRng, &msg1, None)
        .expect("failed to process initiation");
    let mut msg2 = msg2.unwrap();

    {
        let mut parsed = Response::parse(&mut msg2[..]).expect("failed to parse response");
        parsed.noise.f_hash_ephemeral_pq[0] ^= 0x01;
    }

    let err = match dev1.process(&mut OsRng, &msg2, None) {
        Err(err) => err,
        Ok(_) => panic!("tampered response hash should fail"),
    };
    assert!(matches!(
        err,
        HandshakeError::DecryptionFailure | HandshakeError::InvalidMac1 | HandshakeError::InvalidTr
    ));
}

#[test]
fn handshake_message_sizes_reflect_v23_ratchet_payloads() {
    use std::mem;

    let initiation_len = mem::size_of::<Initiation>();
    let response_len = mem::size_of::<Response>();
    let cookie_len = mem::size_of::<CookieReply>();
    const IPV6_UDP_OVERHEAD: usize = 48;

    assert_eq!(initiation_len, 2004);
    assert_eq!(response_len, 2012);
    assert_eq!(cookie_len, 92);
    assert!(initiation_len + IPV6_UDP_OVERHEAD > 1280);
    assert!(response_len + IPV6_UDP_OVERHEAD > 1280);
    assert!(cookie_len + IPV6_UDP_OVERHEAD <= 1280);
}

#[test]
fn ratchet_retry_after_dropped_response_keeps_epoch_usable() {
    let (_pk1, _pk1_pq, _pk1_hash, mut dev1, _pk2, _pk2_pq, pk2_hash, dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let msg1 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let parsed1 = Initiation::parse(&msg1[..]).expect("failed to parse bootstrap initiation");
    assert_eq!(parsed1.noise.f_mode.get(), MODE_BOOTSTRAP);
    assert_eq!(parsed1.noise.f_epoch.get(), 0);

    let (_, msg2, ks_r0) = dev2
        .process(&mut OsRng, &msg1, None)
        .expect("failed to process bootstrap initiation");
    let msg2 = msg2.unwrap();
    let parsed2 = Response::parse(&msg2[..]).expect("failed to parse bootstrap response");
    assert_eq!(parsed2.noise.f_mode.get(), MODE_BOOTSTRAP);
    assert_eq!(parsed2.noise.f_epoch.get(), 0);

    let (_, _, ks_i0) = dev1
        .process(&mut OsRng, &msg2, None)
        .expect("failed to process bootstrap response");
    let ks_i0 = ks_i0.unwrap();
    let ks_r0 = ks_r0.unwrap();
    assert_transport_keys_match(&ks_i0, &ks_r0);
    dev1.release(ks_i0.local_id());
    dev2.release(ks_r0.local_id());

    wait();

    let msg3 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let parsed3 = Initiation::parse(&msg3[..]).expect("failed to parse first ratchet initiation");
    assert_eq!(parsed3.noise.f_mode.get(), MODE_RATCHET);
    assert_eq!(parsed3.noise.f_epoch.get(), 1);
    assert_ne!(parsed3.noise.f_ratchet_kid, [0u8; 16]);
    assert_ne!(parsed3.noise.f_ratchet_ct, [0u8; 768]);
    let dropped_sid = parsed3.noise.f_sender;
    let dropped_local = session_index(&dropped_sid);

    let (_, msg4, ks_r1) = dev2
        .process(&mut OsRng, &msg3, None)
        .expect("failed to process first ratchet initiation");
    let msg4 = msg4.unwrap();
    let parsed4 = Response::parse(&msg4[..]).expect("failed to parse dropped ratchet response");
    assert_eq!(parsed4.noise.f_mode.get(), MODE_RATCHET);
    assert_eq!(parsed4.noise.f_epoch.get(), 1);
    dev2.release(ks_r1.unwrap().local_id());
    dev1.release(dropped_local);

    wait();

    let msg5 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let parsed5 = Initiation::parse(&msg5[..]).expect("failed to parse ratchet retry");
    assert_eq!(parsed5.noise.f_mode.get(), MODE_RATCHET);
    assert_eq!(parsed5.noise.f_epoch.get(), 1);

    let (_, msg6, ks_r2) = dev2
        .process(&mut OsRng, &msg5, None)
        .expect("failed to process ratchet retry");
    let msg6 = msg6.unwrap();
    let (_, _, ks_i2) = dev1
        .process(&mut OsRng, &msg6, None)
        .expect("failed to process ratchet retry response");
    let ks_i2 = ks_i2.unwrap();
    let ks_r2 = ks_r2.unwrap();
    assert_transport_keys_match(&ks_i2, &ks_r2);
    dev1.release(ks_i2.local_id());
    dev2.release(ks_r2.local_id());
}

#[test]
fn resync_mode_recovers_after_forgetting_remote_ratchet_public_key() {
    let (_pk1, _pk1_pq, _pk1_hash, mut dev1, _pk2, _pk2_pq, pk2_hash, dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let msg1 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let (_, msg2, ks_r0) = dev2
        .process(&mut OsRng, &msg1, None)
        .expect("failed to process bootstrap initiation");
    let msg2 = msg2.unwrap();
    let (_, _, ks_i0) = dev1
        .process(&mut OsRng, &msg2, None)
        .expect("failed to process bootstrap response");
    let ks_i0 = ks_i0.unwrap();
    let ks_r0 = ks_r0.unwrap();
    assert_transport_keys_match(&ks_i0, &ks_r0);
    dev1.release(ks_i0.local_id());
    dev2.release(ks_r0.local_id());

    dev1.forget_remote_ratchet_for_test(&pk2_hash)
        .expect("failed to clear remote ratchet public key");

    wait();

    let msg3 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let parsed3 = Initiation::parse(&msg3[..]).expect("failed to parse resync initiation");
    assert_eq!(parsed3.noise.f_mode.get(), MODE_RESYNC);
    assert_eq!(parsed3.noise.f_epoch.get(), 1);
    assert_eq!(parsed3.noise.f_ratchet_kid, [0u8; 16]);
    assert_eq!(parsed3.noise.f_ratchet_ct, [0u8; 768]);

    let (_, msg4, ks_r1) = dev2
        .process(&mut OsRng, &msg3, None)
        .expect("failed to process resync initiation");
    let msg4 = msg4.unwrap();
    let parsed4 = Response::parse(&msg4[..]).expect("failed to parse resync response");
    assert_eq!(parsed4.noise.f_mode.get(), MODE_RESYNC);
    assert_eq!(parsed4.noise.f_epoch.get(), 1);

    let (_, _, ks_i1) = dev1
        .process(&mut OsRng, &msg4, None)
        .expect("failed to process resync response");
    let ks_i1 = ks_i1.unwrap();
    let ks_r1 = ks_r1.unwrap();
    assert_transport_keys_match(&ks_i1, &ks_r1);
    dev1.release(ks_i1.local_id());
    dev2.release(ks_r1.local_id());

    wait();

    let msg5 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let parsed5 = Initiation::parse(&msg5[..]).expect("failed to parse post-resync initiation");
    assert_eq!(parsed5.noise.f_mode.get(), MODE_RATCHET);
    assert_eq!(parsed5.noise.f_epoch.get(), 2);
    let sid = parsed5.noise.f_sender;
    dev1.release(session_index(&sid));
}

#[test]
fn handshake_uses_full_32_byte_session_ids() {
    let (_pk1, _pk1_pq, _pk1_hash, dev1, _pk2, _pk2_pq, pk2_hash, dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let msg1 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    let parsed1 = Initiation::parse(&msg1[..]).expect("failed to parse initiation");
    assert_eq!(parsed1.noise.f_sender.len(), 32);
    assert_ne!(parsed1.noise.f_sender, [0u8; 32]);

    let (_, msg2, _) = dev2
        .process(&mut OsRng, &msg1, None)
        .expect("failed to process initiation");
    let msg2 = msg2.unwrap();
    let parsed2 = Response::parse(&msg2[..]).expect("failed to parse response");
    assert_eq!(parsed2.noise.f_sender.len(), 32);
    assert_eq!(parsed2.noise.f_receiver.len(), 32);
    assert_ne!(parsed2.noise.f_sender, [0u8; 32]);
    assert_eq!(parsed2.noise.f_receiver, parsed1.noise.f_sender);
    assert_ne!(parsed2.noise.f_hash_ephemeral_pq, [0u8; 32]);
}

#[test]
fn initiation_encrypted_identity_tamper_fails() {
    let (_pk1, _pk1_pq, _pk1_hash, dev1, _pk2, _pk2_pq, pk2_hash, dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    let mut msg1 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
    {
        let mut parsed = Initiation::parse(&mut msg1[..]).expect("failed to parse initiation");
        parsed.noise.f_identity[0] ^= 0x01;
    }

    let err = match dev2.process(&mut OsRng, &msg1, None) {
        Err(err) => err,
        Ok(_) => panic!("tampered encrypted identity should fail"),
    };
    assert!(matches!(
        err,
        HandshakeError::DecryptionFailure | HandshakeError::InvalidMac1
    ));
}

#[test]
fn handshake_no_load() {
    let (pk1, pk1_pq, pk1_hash, mut dev1, pk2, pk2_pq, pk2_hash, mut dev2): (
        _,
        _,
        _,
        Device<usize>,
        _,
        _,
        _,
        _,
    ) = setup_devices(&mut OsRng, &mut OsRng, &mut OsRng);

    // do a few handshakes (every handshake should succeed)

    for i in 0..10 {
        println!("handshake : {}", i);

        // create initiation

        let msg1 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();

        println!("msg1 = {} : {} bytes", hex::encode(&msg1[..]), msg1.len());
        println!(
            "msg1 = {:?}",
            Initiation::parse(&msg1[..]).expect("failed to parse initiation")
        );

        // process initiation and create response

        let (_, msg2, ks_r) = dev2
            .process(&mut OsRng, &msg1, None)
            .expect("failed to process initiation");

        let ks_r = ks_r.unwrap();
        let msg2 = msg2.unwrap();

        println!("msg2 = {} : {} bytes", hex::encode(&msg2[..]), msg2.len());
        println!(
            "msg2 = {:?}",
            Response::parse(&msg2[..]).expect("failed to parse response")
        );

        assert!(!ks_r.initiator, "Responders key-pair is confirmed");

        // process response and obtain confirmed key-pair

        let (_, msg3, ks_i) = dev1
            .process(&mut OsRng, &msg2, None)
            .expect("failed to process response");
        let ks_i = ks_i.unwrap();

        assert!(msg3.is_none(), "Returned message after response");
        assert!(ks_i.initiator, "Initiators key-pair is not confirmed");

        assert_eq!(ks_i.send, ks_r.recv, "KeyI.send != KeyR.recv");
        assert_eq!(ks_i.recv, ks_r.send, "KeyI.recv != KeyR.send");

        dev1.release(ks_i.local_id());
        dev2.release(ks_r.local_id());

        // avoid initiation flood detection
        wait();
    }

    dev1.remove(&pk2_hash).unwrap();
    dev2.remove(&pk1_hash).unwrap();
}
