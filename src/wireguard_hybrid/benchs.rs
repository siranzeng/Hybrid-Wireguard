use crate::wireguard_hybrid::handshake::crypto_params::{
    EPHEMERAL_KEM_ALG, SIZE_HASH, STATIC_KEM_ALG,
};
use crate::wireguard_hybrid::handshake::Device;
use meansd::MeanSD;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::thread;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

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

pub fn benchmark_hybrid_handshake(nb_iter: u32) {
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

    println!(
        "Hybrid-WireGuard: (static kem: {:?}, ephemeral kem: {:?})",
        STATIC_KEM_ALG, EPHEMERAL_KEM_ALG
    );

    let mut meansd_init = MeanSD::default();
    let mut meansd_resp = MeanSD::default();

    let mut init_size: Vec<usize> = Vec::new();
    let mut resp_size: Vec<usize> = Vec::new();

    for i in 0..nb_iter {
        // create initiation

        let now = Instant::now();
        let msg1 = dev1.begin(&mut OsRng, &pk2_hash).unwrap();
        let t = now.elapsed().as_secs_f64() * 1000.0;
        meansd_init.update(t);

        init_size.push(msg1.len());

        // process initiation and create response

        let now = Instant::now();
        let (_, msg2, ks_r) = dev2
            .process(&mut OsRng, &msg1, None)
            .expect("failed to process initiation");
        let t = now.elapsed().as_secs_f64() * 1000.0;
        meansd_resp.update(t);

        let ks_r = ks_r.unwrap();
        let msg2 = msg2.unwrap();

        resp_size.push(msg2.len());

        // process response and obtain confirmed key-pair

        let (_, msg3, ks_i) = dev1
            .process(&mut OsRng, &msg2, None)
            .expect("failed to process response");
        let ks_i = ks_i.unwrap();

        dev1.release(ks_i.local_id());
        dev2.release(ks_r.local_id());

        // avoid initiation flood detection
        wait();
    }

    for e in &init_size {
        assert_eq!(e, &init_size[0]);
    }
    for e in &resp_size {
        assert_eq!(e, &resp_size[0]);
    }

    dev1.remove(&pk2_hash).unwrap();
    dev2.remove(&pk1_hash).unwrap();

    println!(
        "InitHello message size: {:?} bytes\nRespHello message size: {:?} bytes",
        init_size[0] + 48,
        resp_size[0] + 48
    );

    println!(
        "InitHello construction time: {:.3} ms (std = {:.3} ms)",
        meansd_init.mean(),
        meansd_init.sstdev()
    );
    println!(
        "InitHello consumption time + RespHello construction time: {:.3} ms (std = {:.3} ms)",
        meansd_resp.mean(),
        meansd_resp.sstdev()
    );
}
