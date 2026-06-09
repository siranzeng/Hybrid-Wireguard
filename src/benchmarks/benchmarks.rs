use crate::wireguard::benchs::benchmark_original_handshake;
use crate::wireguard_hybrid::benchs::benchmark_hybrid_handshake;
use crate::wireguard_hybrid_new::benchs::benchmark_hybrid_new_handshake;
use crate::wireguard_pq_star::benchs::benchmark_pq_star_handshake;
use std::time::Instant;

pub fn test_kem_timings(alg: oqs::kem::Algorithm) {
    let kemalg = oqs::kem::Kem::new(alg).unwrap();

    let mut total_keygen = 0;
    let mut total_encaps = 0;
    let mut total_decaps = 0;
    let nb_iter = 10;

    for i in 0..nb_iter {
        let now = Instant::now();
        let (pk, sk) = kemalg.keypair().unwrap();
        total_keygen += now.elapsed().as_millis();

        let now = Instant::now();
        let (ct, shk) = kemalg.encapsulate(&pk).unwrap();
        total_encaps += now.elapsed().as_millis();

        let now = Instant::now();
        let shk2 = kemalg.decapsulate(&sk, &ct).unwrap();
        total_decaps += now.elapsed().as_millis();
    }
    println!("{:?}:", alg);
    println!("key gen time: {} ms", total_keygen / nb_iter);
    println!("encaps time: {} ms", total_encaps / nb_iter);
    println!("decaps gen time: {} ms", total_decaps / nb_iter);
}

pub fn wireguard_benchmarks(nb_executions: u32) {
    println!("\n################################################################");
    println!("\nAverage time over {nb_executions} executions\n");

    #[cfg(feature = "hybrid_new")]
    {
        println!("############ NEW Hybrid WireGuard (V2.3 + DoS) ############");
        benchmark_hybrid_new_handshake(nb_executions);
        println!("\n################################################################");
        return;
    }

    #[cfg(feature = "hybrid")]
    {
        println!("############ Hybrid WireGuard (V1) ############");
        benchmark_hybrid_handshake(nb_executions);
        println!("\n################################################################");
        return;
    }

    #[cfg(feature = "post_quantum")]
    {
        println!("############ Post-Quantum (PQ-Star) ############");
        benchmark_pq_star_handshake(nb_executions);
        println!("\n################################################################");
        return;
    }

    println!("############ Original WireGuard ############");
    benchmark_original_handshake(nb_executions);
    println!("");

    println!("############ Post-Quantum (PQ-Star) ############");
    benchmark_pq_star_handshake(nb_executions);
    println!("");

    println!("############ Hybrid WireGuard (V1) ############");
    benchmark_hybrid_handshake(nb_executions);
    println!("");

    println!("############ NEW Hybrid WireGuard (V2 + DoS) ############");
    benchmark_hybrid_new_handshake(nb_executions);
    println!("\n################################################################");

    // test_kem_timings(oqs::kem::Algorithm::ClassicMcEliece348864);
    // test_kem_timings(oqs::kem::Algorithm::ClassicMcEliece460896);

    // test_kem_timings(oqs::kem::Algorithm::ClassicMcEliece348864);
    // test_kem_timings(oqs::kem::Algorithm::Kyber512);
    //
    // let kemalg = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece460896).unwrap();
    //
    // let (pk, sk) = kemalg.keypair().unwrap();
    // let (ct, shk) = kemalg.encapsulate(&pk).unwrap();
    //
    // let bytes_pq = pk.as_ref();
    // let test_pk = kemalg.public_key_from_bytes(&bytes_pq).unwrap().to_owned();
    //
    // let bytes_ct = ct.as_ref();
    // let test_ct = kemalg.ciphertext_from_bytes(&bytes_ct).unwrap().to_owned();
    //
    // let test_shk = kemalg.decapsulate(&sk, &ct).unwrap();
    // println!("{}", test_shk.eq(& shk));
    //
    // println!("{}", pk.eq(& test_pk));
    //
    // println!("{}", ct.eq(& test_ct));
    //
    //
    // println!("pk_size: {}", kemalg.length_public_key());
    // println!("sk_size: {}", kemalg.length_secret_key());
    // println!("ct_size: {}", kemalg.length_ciphertext());
    //
    // println!("shk_size: {}", kemalg.length_shared_secret());
}
