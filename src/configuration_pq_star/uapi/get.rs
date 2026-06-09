use super::Configuration;
use crate::wireguard_hybrid::handshake::crypto_params::{
    SIZE_STATIC_KEM_PUB_KEY, SIZE_STATIC_KEM_SECRET_KEY,
};
use std::convert::TryFrom;
use std::io;

pub fn serialize<C: Configuration, W: io::Write>(writer: &mut W, config: &C) -> io::Result<()> {
    let mut write = |key: &'static str, value: String| {
        debug_assert!(value.is_ascii());
        debug_assert!(key.is_ascii());
        log::trace!("UAPI: return : {}={}", key, value);
        writer.write_all(key.as_ref())?;
        writer.write_all(b"=")?;
        writer.write_all(value.as_ref())?;
        writer.write_all(b"\n")
    };

    // serialize interface
    config.get_private_key().map(|sk| {
        let bytes_sk_pq = <[u8; SIZE_STATIC_KEM_SECRET_KEY]>::try_from(sk.0.as_ref()).unwrap();
        let bytes_pk_pq = <[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(sk.1.as_ref()).unwrap();

        let mut concat_pk = [0u8; SIZE_STATIC_KEM_SECRET_KEY + SIZE_STATIC_KEM_PUB_KEY];
        concat_pk[..SIZE_STATIC_KEM_SECRET_KEY].copy_from_slice(&bytes_sk_pq);
        concat_pk[SIZE_STATIC_KEM_SECRET_KEY..].copy_from_slice(&bytes_pk_pq);

        write("private_key", hex::encode(concat_pk.to_vec()))
    });

    config
        .get_listen_port()
        .map(|port| write("listen_port", port.to_string()));

    config
        .get_fwmark()
        .map(|fwmark| write("fwmark", fwmark.to_string()));

    // serialize all peers
    let mut peers = config.get_peers();
    while let Some(p) = peers.pop() {
        let bytes_pk_pq =
            <[u8; SIZE_STATIC_KEM_PUB_KEY]>::try_from(p.public_key_pq.as_ref()).unwrap();

        write("public_key", hex::encode(bytes_pk_pq.to_vec()))?;
        write("preshared_key", hex::encode(p.preshared_key))?;
        write("rx_bytes", p.rx_bytes.to_string())?;
        write("tx_bytes", p.tx_bytes.to_string())?;
        write(
            "persistent_keepalive_interval",
            p.persistent_keepalive_interval.to_string(),
        )?;

        if let Some((secs, nsecs)) = p.last_handshake_time {
            write("last_handshake_time_sec", secs.to_string())?;
            write("last_handshake_time_nsec", nsecs.to_string())?;
        }

        if let Some(endpoint) = p.endpoint {
            write("endpoint", endpoint.to_string())?;
        }

        for (ip, cidr) in p.allowed_ips {
            write("allowed_ip", ip.to_string() + "/" + &cidr.to_string())?;
        }
    }

    Ok(())
}
