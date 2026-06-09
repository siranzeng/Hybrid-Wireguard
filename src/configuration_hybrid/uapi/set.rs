use super::{ConfigError, Configuration};
#[cfg(not(feature = "hybrid_new"))]
use crate::wireguard_hybrid::handshake::crypto_params::{
    SIZE_STATIC_KEM_PUB_KEY, SIZE_STATIC_KEM_SECRET_KEY, STATIC_KEM_ALG,
};
#[cfg(not(feature = "hybrid_new"))]
use crate::wireguard_hybrid::handshake::Device;
#[cfg(feature = "hybrid_new")]
use crate::wireguard_hybrid_new::handshake::crypto_params::{
    SIZE_STATIC_KEM_PUB_KEY, SIZE_STATIC_KEM_SECRET_KEY, STATIC_KEM_ALG,
};
#[cfg(feature = "hybrid_new")]
use crate::wireguard_hybrid_new::handshake::Device;
use hex::FromHex;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

enum ParserState {
    Peer(ParsedPeer),
    Interface,
}

struct ParsedPeer {
    public_key: PublicKey,
    public_key_pq: oqs::kem::PublicKey,
    update_only: bool,
    allowed_ips: Vec<(IpAddr, u32)>,
    remove: bool,
    preshared_key: Option<[u8; 32]>,
    replace_allowed_ips: bool,
    persistent_keepalive_interval: Option<u64>,
    protocol_version: Option<usize>,
    endpoint: Option<SocketAddr>,
}

pub struct LineParser<'a, C: Configuration> {
    config: &'a C,
    state: ParserState,
}

impl<'a, C: Configuration> LineParser<'a, C> {
    pub fn new(config: &'a C) -> LineParser<'a, C> {
        LineParser {
            config,
            state: ParserState::Interface,
        }
    }

    fn new_peer(value: &str) -> Result<ParserState, ConfigError> {
        let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
        let pkv = Vec::from_hex(value).map_err(|_| ConfigError::InvalidHexValue)?;
        let k: [u8; 32 + SIZE_STATIC_KEM_PUB_KEY] =
            <[u8; 32 + SIZE_STATIC_KEM_PUB_KEY]>::try_from(pkv)
                .map_err(|_| ConfigError::InvalidHexValue)?;
        let pk: [u8; 32] = k[..32]
            .try_into()
            .map_err(|_| ConfigError::InvalidHexValue)?;
        let pk_pq: [u8; SIZE_STATIC_KEM_PUB_KEY] = k[32..]
            .try_into()
            .map_err(|_| ConfigError::InvalidHexValue)?;
        let public_key_pq = kemalg_static
            .public_key_from_bytes(&pk_pq)
            .ok_or(ConfigError::InvalidHexValue)?
            .to_owned();

        Ok(ParserState::Peer(ParsedPeer {
            public_key: PublicKey::from(pk),
            public_key_pq,
            remove: false,
            update_only: false,
            allowed_ips: vec![],
            preshared_key: None,
            replace_allowed_ips: false,
            persistent_keepalive_interval: None,
            protocol_version: None,
            endpoint: None,
        }))
    }

    pub fn parse_line(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        #[cfg(debug)]
        {
            if key.len() > 0 {
                log::debug!("UAPI: {}={}", key, value);
            }
        }

        // flush peer updates to configuration
        fn flush_peer<C: Configuration>(config: &C, peer: &ParsedPeer) -> Result<(), ConfigError> {
            if peer.remove {
                log::trace!("flush peer, remove peer");
                let pk_hash =
                    Device::<u32>::hash_static_keys(&peer.public_key, &peer.public_key_pq);
                config.remove_peer(&pk_hash);
                return Ok(());
            }

            if let Some(version) = peer.protocol_version {
                log::trace!("flush peer, set protocol_version {}", version);
                if version == 0 || version > config.get_protocol_version() {
                    return Err(ConfigError::UnsupportedProtocolVersion);
                }
            }

            if !peer.update_only {
                log::trace!("flush peer, add peer");
                let pk_hash =
                    Device::<u32>::hash_static_keys(&peer.public_key, &peer.public_key_pq);
                config.add_peer(peer.public_key, &peer.public_key_pq, &pk_hash);
            }

            if peer.replace_allowed_ips {
                log::trace!("flush peer, replace allowed_ips");
                let pk_hash =
                    Device::<u32>::hash_static_keys(&peer.public_key, &peer.public_key_pq);
                config.replace_allowed_ips(&pk_hash);
            }

            for (ip, cidr) in &peer.allowed_ips {
                log::trace!("flush peer, add allowed_ips : {}/{}", ip.to_string(), cidr);
                let pk_hash =
                    Device::<u32>::hash_static_keys(&peer.public_key, &peer.public_key_pq);
                config.add_allowed_ip(&pk_hash, *ip, *cidr);
            }

            if let Some(psk) = peer.preshared_key {
                log::trace!("flush peer, set preshared_key {}", hex::encode(psk));
                let pk_hash =
                    Device::<u32>::hash_static_keys(&peer.public_key, &peer.public_key_pq);
                config.set_preshared_key(&pk_hash, psk);
            }

            if let Some(secs) = peer.persistent_keepalive_interval {
                log::trace!("flush peer, set persistent_keepalive_interval {}", secs);
                let pk_hash =
                    Device::<u32>::hash_static_keys(&peer.public_key, &peer.public_key_pq);
                config.set_persistent_keepalive_interval(&pk_hash, secs);
            }

            if let Some(endpoint) = peer.endpoint {
                log::trace!("flush peer, set endpoint {}", endpoint.to_string());
                let pk_hash =
                    Device::<u32>::hash_static_keys(&peer.public_key, &peer.public_key_pq);
                config.set_endpoint(&pk_hash, endpoint);
            };

            Ok(())
        };

        // parse line and update parser state
        match self.state {
            // configure the interface
            ParserState::Interface => match key {
                // opt: set private key
                "private_key" => match Vec::from_hex(value) {
                    Ok(skv) => {
                        let k =
                            <[u8; 32 + SIZE_STATIC_KEM_SECRET_KEY + SIZE_STATIC_KEM_PUB_KEY]>::try_from(skv)
                                .map_err(|_| ConfigError::InvalidHexValue)?;

                        self.config.set_private_key(
                            if k.ct_eq(
                                &[0u8; 32 + SIZE_STATIC_KEM_SECRET_KEY + SIZE_STATIC_KEM_PUB_KEY],
                            )
                            .into()
                            {
                                None
                            } else {
                                let sk: [u8; 32] = k[..32].try_into().unwrap();
                                let sk_pq: [u8; SIZE_STATIC_KEM_SECRET_KEY] =
                                    k[32..32 + SIZE_STATIC_KEM_SECRET_KEY].try_into().unwrap();
                                let pk_pq: [u8; SIZE_STATIC_KEM_PUB_KEY] =
                                    k[32 + SIZE_STATIC_KEM_SECRET_KEY..].try_into().unwrap();

                                let kemalg_static = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
                                Some((
                                    StaticSecret::from(sk),
                                    kemalg_static
                                        .secret_key_from_bytes(&sk_pq)
                                        .ok_or(ConfigError::InvalidHexValue)?
                                        .to_owned(),
                                    kemalg_static
                                        .public_key_from_bytes(&pk_pq)
                                        .ok_or(ConfigError::InvalidHexValue)?
                                        .to_owned(),
                                ))
                            },
                        );
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidHexValue),
                },

                // opt: set listen port
                "listen_port" => match value.parse() {
                    Ok(port) => {
                        self.config.set_listen_port(port)?;
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidPortNumber),
                },

                // opt: set fwmark
                "fwmark" => match value.parse() {
                    Ok(fwmark) => {
                        self.config
                            .set_fwmark(if fwmark == 0 { None } else { Some(fwmark) })?;
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidFwmark),
                },

                "ri_key" => match <[u8; 8]>::from_hex(value) {
                    Ok(key) => {
                        self.config.set_ri_key(if key.ct_eq(&[0u8; 8]).into() {
                            None
                        } else {
                            Some(key)
                        });
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidHexValue),
                },

                // opt: remove all peers
                "replace_peers" => match value {
                    "true" => {
                        for p in self.config.get_peers() {
                            let pk_hash =
                                Device::<u32>::hash_static_keys(&p.public_key, &p.public_key_pq);
                            self.config.remove_peer(&pk_hash)
                        }
                        Ok(())
                    }
                    _ => Err(ConfigError::UnsupportedValue),
                },

                // opt: transition to peer configuration
                "public_key" => {
                    self.state = Self::new_peer(value)?;
                    Ok(())
                }

                // ignore (end of transcript)
                "" => Ok(()),

                // unknown key
                _ => Err(ConfigError::InvalidKey),
            },

            // configure peers
            ParserState::Peer(ref mut peer) => match key {
                // opt: new peer
                "public_key" => {
                    flush_peer(self.config, &peer)?;
                    self.state = Self::new_peer(value)?;
                    Ok(())
                }

                // opt: remove peer
                "remove" => {
                    peer.remove = true;
                    Ok(())
                }

                // opt: update only
                "update_only" => {
                    peer.update_only = true;
                    Ok(())
                }

                // opt: set preshared key
                "preshared_key" => match <[u8; 32]>::from_hex(value) {
                    Ok(psk) => {
                        peer.preshared_key = Some(psk);
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidHexValue),
                },

                // opt: set endpoint
                "endpoint" => match value.parse() {
                    Ok(endpoint) => {
                        peer.endpoint = Some(endpoint);
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidSocketAddr),
                },

                // opt: set persistent keepalive interval
                "persistent_keepalive_interval" => match value.parse() {
                    Ok(secs) => {
                        peer.persistent_keepalive_interval = Some(secs);
                        Ok(())
                    }
                    Err(_) => Err(ConfigError::InvalidKeepaliveInterval),
                },

                // opt replace allowed ips
                "replace_allowed_ips" => {
                    peer.replace_allowed_ips = true;
                    peer.allowed_ips.clear();
                    Ok(())
                }

                // opt add allowed ips
                "allowed_ip" => {
                    let mut split = value.splitn(2, '/');
                    let addr = split.next().and_then(|x| x.parse().ok());
                    let cidr = split.next().and_then(|x| x.parse().ok());
                    match (addr, cidr) {
                        (Some(addr), Some(cidr)) => {
                            peer.allowed_ips.push((addr, cidr));
                            Ok(())
                        }
                        _ => Err(ConfigError::InvalidAllowedIp),
                    }
                }

                // set protocol version of peer
                "protocol_version" => {
                    let parse_res: Result<usize, _> = value.parse();
                    match parse_res {
                        Ok(version) => {
                            peer.protocol_version = Some(version);
                            Ok(())
                        }
                        Err(_) => Err(ConfigError::UnsupportedProtocolVersion),
                    }
                }

                // flush (used at end of transcipt)
                "" => {
                    log::trace!("UAPI, Set, processes end of transaction");
                    flush_peer(self.config, &peer)
                }

                // unknown key
                _ => Err(ConfigError::InvalidKey),
            },
        }
    }
}
