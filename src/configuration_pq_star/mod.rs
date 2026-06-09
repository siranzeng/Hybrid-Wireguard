mod config;
mod error;
pub mod uapi;

use super::platform::Endpoint;
use super::platform::{tun, udp};
use super::wireguard_pq_star::WireGuard;

pub use error::ConfigError;

pub use config::Configuration;
pub use config::WireGuardConfig;
