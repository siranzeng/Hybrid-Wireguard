mod config;
mod error;
pub mod uapi;

use super::platform::Endpoint;
use super::platform::{tun, udp};
#[cfg(not(feature = "hybrid_new"))]
use super::wireguard_hybrid::WireGuard;
#[cfg(feature = "hybrid_new")]
use super::wireguard_hybrid_new::WireGuard;

pub use error::ConfigError;

pub use config::Configuration;
pub use config::WireGuardConfig;
