//! Network profiles for Stellar.
//!
//! Passphrases and default RPC URLs are the public network constants and are
//! safe to ship. Nothing here requires network access.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ObservatoryError;

/// A known Stellar network profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Stellar public network.
    Public,
    /// Stellar test network.
    Testnet,
    /// Stellar future network.
    Futurenet,
}

impl Network {
    /// All known networks, in a stable order.
    #[must_use]
    pub fn all() -> &'static [Network] {
        &[Network::Public, Network::Testnet, Network::Futurenet]
    }

    /// The canonical network passphrase.
    #[must_use]
    pub fn passphrase(self) -> &'static str {
        match self {
            Network::Public => "Public Global Stellar Network ; September 2015",
            Network::Testnet => "Test SDF Network ; September 2015",
            Network::Futurenet => "Test SDF Future Network ; October 2022",
        }
    }

    /// A commonly used public RPC endpoint for the network.
    ///
    /// These are defaults for convenience only; users should pass an explicit
    /// endpoint for anything reproducible.
    #[must_use]
    pub fn default_rpc_url(self) -> &'static str {
        match self {
            Network::Public => "https://mainnet.sorobanrpc.com",
            Network::Testnet => "https://soroban-testnet.stellar.org",
            Network::Futurenet => "https://rpc-futurenet.stellar.org",
        }
    }

    /// A stable lowercase name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Network::Public => "public",
            Network::Testnet => "testnet",
            Network::Futurenet => "futurenet",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Network {
    type Err = ObservatoryError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "public" | "mainnet" | "pubnet" => Ok(Network::Public),
            "testnet" | "test" => Ok(Network::Testnet),
            "futurenet" | "future" => Ok(Network::Futurenet),
            other => Err(ObservatoryError::invalid(format!(
                "unknown network `{other}`; expected one of public, testnet, futurenet"
            ))),
        }
    }
}

/// The resolved profile for a [`Network`]: its passphrase and default RPC endpoint.
///
/// Both values are public constants, so a profile can be recorded in output
/// without any network access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NetworkProfile {
    /// The network this profile describes.
    pub network: Network,
    /// The canonical network passphrase.
    pub passphrase: &'static str,
    /// The default RPC endpoint, used when no override is given.
    pub default_rpc_url: &'static str,
}

impl Network {
    /// Resolves this network to its profile.
    #[must_use]
    pub fn profile(self) -> NetworkProfile {
        NetworkProfile {
            network: self,
            passphrase: self.passphrase(),
            default_rpc_url: self.default_rpc_url(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for network in Network::all() {
            assert_eq!(network.name().parse::<Network>().unwrap(), *network);
        }
    }

    #[test]
    fn aliases_parse() {
        assert_eq!("MAINNET".parse::<Network>().unwrap(), Network::Public);
        assert_eq!("Test".parse::<Network>().unwrap(), Network::Testnet);
    }

    #[test]
    fn unknown_network_errors() {
        assert!("devnet".parse::<Network>().is_err());
    }

    #[test]
    fn profile_carries_the_passphrase_and_default_endpoint() {
        let profile = "mainnet".parse::<Network>().unwrap().profile();
        assert_eq!(profile.network, Network::Public);
        assert_eq!(
            profile.passphrase,
            "Public Global Stellar Network ; September 2015"
        );
        assert_eq!(profile.default_rpc_url, "https://mainnet.sorobanrpc.com");
    }

    #[test]
    fn passphrases_are_nonempty() {
        for network in Network::all() {
            assert!(!network.passphrase().is_empty());
            assert!(!network.default_rpc_url().is_empty());
        }
    }
}
