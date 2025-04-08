pub use crate::error::{Error, Result};
pub use alloy_primitives::Address as EvmAddress;
pub use bls::SecretKey;
pub use evmlib::common::U256;
pub use libp2p::Multiaddr;
pub use xor_name::XorName;

use crate::logging::{logging, LoggingHandle};
use alloy_primitives::Bytes as EvmBytes;
use autonomi::{
    Client,
    get_evm_network,
    Wallet,
    ClientConfig,
    InitialPeersConfig,
    GraphEntry,
    pointer::PointerTarget,
    PointerAddress,
    GraphEntryAddress,
    graph::GraphError,
    Network,
    client::{payment::PaymentOption, data::DataAddress},
};
use bytes::Bytes;
use std::str::FromStr;

pub const ROOT_SK: &str = "160922b4d2b35fec6b7a36a54c9793bea0fdef00c2630b4361e7a92546f05993"; // could be anything, it does not have to be secret, because it's only used as a base for derivation. Changing this will make all Autonomi data created before UNACCESSIBLE!!

/// An alternative Autonomi API
///
/// ```no_run
/// use safe_api::{Safe, XorNameBuilder};
/// # use tokio;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), safe_api::Error> {
/// // connect to mainnet
/// let mut safe = Safe::connect(vec![], true, None, "INFO".to_string()).await?;
///
/// # let key_data = std::fs::read("/encrypted/secret_key.json").unwrap();
/// // [...] read key_data from a file
/// let secret_key = Safe::decrypt(&key_data, "password")?;
/// safe.login(Some(secret_key))?;
///
/// let data_name = safe.upload(&[10, 11, 12]).await?;
/// # Ok(())
/// # }
/// ```
pub struct Safe {
    evm_network: Network,
    client: Client,
    wallet: Option<Wallet>,
    sk: Option<SecretKey>,
    log_handle: Option<LoggingHandle>,
}

impl std::fmt::Debug for Safe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        let walllet_debug: String = self.wallet.clone().map(
            |w| format!("Some(Wallet {{ address: {:?} }})", w.address())
        ).unwrap_or("None".to_string());

        f.debug_struct("Safe")
            .field("evm_network", &format!("{:?}", self.evm_network))
            .field("client", &"Client { ... }")
            .field("wallet", &walllet_debug)
            .field("sk", &format!("{:?}", self.sk))
            .field("log_handle", match &self.log_handle { Some(_) => &"Some(LoggingHandle { ... })", None => &"None" })
            .finish()
    }
}

impl Safe {
    /// Connect to Autonomi
    ///
    /// Autonomi will be connected without logging in (read-only), if `secret` is None. `log_level` is a group of pre-defined *ant_logging* levels. Possible values are `trace`, `info` and `error`, case independent.
    pub async fn connect(
        peers: Vec<Multiaddr>,
        add_network_peers: bool,
        secret: Option<SecretKey>,
        log_level: String,
    ) -> Result<Safe> {

        let log_handle = logging(log_level, None)?;
        let network = get_evm_network(!add_network_peers)?;

        let client = Client::init_with_config(ClientConfig {
            init_peers_config: InitialPeersConfig {
                addrs: peers,
                local: !add_network_peers,
                ..Default::default()
            },
            evm_network: network.clone(),
            strategy: Default::default(),
        }).await?;

        let mut safe = Safe {
            evm_network: network,
            client: client,
            wallet: None,
            sk: None,
            log_handle,
        };

        if let Some(sk) = secret {
            safe.login(Some(sk))?;
        }

        Ok(safe)
    }

    /// Login generates SecretKey and initiates a wallet.
    ///
    /// `eth_privkey` is a EVM private key, that will be used in a wallet. It's also used as an index to derive SecretKey from [`ROOT_SK`].
    /// If `eth_privkey` is `None`, it will be randomized.
    pub fn login_with_eth(&mut self, eth_privkey: Option<String>) -> Result<()> {
        let eth_pk = eth_privkey.unwrap_or(SecretKey::random().to_hex()); // bls secret key can be used as eth privkey

        println!("\n\neth_pk: {:.4}(...)", eth_pk);

        let wallet = Wallet::new_from_private_key(self.evm_network.clone(), &eth_pk)?;

        let eth_pk = EvmBytes::from_str(&eth_pk)
            .map_err(|e| Error::Custom(format!("Eth privkey parse: {}", e)))?;
        let root_sk = SecretKey::from_hex(ROOT_SK).unwrap();
        let sk = root_sk.derive_child(&eth_pk);

        self.wallet = Some(wallet);
        self.sk = Some(sk);
        Ok(())
    }

    /// Login uses the SecretKey and initiates a wallet.
    ///
    /// `secret` is used as EVM private key, that will be used in a wallet.
    /// If `secret` is `None`, it will be randomized.
    pub fn login(&mut self, secret: Option<SecretKey>) -> Result<()> {
        let secret = secret.unwrap_or(SecretKey::random());
        self.login_with_eth(Some(SecretKey::to_hex(&secret)))?; // bls secret key can be used as eth privkey
        self.sk = Some(secret);
        Ok(())
    }

    /// Change *ant_logging* levels to a group of pre-defined values.
    ///
    /// Possible group names are `trace`, `info` and `error`, case independent.
    pub fn log_level(&mut self, level: String) -> Result<()> {
        let _ = logging(level, self.log_handle.as_ref());
        Ok(())
    }

    /// Create a Reg with given name
    pub async fn reg_create(
        &mut self,
        data: &[u8],
        name: &XorName,
    ) -> Result<()> {

        println!("\n\nUploading data: {:?}...", data);

        let data_address = self.upload(data).await?;

        println!("\n\nCreating graph entry...");

        let ge_name = XorNameBuilder::from(name).with_str("0").build();
        let ge_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&ge_name);
        let ge = GraphEntry::new(
            &ge_key,
            vec![],
            data_address.0,
            vec![],
        );
        let (_attos, _xorname) = self.client.graph_entry_put(ge, PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?)).await?; // TODO: what will happen if someone already created a graph entry under this address? we have to proceed then to next step, in case when creating a Reg failed at the pointer creation step last time, and now we want to retry that.

        println!("\n\nCreating counter pointer...");

        let pointer_name = XorNameBuilder::from(name)
                .with_str("counter").build();
        let pointer_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&pointer_name);
        let (_attos, _address) = self.client.pointer_create(
            &pointer_key,
            PointerTarget::PointerAddress(PointerAddress::new(pointer_key.public_key().derive_child("DUMMY".as_bytes()))),
            PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?),
        ).await?;

        Ok(())
    }

    /// Update a Reg with given name. Version counter will increase by 1. First version of Reg is always 0.
    pub async fn reg_write(
        &self,
        data: &[u8],
        name: &XorName,
    ) -> Result<()> {

        println!("\n\nGetting counter pointer...");

        let pointer_name = XorNameBuilder::from(name)
                .with_str("counter").build();
        let pointer_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&pointer_name);
        let pointer = self.client.pointer_get(&PointerAddress::new(pointer_key.public_key())).await?;

        println!("\n\nWriting data...");

        let data_address = self.upload(data).await?;

        println!("\n\nNew graph entry...");

        let ge_index = pointer.counter() + 1;
        println!("ge_index {}", ge_index);
        let ge_name = XorNameBuilder::from(name)
                .with_str(&format!("{}", ge_index)).build();
        let ge_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&ge_name);
        let new_tail_ge = GraphEntry::new(
            &ge_key,
            vec![],
            data_address.0,
            vec![],
        );
        let (_attos, _xorname) = self.client.graph_entry_put(new_tail_ge, PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?)).await?; // TODO: what will happen if someone already created a graph entry under this address? we have to proceed then to next step, in case when creating a Reg failed at the pointer creation step last time, and now we want to retry that.

        println!("\n\nIncrementing counter pointer...");

        self.client.pointer_update(
            &pointer_key,
            PointerTarget::PointerAddress(PointerAddress::new(pointer_key.public_key().derive_child("DUMMY".as_bytes()))),
        ).await?;

        Ok(())
    }

    /// Read a Reg with given name and version. If `version` is `None`, latest version will be read. First (oldest) version is 0.
    pub async fn read_reg(&self, name: &XorName, version: Option<u32>) -> Result<Vec<u8>> {

        let version: u32 = if let Some(v) = version {
            v
        } else {
            println!("\n\nReading counter pointer...");
            let pointer_name = XorNameBuilder::from(name)
                    .with_str("counter").build();
            let pointer_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&pointer_name);
            let pointer = self.client.pointer_get(&PointerAddress::new(pointer_key.public_key())).await?;

            pointer.counter()
        };

        println!("\n\nReading graph entry...");
        println!("version {}", version);

        let ge_name = XorNameBuilder::from(name)
                .with_str(&format!("{}", version)).build();
        let ge_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&ge_name);
        let gentriess = self.client.graph_entry_get(&GraphEntryAddress::new(ge_key.public_key())).await;
        let ge = match gentriess {
            Ok(e) => e,
            Err(GraphError::Fork(entries)) => {
                entries.first().ok_or(Error::Custom(format!("No GraphEntry for version {}", version)))?.clone()
            },
            Err(e) => {
                return Err(Error::Custom(format!("Error reading GraphEntry: {}", e)));
            },
        };

        println!("\n\nReading data...");

        let data_address = XorName(ge.content);
        Ok(self.download(data_address).await?)
    }

    pub async fn upload(&self, data: &[u8]) -> Result<XorName> {
        let (_attos, address) = self
            .client
            .data_put_public(
                Bytes::copy_from_slice(data),
                PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?),
            )
            .await?;
        Ok(*address.xorname())
    }

    pub async fn download(&self, xorname: XorName) -> Result<Vec<u8>> {
        let data = self.client.data_get_public(&DataAddress::new(xorname)).await?;
        Ok(data.to_vec()) // TODO: Vec instead of Bytes result in Autonomi API
    }

    pub fn address(&self) -> Result<EvmAddress> {
        self.wallet
            .as_ref()
            .ok_or(Error::NotLoggedIn)
            .map(Wallet::address)
    }

    /// Balance of tokens (ANT) and gas tokens (ETH)
    pub async fn balance(&self) -> Result<(U256, U256)> {
        Ok(
            (self
                .wallet
                .as_ref()
                .ok_or(Error::NotLoggedIn)?
                .balance_of_tokens()
                .await?,

            self
                .wallet
                .as_ref()
                .ok_or(Error::NotLoggedIn)?
                .balance_of_gas_tokens()
                .await?
            )
        )
    }

}

// Add optional maxium price caller agrees to pay for operation.
// A "limit exceeded" error as a possible Result
// Keep internal statistics about price needed for any operation
// A "price cannot be estimated" as a possible Result


/// This can be used to easily generate `XorName`s by chaining text and bytes fragments to derive from a given `XorName` or a random one.
///
/// ```no_run
/// use safe_api::{Safe, XorNameBuilder};
/// # use tokio;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), safe_api::Error> {
/// # let mut safe = Safe::connect(vec![], true, None, "INFO".to_string()).await?;
/// # safe.login(None)?;
///
/// let data_name = safe.upload(&[10, 11, 12]).await?;
/// let related_reg_name = XorNameBuilder::from(&data_name).with_str("related").build();
///
/// safe.reg_create(&[1, 2, 3], &related_reg_name).await?;
///
/// // if you store data_name somewhere, also related_reg_name could be recreated to read both data and Reg.
/// # Ok(())
/// # }
/// ```
pub struct XorNameBuilder {
    origin: XorName,
    sources: Vec<Vec<u8>>,
}

impl XorNameBuilder {
    pub fn from(xor_name: &XorName) -> Self {
        Self {
            origin: xor_name.clone(),
            sources: vec![],
        }
    }

    pub fn from_str(name: &str) -> Self {
        Self {
            origin: XorName::from_content(name.as_bytes()),
            sources: vec![],
        }
    }

    pub fn random() -> Self {
        Self {
            origin: XorName::random(&mut rand::thread_rng()),
            sources: vec![],
        }
    }

    pub fn with_bytes(mut self, name: &[u8]) -> Self {
        self.sources.push(name.to_vec());
        self
    }

    pub fn with_str(mut self, name: &str) -> Self {
        self.sources.push(name.as_bytes().to_vec());
        self
    }

    pub fn build(self) -> XorName {
        let mut built = self.origin.0;
        if !self.sources.is_empty() {
            let other = XorName::from_content_parts(
                Vec::from_iter(self.sources.iter().map(|v| v.as_slice())).as_slice(),
            );
            for i in 0..xor_name::XOR_NAME_LEN {
                built[i] = built[i] ^ other.0[i];
            }
        }
        XorName(built)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xor_name::XorName;

    #[test]
    fn xor_builder() {
        let x = XorNameBuilder::random().build();

        let x1: XorName = XorNameBuilder::from(&x).build();

        assert_eq!(x.0, x1.0);

        let x2: XorName = XorNameBuilder::from(&x).with_str("test").build();

        assert_ne!(x1.0, x2.0);

        let x3: XorName = XorNameBuilder::from(&x1)
            .with_bytes("test".as_bytes())
            .build();

        assert_eq!(x2.0, x3.0);
    }
}
