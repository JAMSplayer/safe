pub use crate::error::{Error, Result};
pub use alloy_primitives::Address as EvmAddress;
pub use autonomi::{
    client::registers::{Register, RegisterAddress, RegisterPermissions},
    Client,
};
pub use bls::SecretKey;
pub use evmlib::common::U256;
pub use libp2p::Multiaddr;
pub use xor_name::XorName;

use autonomi::{get_evm_network_from_env, Wallet};
use bytes::Bytes;
use sn_peers_acquisition::{get_peers_from_url, NETWORK_CONTACTS_URL};
use std::time::Duration;
use tracing::Level;

const _CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Safe {
    client: Client,
    wallet: Option<Wallet>,
    sk: Option<SecretKey>,
}

// TODO: wait for resolving upstream issue: https://github.com/maidsafe/safe_network/issues/2329
//
//pub type PaymentResult<T> = Result<(T, NanoTokens, NanoTokens)>;
//
//pub fn add_payment<T>(
//    pr: PaymentResult<T>,
//    other_cost: NanoTokens,
//    other_royalties: NanoTokens,
//) -> PaymentResult<T> {
//    if let Ok((v, cost, royalties)) = pr {
//        Ok((
//            v,
//            cost.checked_add(other_cost)
//                .ok_or(Error::Custom("Overflow".to_string()))?,
//            royalties
//                .checked_add(other_royalties)
//                .ok_or(Error::Custom("Overflow".to_string()))?,
//        ))
//    } else {
//        pr
//    }
//}

impl Safe {
    // if secret is None, will connect without logging in
    pub async fn connect(
        peers: Vec<Multiaddr>,
        add_network_peers: bool,
        secret: Option<SecretKey>,
    ) -> Result<Safe> {
        if add_network_peers {
            let mut net_peers =
                get_peers_from_url(url::Url::parse(NETWORK_CONTACTS_URL.as_str()).unwrap()).await?;
            let mut peers = peers.clone();
            peers.append(&mut net_peers);
        }

        //let client = Client::new(sk.clone(), Some(peers), Some(CONNECTION_TIMEOUT), None).await?;
        let client = Client::connect(&peers).await?;

        let wallet = if let Some(sk) = secret.clone() {
            let network = get_evm_network_from_env()?;
            Some(Wallet::new_from_private_key(network, &sk.to_hex())?)
        } else {
            None
        };

        Ok(Safe {
            client: client,
            wallet: wallet,
            sk: secret,
        })
    }

    // if secret is None, it will be randomized.
    pub fn login(&mut self, secret: Option<SecretKey>) -> Result<Safe> {
        let sk = secret.unwrap_or(SecretKey::random());

        let network = get_evm_network_from_env()?;
        let wallet = Wallet::new_from_private_key(network, &sk.to_hex())?;

        Ok(Safe {
            client: self.client.clone(),
            wallet: Some(wallet),
            sk: Some(sk),
        })
    }

    // allows using XorNameBuilder with Xor when you need a deeper naming structure.
    // when perms is None, only owner can write to the register.
    pub async fn register_create(
        &mut self,
        data: &[u8],
        meta: XorName,
        perms: Option<RegisterPermissions>,
    ) -> Result<Register> {
        let perms = perms.unwrap_or(self.only_owner_can_write()?);

        if let Some(_) = self.wallet.as_ref().and(self.sk.as_ref()) {
            Ok(self
                .client
                .register_create_with_permissions(
                    Bytes::copy_from_slice(data),
                    &format!("{:x}", meta), // convert meta to lower hex string
                    self.sk.clone().unwrap(),
                    perms,
                    self.wallet.as_ref().unwrap(),
                )
                .await?)
        } else {
            Err(Error::NotLoggedIn)
        }
    }

    pub async fn open_own_register(&self, meta: XorName) -> Result<Register> {
        match &self.sk {
            Some(sk) => {
                let meta = registers::XorNameBuilder::from_str(&format!("{:x}", meta)).build(); // forced by all autonomi api requiring names as strings
                self.open_register(RegisterAddress::new(meta, sk.public_key()))
                    .await
            }
            None => Err(Error::NotLoggedIn),
        }
    }

    pub async fn open_register(&self, address: RegisterAddress) -> Result<Register> {
        Ok(self.client.register_get(address).await?)
    }

    pub async fn register_write(&self, reg: &Register, data: &[u8]) -> Result<()> {
        let reg = reg.clone(); // TODO: wait for resolving upstream issue: https://github.com/maidsafe/safe_network/issues/2396
        if let Some(sk) = &self.sk {
            Ok(self
                .client
                .register_update(reg, Bytes::copy_from_slice(data), sk.clone())
                .await?)
        } else {
            Err(Error::NotLoggedIn)
        }
    }

    // In case of multiple branches, register is merged with one of the entries copied on top.
    pub async fn read_register(reg: &mut Register, version: u32) -> Result<Option<Vec<u8>>> {
        if version > 0 {
            return Err(Error::Custom(String::from(
                "Registers versioning is not yet supported.",
            )));
        };

        let entries = reg.values();

        Ok(entries.iter().next().map(|bytes| bytes.to_vec()))
    }

    pub fn random_register_address(&self) -> Option<RegisterAddress> {
        self.sk.as_ref().map(|sk| {
            RegisterAddress::new(XorName::random(&mut rand::thread_rng()), sk.public_key())
        })
    }

    pub fn init_logging() -> Result<()> {
        let logging_targets = vec![
            ("sn_networking".to_string(), Level::DEBUG),
            ("safe".to_string(), Level::TRACE),
            ("sn_build_info".to_string(), Level::TRACE),
            ("sn_cli".to_string(), Level::TRACE),
            ("autonomi".to_string(), Level::TRACE),
            ("sn_logging".to_string(), Level::TRACE),
            ("sn_peers_acquisition".to_string(), Level::TRACE),
            ("sn_protocol".to_string(), Level::TRACE),
            ("sn_registers".to_string(), Level::TRACE),
            ("sn_transfers".to_string(), Level::TRACE),
        ];
        let mut log_builder = sn_logging::LogBuilder::new(logging_targets);
        log_builder.output_dest(sn_logging::LogOutputDest::Stdout);
        log_builder.format(sn_logging::LogFormat::Default);
        let _ = log_builder
            .initialize()
            .map_err(|e| Error::Custom(format!("logging: {}", e)))?;

        Ok(())
    }

    pub fn address(&self) -> Result<EvmAddress> {
        self.wallet
            .as_ref()
            .ok_or(Error::NotLoggedIn)
            .map(Wallet::address)
    }

    pub async fn balance(&self) -> Result<U256> {
        Ok(self
            .wallet
            .as_ref()
            .ok_or(Error::NotLoggedIn)?
            .balance_of_tokens()
            .await?)
    }

    fn only_owner_can_write(&self) -> Result<RegisterPermissions> {
        self.sk
            .as_ref()
            .ok_or(Error::NotLoggedIn)
            .map(|sk| RegisterPermissions::new_with([sk.public_key()]))
    }
}

pub fn random_register_address() -> RegisterAddress {
    RegisterAddress::new(
        XorName::random(&mut rand::thread_rng()),
        Client::register_generate_key().public_key(),
    )
}

// create_register(address: Option<XorAddress>, data: Vec<u8>) -> Result<XorAddress>
//      ! if address is None, that means it should be assigned a random address
//      ? exists / squatted
//
// read_register(meta: XorName) -> Result<Vec<u8>>
// read_register(address: NetworkAddress) -> Result<Vec<u8>>
//
// update_register(new_data: Vec<u8>, address: XorAddress) -> Result<XorAddress>
//
// upload_file(data: Vec<u8>) -> Result<XorAddress>
//      ? already uploaded
//
// read_file()
// → sn_client::file::download::read()
//

// Add optional maxium price caller agrees to pay for operation.
// A "limit exceeded" error as a possible Result
// Keep internal statistics about price needed for any operation
// A "price cannot be estimated" as a possible Result

pub mod registers {
    use xor_name::XorName;

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
        use crate::Client;
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

        #[test]
        fn xorname_from_string_autonomi() {
            let x1 = XorNameBuilder::from_str("test").build();
            let x2 = Client::register_address("test", &Client::register_generate_key()).meta();
            assert_eq!(x1.0, x2.0);
        }
    }
}
