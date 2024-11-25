pub use crate::error::{Error, Result};
pub use alloy_primitives::Address as EvmAddress;
pub use autonomi::{Client, client::registers::{Register, RegisterPermissions, RegisterAddress}};
pub use bls::SecretKey;
pub use evmlib::common::U256;
pub use libp2p::Multiaddr;
pub use xor_name::XorName;

use autonomi::{get_evm_network_from_env, Wallet};
use bytes::Bytes;
use std::{path::PathBuf, time::Duration};
use tracing::Level;
use sn_peers_acquisition::{get_peers_from_url, NETWORK_CONTACTS_URL};

const _CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Safe {
    pub client: Client,
    wallet: Wallet,
    sk: SecretKey,
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
    pub async fn connect(
        peers: Vec<Multiaddr>,
        add_network_peers: bool,
        secret: Option<SecretKey>,
        _wallet_dir: PathBuf,
    ) -> Result<Safe> {
        let sk = secret.unwrap_or(SecretKey::random());

		if add_network_peers {
	        let mut net_peers = get_peers_from_url(url::Url::parse(NETWORK_CONTACTS_URL.as_str()).unwrap()).await?;
	        let mut peers = peers.clone();
	        peers.append(&mut net_peers);
		}

        //        let client = Client::new(sk.clone(), Some(peers), Some(CONNECTION_TIMEOUT), None).await?;
        let client = Client::connect(&peers).await?;
        let network = get_evm_network_from_env()?;
        let wallet = Wallet::new_from_private_key(network, &sk.to_hex())?;

        Ok(Safe {
            client: client,
            wallet: wallet,
            sk: sk,
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
        let perms = perms.unwrap_or(self.only_owner_can_write());

        Ok(self
            .client
            .register_create_with_permissions(
                Bytes::copy_from_slice(data),
                &format!("{:x}", meta), // convert meta to lower hex string
                self.sk.clone(),
                perms,
                &self.wallet,
            )
            .await?)
    }

    pub async fn open_register(&self, meta: XorName) -> Result<Register> {
        let meta = registers::XorNameBuilder::from_str(&format!("{:x}", meta)).build(); // forced by all autonomi api requiring names as strings
        Ok(self
            .client
            .register_get(RegisterAddress::new(meta, self.sk.public_key()))
            .await?)
    }

    pub async fn register_write(&self, reg: &Register, data: &[u8]) -> Result<()> {
        let reg = reg.clone(); // TODO: wait for resolving upstream issue: https://github.com/maidsafe/safe_network/issues/2396
        Ok(self
            .client
            .register_update(reg, Bytes::copy_from_slice(data), self.sk.clone())
            .await?)
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

	pub fn random_register_address(&self) -> RegisterAddress {
		RegisterAddress::new(XorName::random(&mut rand::thread_rng()), self.sk.public_key())
	}

    pub fn init_logging() -> Result<()> {
        let logging_targets = vec![
            ("sn_networking".to_string(), Level::DEBUG),
            ("safe".to_string(), Level::TRACE),
            ("sn_build_info".to_string(), Level::TRACE),
            ("sn_cli".to_string(), Level::TRACE),
//            ("sn_client".to_string(), Level::TRACE),
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

    pub fn address(&self) -> EvmAddress {
        self.wallet.address()
    }

    pub async fn balance(&self) -> Result<U256> {
        Ok(self.wallet.balance_of_tokens().await?)
    }

    fn only_owner_can_write(&self) -> RegisterPermissions {
        RegisterPermissions::new_with([self.sk.public_key()])
    }

}

pub fn random_register_address() -> RegisterAddress {
	RegisterAddress::new(XorName::random(&mut rand::thread_rng()), Client::register_generate_key().public_key())
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
        use xor_name::XorName;
        use crate::Client;

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
