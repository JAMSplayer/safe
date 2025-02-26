pub use crate::error::{Error, Result};
pub use crate::logging::{init_logging, LoggingHandle};
pub use alloy_primitives::Address as EvmAddress;
pub use bls::SecretKey;
pub use evmlib::common::U256;
pub use libp2p::Multiaddr;
pub use xor_name::XorName;

use alloy_primitives::Bytes as EvmBytes;
use autonomi::{
    Client,
    get_evm_network,
    Wallet,
    ClientConfig,
    GraphEntry,
    pointer::PointerTarget,
    PointerAddress,
    GraphEntryAddress,
    graph::GraphError,
    Network,
    client::payment::PaymentOption,
};
use bytes::Bytes;
use std::str::FromStr;

const ROOT_SK: &str = "160922b4d2b35fec6b7a36a54c9793bea0fdef00c2630b4361e7a92546f05993"; // could be anything, it does not have to be secret, because it's only used as a base for derivation. Changing this will make all Autonomi data created before UNACCESSIBLE!!

#[derive(Clone)]
pub struct Safe {
    evm_network: Network,
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

        let network = get_evm_network(!add_network_peers)?;

        let client = Client::init_with_config(ClientConfig {
            local: !add_network_peers,
            peers: Some(peers),
            evm_network: network.clone(),
            strategy: Default::default(),
        }).await?;

        let mut safe = Safe {
            evm_network: network,
            client: client,
            wallet: None,
            sk: None,
        };

        if let Some(sk) = secret {
            safe.login(Some(sk))
        } else {
            Ok(safe)
        }
    }

    // if eth_privkey is None, it will be randomized.
    pub fn login_with_eth(&mut self, eth_privkey: Option<String>) -> Result<Safe> {
        let eth_pk = eth_privkey.unwrap_or(SecretKey::random().to_hex()); // bls secret key can be used as eth privkey

        println!("\n\neth_pk: {:?}", eth_pk);

        let wallet = Wallet::new_from_private_key(self.evm_network.clone(), &eth_pk)?;

        let eth_pk = EvmBytes::from_str(&eth_pk)
            .map_err(|e| Error::Custom(format!("Eth privkey parse: {}", e)))?;
        let root_sk = SecretKey::from_hex(ROOT_SK).unwrap();
        // TODO: is it secure? can it be reverse-engineered, that means derivation index (eth_pk) can be reproduced from derived sk?
        let sk = root_sk.derive_child(&eth_pk);
        println!("\n\nsk: {:?}", sk);

        Ok(Safe {
            evm_network: self.evm_network.clone(),
            client: self.client.clone(),
            wallet: Some(wallet),
            sk: Some(sk),
        })
    }

    // if secret is None, it will be randomized.
    pub fn login(&mut self, secret: Option<SecretKey>) -> Result<Safe> {
        self.login_with_eth(secret.map(|sk| SecretKey::to_hex(&sk))) // bls secret key can be used as eth privkey
    }

    pub async fn reg_create(
        &mut self,
        data: &[u8],
        meta: &XorName,
    ) -> Result<()> {

        println!("\n\nUploading data: {:?}...", data);

        let data_address = self.upload(data).await?;

        println!("\n\nCreating graph entry...");

        let ge_meta = registers::XorNameBuilder::from(meta).with_str("0").build();
        let ge_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&ge_meta);
        let ge = GraphEntry::new(
            &ge_key,
            vec![],
            data_address.0,
            vec![],
        );
        let (_attos, _xorname) = self.client.graph_entry_put(ge, PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?)).await?; // TODO: what will happen if someone already created a graph entry under this address? we have to proceed then to next step, in case when creating a Reg failed at the pointer creation step last time, and now we want to retry that.

        println!("\n\nCreating counter pointer...");

        let pointer_meta = registers::XorNameBuilder::from(meta)
                .with_str("counter").build();
        let pointer_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&pointer_meta);
        let (_attos, _address) = self.client.pointer_create(
            &pointer_key,
            PointerTarget::PointerAddress(PointerAddress::from_owner(pointer_key.public_key())), // todo: ZERO target, https://github.com/maidsafe/autonomi/issues/2735
            PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?),
        ).await?;

        Ok(())
    }

    pub async fn reg_write(
        &self,
        data: &[u8],
        meta: &XorName,
    ) -> Result<()> {

        println!("\n\nGetting counter pointer...");

        let pointer_meta = registers::XorNameBuilder::from(meta)
                .with_str("counter").build();
        let pointer_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&pointer_meta);
        let pointer = self.client.pointer_get(&PointerAddress::from_owner(pointer_key.public_key())).await?;

        println!("\n\nWriting data...");

        let data_address = self.upload(data).await?;

        println!("\n\nNew graph entry...");

        let ge_index = pointer.counter();
        println!("ge_index {}", ge_index);
        let ge_meta = registers::XorNameBuilder::from(meta)
                .with_str(&format!("{}", ge_index)).build();
        let ge_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&ge_meta);
        let new_tail_ge = GraphEntry::new(
            &ge_key,
            vec![],
            data_address.0,
            vec![],
        );
//        let tail_ge_xorname = new_tail_ge.address().xorname().to_vec();
        let (_attos, _xorname) = self.client.graph_entry_put(new_tail_ge, PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?)).await?; // TODO: what will happen if someone already created a graph entry under this address? we have to proceed then to next step, in case when creating a Reg failed at the pointer creation step last time, and now we want to retry that.

        println!("\n\nIncrementing counter pointer...");

        self.client.pointer_update(
            &pointer_key,
            PointerTarget::PointerAddress(PointerAddress::from_bytes(&[])?), // ZERO target
        ).await?;

        Ok(())
    }

    pub async fn read_reg(&self, meta: &XorName, version: Option<u32>) -> Result<Vec<u8>> {

        let version: u32 = if let Some(v) = version {
            v
        } else {
            println!("\n\nReading counter pointer...");
            let pointer_meta = registers::XorNameBuilder::from(meta)
                    .with_str("counter").build();
            let pointer_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&pointer_meta);
            let pointer = self.client.pointer_get(&PointerAddress::from_owner(pointer_key.public_key())).await?;

            pointer.counter() - 1
        };

        println!("\n\nReading graph entry...");
        println!("version {}", version);

        let ge_meta = registers::XorNameBuilder::from(meta)
                .with_str(&format!("{}", version)).build();
        let ge_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&ge_meta);
        let gentriess = self.client.graph_entry_get(&GraphEntryAddress::from_owner(ge_key.public_key())).await;
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
        Ok(self.download(&data_address).await?)
    }

    pub async fn upload(&self, data: &[u8]) -> Result<XorName> {
        let (_attos, xorname) = self
            .client
            .data_put_public(
                Bytes::copy_from_slice(data),
                PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?),
            )
            .await?;
        Ok(xorname)
    }

    pub async fn download(&self, address: &XorName) -> Result<Vec<u8>> {
        let data = self.client.data_get_public(address).await?;
        Ok(data.to_vec()) // TODO: Vec instead of Bytes result in Autonomi API
    }

    pub fn address(&self) -> Result<EvmAddress> {
        self.wallet
            .as_ref()
            .ok_or(Error::NotLoggedIn)
            .map(Wallet::address)
    }

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
