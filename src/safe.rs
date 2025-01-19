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

use alloy_primitives::Bytes as EvmBytes;
use ant_protocol::storage::TransactionAddress;
use autonomi::{
    get_evm_network_from_env,
    Wallet,
    client::{
        payment::PaymentOption,
        transactions::Transaction,
    },
    ClientConfig,
};
use bytes::Bytes;
use std::str::FromStr;
use std::time::Duration;
use tracing::Level;

const ROOT_SK: &str = "160922b4d2b35fec6b7a36a54c9793bea0fdef00c2630b4361e7a92546f05993"; // could be anything, it does not have to be secred, because it's only used as a base for derivation. Changing this will make all Autonomi data created before UNACCESSIBLE!!

const SAFE_REG_TYPE: u64 = 0x90B2F5FFF5A18393u64; // first 8 bytes of "safe-reg" SHA256 hash

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

        let client = Client::init_with_config(ClientConfig {
            local: !add_network_peers,
            peers: Some(peers),
        }).await?;

        let mut safe = Safe {
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

        let network = get_evm_network_from_env()?;
        let wallet = Wallet::new_from_private_key(network, &eth_pk)?;

        let eth_pk = EvmBytes::from_str(&eth_pk)
            .map_err(|e| Error::Custom(format!("Eth privkey parse: {}", e)))?;
        let root_sk = SecretKey::from_hex(ROOT_SK).unwrap();
        // TODO: is it secure? can it be reverse-engineered, that means derivation index (eth_pk) can be reproduced from derived sk?
        let sk = root_sk.derive_child(&eth_pk);
        println!("\n\nsk: {:?}", sk);

        Ok(Safe {
            client: self.client.clone(),
            wallet: Some(wallet),
            sk: Some(sk),
        })
    }

    // if secret is None, it will be randomized.
    pub fn login(&mut self, secret: Option<SecretKey>) -> Result<Safe> {
        self.login_with_eth(secret.map(|sk| SecretKey::to_hex(&sk))) // bls secret key can be used as eth privkey
    }

    // allows using XorNameBuilder with Xor when you need a deeper naming structure.
    // when perms is None, only owner can write to the register.
    pub async fn register_create(
        &mut self,
        data: Vec<u8>,
        meta: &XorName,
        perms: Option<RegisterPermissions>,
    ) -> Result<Register> {
        let perms = perms.unwrap_or(self.only_owner_can_write()?);

        if let Some(_) = self.wallet.as_ref().and(self.sk.as_ref()) {
            Ok(self
                .client
                .register_create_with_permissions(
                    Some(data.into()),
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

    pub async fn reg_create(
        &mut self,
        data: Vec<u8>,
        meta: &XorName,
    ) -> Result<()> {

//        if self.sk.is_none() || self.wallet.is_none() {
//            return Err(Error::NotLoggedIn);
//        }

        println!("\n\nUploading data...");

        // put data into chunk
        let data_address = self.upload(data).await?;

        println!("\n\nCreating transaction...");

        // create transaction
        let tx_meta = registers::XorNameBuilder::from(meta).with_str("0").build();
        let tx_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&tx_meta);
        let tx = Transaction::new(
            tx_key.public_key(),
            vec![],
            data_address.0,
            vec![],
            &tx_key,
        );
        self.client.transaction_put(tx, &self.wallet.clone().ok_or(Error::NotLoggedIn)?).await?; // TODO: what will happen if someone already created a transaction under this address? we have to proceed then to next step, in case when creating a Reg failed at the Vault creation step last time, and now we want to retry that.

        println!("\n\nCreating vault...");

        // create vault
        let vault_meta = registers::XorNameBuilder::from(meta)
                .with_str("counter").build();
        let vault_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&vault_meta);
        let _attos = self.client.write_bytes_to_vault(
            Bytes::new(),
            PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?),
            &vault_key,
            SAFE_REG_TYPE,
        ).await?;

        Ok(())
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

    pub async fn register_write(&self, reg: &Register, data: Vec<u8>) -> Result<()> {
        let reg = reg.clone(); // TODO: wait for resolving upstream issue: https://github.com/maidsafe/safe_network/issues/2396
        if let Some(sk) = &self.sk {
            Ok(self
                .client
                .register_update(reg, data.into(), sk.clone())
                .await?)
        } else {
            Err(Error::NotLoggedIn)
        }
    }

    pub async fn reg_write(
        &self,
        data: Vec<u8>,
        meta: &XorName,
    ) -> Result<()> {

        println!("\n\nGetting count scratchpad...");

        let vault_meta = registers::XorNameBuilder::from(meta)
                .with_str("counter").build();
        let vault_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&vault_meta);
        let vault = self.client.get_or_create_scratchpad(&vault_key, SAFE_REG_TYPE).await?;
        if vault.1 { // is new
            return Err(Error::Custom(format!("Could not find vault: {:?}", vault_key))); // TODO: in next release there will be get_vault_from_network function that errors, when cannot find vault
        }

        println!("\n\nWriting data...");

        let data_address = self.upload(data).await?;

        println!("\n\nNew transaction...");

        let tx_index = vault.0.count();
        println!("tx_index {}", tx_index);
        let tx_meta = registers::XorNameBuilder::from(meta)
                .with_str(&format!("{}", tx_index)).build();
        let tx_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&tx_meta);
        let new_tail_tx = Transaction::new(
            tx_key.public_key(),
            vec![],
            data_address.0,
            vec![], // TODO: can I predict next tx? xorname(meta(i + 1))?
            &tx_key,
        );
        let tail_tx_xorname = new_tail_tx.address().xorname().to_vec();
        self.client.transaction_put(new_tail_tx, &self.wallet.clone().ok_or(Error::NotLoggedIn)?).await?; // TODO: what will happen if someone already created a transaction under this address? we have to proceed then to next step, in case when creating a Reg failed at the Vault creation step last time, and now we want to retry that.

        println!("\n\nIncrementing count scratchpad...");

        let _attos = self.client.write_bytes_to_vault(
            Bytes::new(),
            PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?),
            &vault_key,
            SAFE_REG_TYPE,
        ).await?;

        Ok(())
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

    pub async fn read_reg(&self, meta: &XorName, version: Option<u64>) -> Result<Vec<u8>> {

        let version: u64 = if let Some(v) = version {
            v
        } else {
            println!("\n\nReading vault...");
            let vault_meta = registers::XorNameBuilder::from(meta)
                    .with_str("counter").build();
            let vault_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&vault_meta);
            let vault = self.client.get_or_create_scratchpad(&vault_key, SAFE_REG_TYPE).await?;
            if vault.1 { // is new
                return Err(Error::Custom(format!("Could not find vault: {:?}", vault_key))); // TODO: in next release there will be get_vault_from_network function that errors, when cannot find vault
            }
            vault.0.count() - 1
        };

        println!("\n\nReading transaction...");
        println!("version {}", version);

        let tx_meta = registers::XorNameBuilder::from(meta)
                .with_str(&format!("{}", version)).build();
        let tx_key = self.sk.clone().ok_or(Error::NotLoggedIn)?.derive_child(&tx_meta);
        let txs = self.client.transaction_get(TransactionAddress::from_owner(tx_key.public_key())).await?;
        let tx = txs.first().ok_or(Error::Custom(format!("No transaction for version {}", version)))?;
        // TODO: handle multiple transactions returned. Merge branches? Put all leaves as parents?

        println!("\n\nReading data...");

        let data_address = XorName(tx.content);
        let data = self.client.data_get_public(data_address).await?;
        Ok(data.to_vec())
    }

    pub fn random_register_address(&self) -> Option<RegisterAddress> {
        self.sk.as_ref().map(|sk| {
            RegisterAddress::new(XorName::random(&mut rand::thread_rng()), sk.public_key())
        })
    }

    pub async fn upload(&self, data: Vec<u8>) -> Result<XorName> {
        Ok(self
            .client
            .data_put_public(
                data.into(),
                PaymentOption::Wallet(self.wallet.clone().ok_or(Error::NotLoggedIn)?),
            )
            .await?)
    }

    pub fn init_logging() -> Result<()> {
        let logging_targets = vec![
//            ("ant_networking".to_string(), Level::DEBUG),
            ("ant_networking".to_string(), Level::INFO),
            ("safe".to_string(), Level::TRACE),
            ("ant_build_info".to_string(), Level::TRACE),
            ("autonomi".to_string(), Level::TRACE),
            ("ant_logging".to_string(), Level::TRACE),
//            ("ant_bootstrap".to_string(), Level::TRACE),
            ("ant_bootstrap".to_string(), Level::DEBUG),
            ("ant_protocol".to_string(), Level::TRACE),
            ("ant_registers".to_string(), Level::TRACE),
            ("ant_evm".to_string(), Level::TRACE),
            ("evmlib".to_string(), Level::TRACE),
        ];
        let mut log_builder = ant_logging::LogBuilder::new(logging_targets);
        log_builder.output_dest(ant_logging::LogOutputDest::Stdout);
        log_builder.format(ant_logging::LogFormat::Default);
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
