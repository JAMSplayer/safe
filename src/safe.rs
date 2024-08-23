pub use crate::error::{Error, Result};
pub use bls::{PublicKey, SecretKey};
pub use libp2p::Multiaddr;
pub use sn_registers::Permissions;

use sn_client::{Client, ClientRegister, WalletClient};
use sn_transfers::{HotWallet, MainSecretKey, NanoTokens, Transfer};
use std::{path::PathBuf, time::Duration};
use tracing::Level;
use xor_name::XorName;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Safe {
    pub client: Client,
    wallet_dir: PathBuf,
    sk: SecretKey,
}

type PaymentResult<T> = Result<(T, NanoTokens, NanoTokens)>;

impl Safe {
    pub async fn connect(
        peers: Vec<Multiaddr>,
        secret: Option<SecretKey>,
        wallet_dir: PathBuf,
    ) -> Result<Safe> {
        let sk = secret.unwrap_or(SecretKey::random());

        println!("Connecting...");

        let client = Client::new(sk.clone(), Some(peers), Some(CONNECTION_TIMEOUT), None).await?;

        println!("Client created.");

        Ok(Safe {
            client: client,
            wallet_dir: wallet_dir,
            sk: sk,
        })
    }

    pub async fn register_create(
        &mut self,
        meta: XorName,
        perms: Option<Permissions>,
    ) -> PaymentResult<ClientRegister> {
        let perms = perms.unwrap_or(only_owner_can_write());
        let register_with_payment = ClientRegister::create_online(
            self.client.clone(),
            meta,
            &mut self.wallet_client()?,
            true,
            perms,
        )
        .await?;

        // let public_key = self.client.signer_pk();
        // let register = Register::new(public_key, meta, perms);
        Ok(register_with_payment)
    }

    pub async fn receive(&self, transfer: String) -> Result<()> {
        let transfer =
            Transfer::from_hex(&transfer).map_err(|e| Error::Custom(format!("transfer: {}", e)))?;
        println!("Successfully parsed transfer");

        let mut wallet = self.hot_wallet()?;
        let cashnotes = self.client.receive(&transfer, &wallet).await?;
        println!(
            "Successfully verified transfer. Cashnotes: {:?}",
            &cashnotes
        );

        let old_balance = wallet.balance();
        wallet.deposit_and_store_to_disk(&cashnotes)?;
        let new_balance = wallet.balance();
        println!("Successfully stored cash_note to wallet dir. \nOld balance: {old_balance}\nNew balance: {new_balance}");

        Ok(())
    }

    pub fn init_logging() -> Result<()> {
        let logging_targets = vec![
            ("sn_networking".to_string(), Level::DEBUG),
            ("safe".to_string(), Level::TRACE),
            ("sn_build_info".to_string(), Level::TRACE),
            ("sn_cli".to_string(), Level::TRACE),
            ("sn_client".to_string(), Level::TRACE),
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

    pub fn address(&self) -> Result<PublicKey> {
        Ok(self.hot_wallet()?.address().public_key())
    }

    pub fn balance(&self) -> Result<u64> {
        Ok(self.hot_wallet()?.balance().as_nano())
    }

    fn hot_wallet(&self) -> Result<HotWallet> {
        let wallet =
            HotWallet::load_from_path(&self.wallet_dir, Some(MainSecretKey::new(self.sk.clone())))?;
        println!("Wallet created.");
        Ok(wallet)
    }

    fn wallet_client(&self) -> Result<WalletClient> {
        Ok(WalletClient::new(self.client.clone(), self.hot_wallet()?))
    }
}

fn only_owner_can_write() -> Permissions {
    Permissions::default()
}

// create_register(address: Option<XorAddress>, data: Vec<u8>) -> Result<XorAddress>
//      ! if address is None, that means it should be assigned a random address
//      ? exists / squatted
//
// read_register(address: XorAddress) -> Result<Vec<u8>>
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
}
