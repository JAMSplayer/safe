pub use crate::error::{Error, Result};
pub use bls::{serde_impl::SerdeSecret, SecretKey};
pub use libp2p::Multiaddr;

use tracing::Level;
use serde::{de::Deserialize, ser::Serialize};
use sn_client::Client;

pub struct Safe {
    client: Client,
    //    wallet: WalletClient,
}

impl Safe {
    pub async fn connect(peers: Vec<Multiaddr>, secret: Option<SecretKey>) -> Result<Self> {
        Self::init_logging()?;

        println!(
            "connect() secret: {:?}",
            &secret.as_ref().unwrap_or(&SecretKey::default()).to_hex()
        );
        let sk = secret.unwrap_or(SecretKey::random());

        let not_empty_peers =
            sn_peers_acquisition::get_peers_from_args(sn_peers_acquisition::PeersArgs {
                first: false,
                peers: peers,
                network_contacts_url: None,
            })
            .await?;

        let client = Client::new(sk, Some(not_empty_peers), false, None, None).await?;
        let safe = Self { client: client };

        return Ok(safe);
        //    	Ok(Some(SerdeSecret(SecretKey::random())))
        //    	Err(Error::Custom(String::from("Test")))
    }

    fn init_logging() -> Result<()> {
        let logging_targets = vec![
            // TODO: Reset to nice and clean defaults once we have a better idea of what we want
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
            .map_err(|e| format!("logging: {}", e));
        //        let _ = log_builder.initialize()?;

        Ok(())
    }
}

// create register (hash) -> xor address


// upload_file(data: Vec<u8>) -> Result<XorAddress>
//      ? already uploaded
// 
// read_file()
// → sn_client::file::download::read()
//
// create_register(data: Vec<u8>, address: Option<XorAddress>) -> Result<XorAddress>
//      ? exists / squatted
//
// update_register(new_data: Vec<u8>, address: XorAddress) -> Result<XorAddress>
//
// read_register(address: XorAddress) -> Result<Vec<u8>>
//
// hash(xor_addr).with(data2).with(data3).xor_addr()
//

// TODO: tests

