pub use crate::error::{Error, Result};
pub use bls::{serde_impl::SerdeSecret, SecretKey};
pub use libp2p::Multiaddr;

use tracing::Level;
use serde::{de::Deserialize, ser::Serialize};
use xor_name::XorName;
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


mod registers {
    use xor_name::{XorName, xor_name};

    enum EntryContent {
        Data(Vec<u8>), // when data_size < max_entry
        SingleChunkAddress(XorName), // when data_size < max_chunk
        DataMap(self_encryption::DataMap), // when data_size > max_chunk and datamap_size < max_entry
        DataMapAddress(XorName), // when data_size > max_chunk and datamap_size > max_entry
        Registers(Vec<XorName>), // subdirectory
    }

    struct Entry(String, EntryContent);
    
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
                let other = XorName::from_content_parts(self.sources);
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
            let x = XorName::random(&mut rand::thread_rng());
    
            let x1: XorName = XorNameBuilder
                ::from(&x)
                .build();

            assert_eq!(x.0, x1.0);
                
            let x2: XorName = XorNameBuilder
                ::from(&x)
                .with_str("test")
                .build();
            
            assert_ne!(x1.0, x2.0);

            let x3: XorName = XorNameBuilder
                ::from(&x1)
                .with_bytes("test".as_bytes())
                .build();
            
            assert_eq!(x2.0, x3.0);
        }
    }
    
}

// TODO: tests

