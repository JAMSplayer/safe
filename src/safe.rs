pub use bls::{serde_impl::SerdeSecret, SecretKey};
pub use libp2p::Multiaddr;

use crate::error::{Error, Result};

pub struct Safe {
    verify_store: bool,
    show_holders: bool,
    enable_gossip: bool,
    batch_size: usize,
}

impl Default for Safe {
    fn default() -> Safe {
        Safe {
            verify_store: false,
            show_holders: false,
            enable_gossip: false,
            batch_size: 4,
        }
    }
}

impl Safe {
    pub fn connect(
        &self,
        peers: Vec<Multiaddr>,
        secret: Option<SecretKey>,
    ) -> Result<Option<SerdeSecret<SecretKey>>> {
        println!(
            "connect() secret: {:?}",
            &secret.as_ref().unwrap_or(&SecretKey::default()).to_hex()
        );

        let (generated, sk) = match secret {
            Some(sk) => (false, sk),
            None => (true, SecretKey::random()),
        };

        return Ok(match generated {
            false => None,
            true => Some(SerdeSecret(sk)),
        });
        //    	Ok(Some(SerdeSecret(SecretKey::random())))
        //    	Err(Error::Custom(String::from("Test")))
    }
}

// connect (node_ids, user_keys_and_wallet) -> safe_handle

// create register (hash) -> xor address
