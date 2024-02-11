use std::fmt;
use bls::SecretKey;
use libp2p::PeerId;



type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
	Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	match self {
    		Error::Custom(str) => {
        		write!(f, "safe error: \"{}\"", str)
    		}
    	}
    }
}

impl std::error::Error for Error {}



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
        peers: Vec<String>, // PeerId
        secret: Option<String>, // SecretKey
    ) -> Result<Option<String>> { // SecretKey
    	Ok(Some(String::from("YEAH!")))
//    	Err(Error::Custom(String::from("Test")))
    }
}

// connect (node_ids, user_keys_and_wallet) -> safe_handle

// create register (hash) -> xor address

// write to register (hash, data)

// read from register (hash)
