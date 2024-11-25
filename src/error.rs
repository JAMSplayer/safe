use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Custom(str) => {
                write!(f, "safe: {}", str)
            }
        }
    }
}

impl std::error::Error for Error {}

//impl From<sn_client::Error> for Error {
//    fn from(client_error: sn_client::Error) -> Self {
//        Error::Custom(format!("client: {}", client_error))
//    }
//}

impl From<sn_peers_acquisition::error::Error> for Error {
    fn from(peers_acquisition_error: sn_peers_acquisition::error::Error) -> Self {
        Error::Custom(format!("peers_acquisition: {}", peers_acquisition_error))
    }
}

//impl From<sn_transfers::WalletError> for Error {
//    fn from(wallet_error: sn_transfers::WalletError) -> Self {
//        Error::Custom(format!("transfers: {}", wallet_error))
//    }
//}

//impl From<sn_logging::Error> for Error {
//	fn from(logging_error: sn_logging::Error) -> Self {
//		Error::Custom(format!("logging: {}", logging_error))
//	}
//}

impl From<autonomi::client::ConnectError> for Error {
    fn from(err: autonomi::client::ConnectError) -> Self {
        Error::Custom(format!("connect: {}", err))
    }
}

impl From<autonomi::client::registers::RegisterError> for Error {
    fn from(err: autonomi::client::registers::RegisterError) -> Self {
        Error::Custom(format!("register: {}", err))
    }
}

impl From<evmlib::utils::Error> for Error {
    fn from(err: evmlib::utils::Error) -> Self {
        Error::Custom(format!("evm utils: {}", err))
    }
}

impl From<evmlib::wallet::Error> for Error {
    fn from(err: evmlib::wallet::Error) -> Self {
        Error::Custom(format!("evm wallet: {}", err))
    }
}

impl From<evmlib::contract::network_token::Error> for Error {
    fn from(err: evmlib::contract::network_token::Error) -> Self {
        Error::Custom(format!("evm token: {}", err))
    }
}
