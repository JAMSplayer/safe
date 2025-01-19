use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    NotConnected,
    NotLoggedIn,
    Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Custom(s) => f.write_str(&s),
            _ => {
                write!(f, "{:?}", self)
            }
        }
    }
}

impl std::error::Error for Error {}


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

impl From<autonomi::client::data::PutError> for Error {
    fn from(err: autonomi::client::data::PutError) -> Self {
        Error::Custom(format!("put: {}", err))
    }
}

impl From<autonomi::client::data::GetError> for Error {
    fn from(err: autonomi::client::data::GetError) -> Self {
        Error::Custom(format!("get: {}", err))
    }
}

impl From<autonomi::client::transactions::TransactionError> for Error {
    fn from(err: autonomi::client::transactions::TransactionError) -> Self {
        Error::Custom(format!("transaction: {}", err))
    }
}

impl From<autonomi::client::vault::VaultError> for Error {
    fn from(err: autonomi::client::vault::VaultError) -> Self {
        Error::Custom(format!("vault: {}", err))
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
