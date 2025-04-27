use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    NotConnected,
    NotLoggedIn,
    BadPassword,
    SecretKeyEncryption(String),
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


impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Custom(err)
    }
}

impl From<autonomi::client::ConnectError> for Error {
    fn from(err: autonomi::client::ConnectError) -> Self {
        Error::Custom(format!("connect: {}", err))
    }
}

impl From<autonomi::client::PutError> for Error {
    fn from(err: autonomi::client::PutError) -> Self {
        Error::Custom(format!("put: {}", err))
    }
}

impl From<autonomi::client::GetError> for Error {
    fn from(err: autonomi::client::GetError) -> Self {
        Error::Custom(format!("get: {}", err))
    }
}

impl From<autonomi::client::data_types::graph::GraphError> for Error {
    fn from(err: autonomi::client::data_types::graph::GraphError) -> Self {
        Error::Custom(format!("transaction: {}", err))
    }
}

impl From<autonomi::pointer::PointerError> for Error {
    fn from(err: autonomi::pointer::PointerError) -> Self {
        Error::Custom(format!("pointer: {}", err))
    }
}

impl From<autonomi::EvmUtilError> for Error {
    fn from(err: autonomi::EvmUtilError) -> Self {
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

impl From<rmp_serde::decode::Error> for Error {
    fn from(err: rmp_serde::decode::Error) -> Self {
        Error::Custom(format!("decode: {}", err))
    }
}

