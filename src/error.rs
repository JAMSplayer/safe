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

impl From<sn_client::Error> for Error {
    fn from(client_error: sn_client::Error) -> Self {
        Error::Custom(format!("client: {}", client_error))
    }
}

impl From<sn_peers_acquisition::error::Error> for Error {
    fn from(peers_acquisition_error: sn_peers_acquisition::error::Error) -> Self {
        Error::Custom(format!("peers_acquisition: {}", peers_acquisition_error))
    }
}

//impl From<sn_logging::Error> for Error {
//	fn from(logging_error: sn_logging::Error) -> Self {
//		Error::Custom(format!("logging: {}", logging_error))
//	}
//}
