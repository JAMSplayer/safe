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
        		write!(f, "safe error: \"{}\"", str)
    		}
    	}
    }
}

impl std::error::Error for Error {}
