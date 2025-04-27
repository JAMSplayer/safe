//! Alternative API to access [`Autonomi Network`]. Focusing on being as simple as possible and cover most common usecases.
//! ```no_run
//! use safeapi::{Network, Safe, XorNameBuilder};
//! # use tokio;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), safeapi::Error> {
//! // connect to mainnet
//! let mut safe = Safe::connect(Network::Mainnet, None, "INFO").await?;
//!
//! # let key_data = std::fs::read("/encrypted/secret_key.json").unwrap();
//! // [...] read key_data from a file
//! let secret_key = Safe::decrypt(&key_data, "password")?;
//! safe.login(Some(secret_key))?;
//!
//! let data_name = safe.upload(&[10, 11, 12]).await?;
//! let related_reg_name = XorNameBuilder::from(&data_name).with_str("related").build();
//!
//! safe.reg_create(&[1, 2, 3], &related_reg_name).await?;
//!
//! // if you store data_name somewhere, also related_reg_name could be recreated to read both data and Reg.
//! # Ok(())
//! # }
//! ```
//!
//! [`Autonomi Network`]: https://autonomi.com/

mod error;
mod logging;
mod safe;
mod secure_sk;

pub use safe::*;
