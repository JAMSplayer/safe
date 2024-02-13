mod error;
mod safe;

use serde::{de::Deserialize, ser::Serialize};

pub use safe::*;

// write to register (hash, data)

// read from register (hash)
