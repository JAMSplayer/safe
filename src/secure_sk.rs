use super::Error;
use crate::{Safe, SecretKey};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use argon2::{Argon2, ParamsBuilder};
use password_hash::SaltString;
use serde::{Deserialize, Serialize};

const AES_KEY_SIZE: usize = 32;
const ARGON2_ALGO: argon2::Algorithm = argon2::Algorithm::Argon2id;
const ARGON2_VER: argon2::Version = argon2::Version::V0x13;

const ARGON2_ALGO_ID_STR: &str = "Argon2id";
const ARGON2_VER_13_STR: &str = "V0x13";

#[derive(Debug, Serialize, Deserialize)]
enum PassHashAlgo {
    Argon2,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecretKeyFile {
    algorithm: PassHashAlgo,
    param_mcost: u32,
    param_tcost: u32,
    param_pcost: u32,
    param_algo: String,
    param_ver: String,
    salt: Vec<u8>,
    encrypted_sk: Vec<u8>,
}

impl Safe {

    pub fn encrypt_eth(privkey: String, password: &str) -> Result<Vec<u8>, Error> {
        let pk_bytes: &[u8] = privkey.as_bytes();
        common_encrypt(pk_bytes, password)
    }

    pub fn encrypt(sk: SecretKey, password: &str) -> Result<Vec<u8>, Error> {
        let sk_bytes: &[u8] = &sk.to_bytes();
        common_encrypt(sk_bytes, password)
    }

    pub fn decrypt_eth(file_bytes: &[u8], password: &str) -> Result<String, Error> {
        let pk_bytes = common_decrypt(file_bytes, password)?;
        String::from_utf8(pk_bytes)
            .map_err(|e| Error::SecretKeyEncryption(format!("Could not create private key. {}", e)))
    }

    pub fn decrypt(file_bytes: &[u8], password: &str) -> Result<SecretKey, Error> {
        let sk_bytes = common_decrypt(file_bytes, password)?;

        Ok(SecretKey::from_bytes(
            sk_bytes.try_into().map_err(|_| {
                Error::SecretKeyEncryption(String::from("Could not transform bytes representation."))
            })?,
        )
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not create secret key. {}", e)))?)
    }
}

fn common_encrypt(sk_bytes: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    let params = ParamsBuilder::new()
        .output_len(AES_KEY_SIZE)
        .build()
        .unwrap();

    let argon2 = Argon2::new(ARGON2_ALGO, ARGON2_VER, params.clone());

    let salt = SaltString::generate(&mut OsRng);
    let mut aes_key = [0u8; AES_KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut aes_key)
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not create key hash. {}", e)))?;

    let aes = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not init cipher. {}", e)))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let data = aes
        .encrypt(&nonce, sk_bytes)
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not encrypt secret key. {}", e)))?;
    let nonced_data = [&nonce, &data[..]].concat();

    let algo_str = match ARGON2_ALGO {
        argon2::Algorithm::Argon2id => String::from(ARGON2_ALGO_ID_STR),
        _ => {
            panic!("Unexpected Argon2 algorithm");
        }
    };
    let ver_str = match ARGON2_VER {
        argon2::Version::V0x13 => String::from(ARGON2_VER_13_STR),
        _ => {
            panic!("Unexpected Argon2 version");
        }
    };

    let skf = SecretKeyFile {
        algorithm: PassHashAlgo::Argon2,
        param_mcost: params.m_cost(),
        param_tcost: params.t_cost(),
        param_pcost: params.p_cost(),
        param_algo: algo_str,
        param_ver: ver_str,
        salt: Vec::from(salt.as_str()),
        encrypted_sk: Vec::from(nonced_data),
    };

    Ok(serde_json::to_vec(&skf).unwrap())
}

fn common_decrypt(file_bytes: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    let skf: SecretKeyFile = serde_json::from_slice(file_bytes)
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not decode JSON. {}", e)))?;

    let params = ParamsBuilder::new()
        .m_cost(skf.param_mcost)
        .t_cost(skf.param_tcost)
        .p_cost(skf.param_pcost)
        .output_len(AES_KEY_SIZE)
        .build()
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not interpret cipher params. {}", e)))?;

    let algo = match skf.param_algo.as_str() {
        ARGON2_ALGO_ID_STR => argon2::Algorithm::Argon2id,
        _ => {
            panic!("Unexpected Argon2 algorithm");
        }
    };
    let ver = match skf.param_ver.as_str() {
        ARGON2_VER_13_STR => argon2::Version::V0x13,
        _ => {
            panic!("Unexpected Argon2 version");
        }
    };

    let argon2 = Argon2::new(algo, ver, params);

    let mut aes_key = [0u8; AES_KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), &skf.salt[..], &mut aes_key)
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not create key hash. {}", e)))?;

    let aes = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| Error::SecretKeyEncryption(format!("Could not init cipher. {}", e)))?;
    let nonce = &skf.encrypted_sk[0..12];
    let data = &skf.encrypted_sk[12..];
    let sk_bytes: &[u8] = &aes
        .decrypt(nonce.into(), data)
        .map_err(|_| Error::BadPassword)?;
    Ok(Vec::from(sk_bytes))
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn sk_encrypt_decrypt() {
        let sk = SecretKey::random();
        let pass = "testpass";
        let encrypted = Safe::encrypt(sk.clone(), pass).unwrap();
        let decrypted = Safe::decrypt(&encrypted, pass).unwrap();

        assert_eq!(sk, decrypted);
    }

    #[test]
    fn eth_encrypt_decrypt() {
        let pk = SecretKey::random().to_hex();
        let pass = "testpass";
        let encrypted = Safe::encrypt_eth(pk.clone(), pass).unwrap();
        let decrypted = Safe::decrypt_eth(&encrypted, pass).unwrap();

        assert_eq!(pk, decrypted);
    }

    #[test]
    fn eth_with_0x() {
        let mut pk = SecretKey::random().to_hex();
        pk.insert_str(0, "0x");
        let pass = "testpass";
        let encrypted = Safe::encrypt_eth(pk.clone(), pass).unwrap();
        let decrypted = Safe::decrypt_eth(&encrypted, pass).unwrap();

        assert_eq!(pk, decrypted);
    }
}
