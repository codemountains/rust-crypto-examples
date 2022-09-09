use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::anyhow;
use data_encoding::HEXLOWER;
use dotenv::dotenv;
use std::{env, str};

struct EncryptionKey(String);
struct EncryptionNonce(String);

impl From<String> for EncryptionKey {
    fn from(key: String) -> Self {
        Self(key)
    }
}

impl From<String> for EncryptionNonce {
    fn from(nonce: String) -> Self {
        Self(nonce)
    }
}

fn main() -> anyhow::Result<()> {
    let (encryption_key, encryption_nonce) = init()?;
    let key = encryption_key.0.as_bytes();
    let nonce = encryption_nonce.0.as_bytes();

    // contents to be encrypted
    let contents = "plain text".to_string();

    // encryption
    let encrypted_contents =
        aes_encrypt(contents.as_bytes(), key, nonce).map_err(|e| anyhow!(e))?;
    println!("{:?}", encrypted_contents);

    // encode
    let encoded_contents = HEXLOWER.encode(&encrypted_contents);
    println!("{}", encoded_contents);

    // decode
    let decoded_contents = HEXLOWER
        .decode(encoded_contents.as_ref())
        .map_err(|e| anyhow!(e))?;
    println!("{:?}", decoded_contents);

    // decryption
    let plain_text = aes_decrypt(&encrypted_contents, key, nonce).map_err(|e| anyhow!(e))?;
    let decrypted_contents: &str = str::from_utf8(&plain_text)?;
    println!("{}", decrypted_contents);

    assert_eq!(&contents, decrypted_contents);

    Ok(())
}

fn init() -> anyhow::Result<(EncryptionKey, EncryptionNonce)> {
    dotenv().ok();

    let key = env::var_os("AES_GCM_KEY")
        .expect("AES_GCM_KEY is undefined.")
        .into_string()
        .map_err(|_| anyhow!("AES_GCM_KEY is invalid value."))?
        .into();

    // Nonce: 96-bits; unique per message
    let nonce = env::var_os("AES_GCM_NONCE")
        .expect("AES_GCM_NONCE is undefined.")
        .into_string()
        .map_err(|_| anyhow!("AES_GCM_NONCE is invalid value."))?
        .into();

    Ok((key, nonce))
}

fn aes_encrypt(contents: &[u8], key: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(nonce);

    // encryption
    let cipher = Aes256Gcm::new(key);
    cipher
        .encrypt(nonce, contents.as_ref())
        .map_err(|e| anyhow!(e))
}

fn aes_decrypt(cipher_text: &[u8], key: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(nonce);

    // decryption
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, cipher_text).map_err(|e| anyhow!(e))
}
