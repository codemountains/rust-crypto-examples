use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::anyhow;
use data_encoding::HEXLOWER;
use rand::seq::SliceRandom;
use std::str;

#[derive(Debug)]
struct EncryptionKey(String);
#[derive(Debug)]
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

const RAND_BASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

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
    let key = gen_rand_string(KEY_SIZE)?.into();
    let nonce = gen_rand_string(NONCE_SIZE)?.into();

    println!("{:?}, {:?}", key, nonce);
    Ok((key, nonce))
}

fn gen_rand_string(size: usize) -> anyhow::Result<String> {
    let mut rng = &mut rand::thread_rng();
    String::from_utf8(
        RAND_BASE
            .as_bytes()
            .choose_multiple(&mut rng, size)
            .cloned()
            .collect(),
    )
    .map_err(|e| anyhow!(e))
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
