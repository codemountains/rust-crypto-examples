use anyhow::anyhow;
use dotenv::dotenv;
use pbkdf2::password_hash::{Ident, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::{Params, Pbkdf2};
use std::env;

struct EncryptionData {
    salt: String,
    variant: String,
    iteration: u32,
    output_len: usize,
}

impl EncryptionData {
    fn new(salt: String, variant: String, iteration: u32, output_len: usize) -> Self {
        Self {
            salt,
            variant,
            iteration,
            output_len,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let encryption_data = init()?;

    let password = "password".to_string();

    pbkdf2_default(&password, &encryption_data)?;
    pbkdf2_custom(&password, &encryption_data)?;

    Ok(())
}

fn pbkdf2_default(password: &str, encryption_data: &EncryptionData) -> anyhow::Result<()> {
    let bin_password = password.as_bytes();

    let salt_string = SaltString::new(&encryption_data.salt).map_err(|e| anyhow!(e))?;
    println!("salt: {}", salt_string);

    // Hash password to PHC string ($pbkdf2-sha256$...)
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    let password_hash = Pbkdf2
        .hash_password(bin_password, &salt_string)
        .map_err(|e| anyhow!(e))?
        .to_string();
    println!("PHC string: {}", password_hash);

    // Verify password against PHC string
    // let phc_string = format!(
    //     "${}$i={},l={}${}${}",
    //     phc.variant,
    //     phc.iteration,
    //     salt_string.len(),
    //     salt_string,
    //     password_hash.hash.ok_or(anyhow!("hash error"))?
    // );
    let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| anyhow!(e))?;
    println!(
        "{}",
        Pbkdf2.verify_password(bin_password, &parsed_hash).is_ok()
    );

    Ok(())
}

fn pbkdf2_custom(password: &str, encryption_data: &EncryptionData) -> anyhow::Result<()> {
    let bin_password = password.as_bytes();

    let salt_string = SaltString::new(&encryption_data.salt).map_err(|e| anyhow!(e))?;
    println!("salt: {}", salt_string);

    // PBKDF2 with customized params
    let ident = Ident::try_from(encryption_data.variant.as_str()).map_err(|e| anyhow!(e))?;

    let params = Params {
        rounds: encryption_data.iteration,
        output_length: encryption_data.output_len,
    };

    // Hash password to PHC string ($pbkdf2-sha256$...)
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    let password_hash = Pbkdf2
        .hash_password_customized(bin_password, Some(ident), None, params, &salt_string)
        .map_err(|e| anyhow!(e))?
        .to_string();
    println!("PHC string: {}", password_hash);

    let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| anyhow!(e))?;
    println!(
        "{}",
        Pbkdf2.verify_password(bin_password, &parsed_hash).is_ok()
    );

    Ok(())
}

fn init() -> anyhow::Result<EncryptionData> {
    dotenv().ok();

    let salt = env::var_os("PBKDF2_PHC_SALT")
        .expect("PBKDF2_PHC_SALT is undefined.")
        .into_string()
        .map_err(|_| anyhow!("PBKDF2_PHC_SALT is invalid value."))?;
    let variant = env::var_os("PBKDF2_PHC_VARIANT")
        .expect("PBKDF2_PHC_VARIANT is undefined.")
        .into_string()
        .map_err(|_| anyhow!("PBKDF2_PHC_VARIANT is invalid value."))?;
    let iteration = env::var_os("PBKDF2_PHC_ITERATION")
        .expect("PBKDF2_PHC_ITERATION is undefined.")
        .into_string()
        .map_err(|_| anyhow!("PBKDF2_PHC_ITERATION is invalid value."))?
        .parse::<u32>()?;
    let output_len = env::var_os("PBKDF2_PHC_OUTPUT_LEN")
        .expect("PBKDF2_PHC_OUTPUT_LEN is undefined.")
        .into_string()
        .map_err(|_| anyhow!("PBKDF2_PHC_OUTPUT_LEN is invalid value."))?
        .parse::<usize>()?;

    Ok(EncryptionData::new(salt, variant, iteration, output_len))
}
