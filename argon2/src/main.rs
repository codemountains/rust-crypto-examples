use anyhow::anyhow;
use argon2::password_hash::{Ident, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use dotenv::dotenv;
use std::env;

struct EncryptionData {
    salt: String,
    variant: String,
    version: u32,
    time_cost: u32,
    memory_cost: u32,
    parallelism_cost: u32,
}

impl EncryptionData {
    fn new(
        salt: String,
        variant: String,
        version: u32,
        time_cost: u32,
        memory_cost: u32,
        parallelism_cost: u32,
    ) -> Self {
        Self {
            salt,
            variant,
            version,
            time_cost,
            memory_cost,
            parallelism_cost,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let encryption_data = init()?;

    let password = "password".to_string();

    argon2_default(&password, &encryption_data)?;
    argon2_custom(&password, &encryption_data)?;

    Ok(())
}

fn argon2_default(password: &str, encryption_data: &EncryptionData) -> anyhow::Result<()> {
    let bin_password = password.as_bytes();

    let salt_string = SaltString::new(&encryption_data.salt).map_err(|e| anyhow!(e))?;
    println!("salt: {}", salt_string);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    let password_hash = argon2
        .hash_password(bin_password, &salt_string)
        .map_err(|e| anyhow!(e))?
        .to_string();
    println!("PHC string: {}", password_hash);

    let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| anyhow!(e))?;
    println!(
        "authentication result: {}",
        Argon2::default()
            .verify_password(bin_password, &parsed_hash)
            .is_ok()
    );

    Ok(())
}

fn argon2_custom(password: &str, encryption_data: &EncryptionData) -> anyhow::Result<()> {
    let bin_password = password.as_bytes();

    let salt_string = SaltString::new(&encryption_data.salt).map_err(|e| anyhow!(e))?;
    println!("salt: {}", salt_string);

    // Argon2 with customized params
    let ident = Ident::try_from(encryption_data.variant.as_str()).map_err(|e| anyhow!(e))?;
    let algorithm = Algorithm::try_from(ident).map_err(|e| anyhow!(e))?; // = Algorithm::Argon2id
    let version = Version::try_from(encryption_data.version).map_err(|e| anyhow!(e))?; // = Version::V0x13

    let params = Params::new(
        encryption_data.memory_cost,
        encryption_data.time_cost,
        encryption_data.parallelism_cost,
        None,
    )
    .map_err(|e| anyhow!(e))?;
    let argon2 = Argon2::new(algorithm, version, params);

    // Hash password to PHC string ($argon2id$v=19$...)
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    let password_hash = argon2
        .hash_password(bin_password, &salt_string)
        .map_err(|e| anyhow!(e))?
        .to_string();
    println!("PHC string: {}", password_hash);

    let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| anyhow!(e))?;
    println!(
        "authentication result: {}",
        Argon2::default()
            .verify_password(bin_password, &parsed_hash)
            .is_ok()
    );

    Ok(())
}

fn init() -> anyhow::Result<EncryptionData> {
    dotenv().ok();

    let salt = env::var_os("ARGON2_PHC_SALT")
        .expect("ARGON2_PHC_SALT is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_SALT is invalid value."))?;
    let variant = env::var_os("ARGON2_PHC_VARIANT")
        .expect("ARGON2_PHC_VARIANT is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_VARIANT is invalid value."))?;
    let version = env::var_os("ARGON2_PHC_VERSION")
        .expect("ARGON2_PHC_VERSION is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_VERSION is invalid value."))?
        .parse::<u32>()?;
    let time_cost = env::var_os("ARGON2_PHC_TIME_COST")
        .expect("ARGON2_PHC_TIME_COST is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_TIME_COST is invalid value."))?
        .parse::<u32>()?;
    let memory_cost = env::var_os("ARGON2_PHC_MEMORY_COST")
        .expect("ARGON2_PHC_MEMORY_COST is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_MEMORY_COST is invalid value."))?
        .parse::<u32>()?;
    let parallelism_cost = env::var_os("ARGON2_PHC_PARALLELISM_COST")
        .expect("ARGON2_PHC_PARALLELISM_COST is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_PARALLELISM_COST is invalid value."))?
        .parse::<u32>()?;

    Ok(EncryptionData::new(
        salt,
        variant,
        version,
        time_cost,
        memory_cost,
        parallelism_cost,
    ))
}
