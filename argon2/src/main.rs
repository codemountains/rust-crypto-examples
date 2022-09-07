use anyhow::anyhow;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use dotenv::dotenv;
use std::env;

struct PHCString {
    salt: String,
    variant: String,
    version: String,
    time_cost: String,
    memory_cost: String,
    parallelism_cost: String,
}

impl PHCString {
    fn new(
        salt: String,
        variant: String,
        version: String,
        time_cost: String,
        memory_cost: String,
        parallelism_cost: String,
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
    let phc = init()?;

    let password = "password".to_string();
    let bin_password = password.as_bytes();

    let salt_string = SaltString::new(&phc.salt).map_err(|e| anyhow!(e))?;
    println!("salt: {}", salt_string);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    let password_hash = argon2
        .hash_password(bin_password, &salt_string)
        .map_err(|e| anyhow!(e))?;
    println!("PHC string: {}", password_hash);

    // Verify password against PHC string.
    let phc_string = format!(
        "${}$v={}$m={},t={},p={}${}${}",
        phc.variant,
        phc.version,
        phc.memory_cost,
        phc.time_cost,
        phc.parallelism_cost,
        salt_string,
        password_hash.hash.ok_or(anyhow!("hash error"))?
    );
    let parsed_hash = PasswordHash::new(&phc_string).map_err(|e| anyhow!(e))?;
    println!(
        "authentication result: {}",
        Argon2::default()
            .verify_password(bin_password, &parsed_hash)
            .is_ok()
    );

    Ok(())
}

fn init() -> anyhow::Result<PHCString> {
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
        .map_err(|_| anyhow!("ARGON2_PHC_VERSION is invalid value."))?;
    let time_cost = env::var_os("ARGON2_PHC_TIME_COST")
        .expect("ARGON2_PHC_TIME_COST is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_TIME_COST is invalid value."))?;
    let memory_cost = env::var_os("ARGON2_PHC_MEMORY_COST")
        .expect("ARGON2_PHC_MEMORY_COST is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_MEMORY_COST is invalid value."))?;
    let parallelism_cost = env::var_os("ARGON2_PHC_PARALLELISM_COST")
        .expect("ARGON2_PHC_PARALLELISM_COST is undefined.")
        .into_string()
        .map_err(|_| anyhow!("ARGON2_PHC_PARALLELISM_COST is invalid value."))?;

    Ok(PHCString::new(
        salt,
        variant,
        version,
        time_cost,
        memory_cost,
        parallelism_cost,
    ))
}
