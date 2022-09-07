use anyhow::anyhow;
use dotenv::dotenv;
use pbkdf2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::Pbkdf2;
use std::env;

struct PHCString {
    salt: String,
    variant: String,
    iteration: String,
}

impl PHCString {
    fn new(salt: String, variant: String, iteration: String) -> Self {
        Self {
            salt,
            variant,
            iteration,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let phc = init()?;

    let password = "password".to_string();
    let bin_password = password.as_bytes();

    let salt_string = SaltString::new(&phc.salt).map_err(|e| anyhow!(e))?;
    println!("salt: {}", salt_string);

    // Hash password to PHC string ($pbkdf2-sha256$...)
    // https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    let password_hash = Pbkdf2
        .hash_password(bin_password, &salt_string)
        .map_err(|e| anyhow!(e))?;
    println!("PHC string: {}", password_hash);

    // Verify password against PHC string
    let phc_string = format!(
        "${}$i={},l={}${}${}",
        phc.variant,
        phc.iteration,
        salt_string.len(),
        salt_string,
        password_hash.hash.ok_or(anyhow!("hash error"))?
    );
    let parsed_hash = PasswordHash::new(&phc_string).map_err(|e| anyhow!(e))?;
    println!(
        "{}",
        Pbkdf2.verify_password(bin_password, &parsed_hash).is_ok()
    );

    Ok(())
}

fn init() -> anyhow::Result<PHCString> {
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
        .map_err(|_| anyhow!("PBKDF2_PHC_ITERATION is invalid value."))?;

    Ok(PHCString::new(salt, variant, iteration))
}
