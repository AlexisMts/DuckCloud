use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use argon2::password_hash::SaltString;
use rand_core::OsRng;

// Function to create a password hash using Argon2
pub fn create_password_hash(master_password_hash: &[u8]) -> Result<String> {
    // Generate a random salt for password hashing
    let salt = SaltString::generate(&mut OsRng);

    // Create an Argon2 instance with specific parameters
    let argon2 = Argon2::new(
        Algorithm::Argon2id,   // Use Argon2id algorithm
        Version::V0x13,        // Use Argon2 version 0x13
        Params::new(64 * 1024, 3, 1, Some(32)).unwrap() // Parameters for memory, iterations, parallelism, and hash length
    );

    // Hash the master password using Argon2
    let password_hash = argon2.hash_password(master_password_hash, &salt)
        .map_err(|e| anyhow!(e.to_string()))?
        .to_string();

    Ok(password_hash)
}

// Function to verify a password hash against a master password
pub fn verify_password_hash(master_password_hash: &[u8], password_hash: &[u8]) -> Result<()> {
    // Convert the password hash bytes to a string
    let password_hash_str = String::from_utf8(password_hash.to_vec().clone())
        .map_err(|e| anyhow!("Failed to convert password hash to string: {}", e))?;

    // Parse the password hash string into a PasswordHash structure
    let parsed_hash = PasswordHash::new(password_hash_str.as_str())
        .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;

    // Create an Argon2 instance with the same parameters as during hashing
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 3, 1, Some(32)).unwrap()
    );

    // Verify the master password against the parsed hash
    argon2.verify_password(master_password_hash, &parsed_hash)
        .map_err(|e| anyhow!(e.to_string()))
}
