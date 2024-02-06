use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Sha256, Digest};
use argon2::password_hash::{PasswordHasher, SaltString};
use hkdf::Hkdf;
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, NewAead}, Key, XNonce};
use rand_core::{OsRng, RngCore};
use rsa::{Oaep, pkcs8, RsaPrivateKey, RsaPublicKey};

// Function to create a master key based on a master password and salted username.
pub fn create_master_key(master_password: &str, salt_username: &str) -> Result<String> {
    // Hash the salted username using SHA-256 to create a salt.
    let mut username_hasher = Sha256::new();
    username_hasher.update(salt_username.as_bytes());
    let salt_bytes = username_hasher.finalize();
    let salt = SaltString::encode_b64(salt_bytes.as_slice())
        .map_err(|e| anyhow!(e.to_string()))?;

    // Create an Argon2 hasher with specific parameters.
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(64 * 1024, 3, 1, Some(32)).unwrap());

    // Hash the master password using the generated salt.
    let master_key = argon2.hash_password(master_password.as_bytes(), &salt)
        .map_err(|e| anyhow!(e.to_string()))?.to_string();

    Ok(master_key)
}

// Function to perform HKDF (HMAC-based Key Derivation Function).
pub fn hkdf(master_key: &str, context: &str) -> Result<[u8; 32]> {
    let ikm = master_key.as_bytes();
    let info = context.as_bytes();

    // Create an HKDF instance with SHA-256.
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];

    // Expand the key material using HKDF.
    hk.expand(info, &mut okm)
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(okm)
}

// Function to encrypt data using XChaCha20-Poly1305.
pub fn encrypt_xchacha20_poly1305(key: &[u8], plaintext: &[u8], nonce_option: Option<&[u8]>) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow!("Key must be 32 bytes"));
    }

    // Create a cipher with the provided key.
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let random_bytes: Vec<u8> = match nonce_option {
        Some(n) => n.to_vec(),
        None => {
            let random_bytes: Vec<u8> = random_bytes::<24>().to_vec();
            random_bytes
        }
    };

    let nonce = XNonce::from_slice(&random_bytes);

    // Encrypt the plaintext using XChaCha20-Poly1305.
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow!(e.to_string()))?;

    // Concatenate nonce and ciphertext.
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

// Function to decrypt data using XChaCha20-Poly1305.
pub fn decrypt_xchacha20_poly1305(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow!("Key must be 32 bytes"));
    }

    // Split nonce and ciphertext.
    let (nonce, ciphertext) = ciphertext.split_at(24);

    // Create a cipher with the provided key.
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    // Decrypt the ciphertext using XChaCha20-Poly1305.
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(plaintext)
}

// Function to generate an RSA key pair.
pub fn generate_key_pair_rsa() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let bits = 3072;

    // Generate a new RSA private key with the specified bit length.
    let priv_key = RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|e| anyhow!(e.to_string()))?;
    let pub_key = RsaPublicKey::from(&priv_key);

    Ok((priv_key, pub_key))
}

// Function to encrypt data using RSA with OAEP padding.
pub fn encrypt_rsa_oaep(pub_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();

    // Encrypt the data using the public key and OAEP padding.
    let enc_data = pub_key.encrypt(&mut OsRng, padding, data)
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(enc_data)
}

// Function to decrypt data using RSA with OAEP padding.
pub fn decrypt_rsa_oaep(priv_key: &RsaPrivateKey, enc_data: &[u8]) -> Result<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();

    // Decrypt the data using the private key and OAEP padding.
    let dec_data = priv_key.decrypt(padding, enc_data)
        .map_err(|e| anyhow!(e.to_string()))?;

    Ok(dec_data)
}

// Function to decode an RSA public key from DER-encoded bytes.
pub fn decode_public_key(der_encoded_public_key: &[u8]) -> Result<RsaPublicKey> {
    let public_key: RsaPublicKey = pkcs8::DecodePublicKey::from_public_key_der(der_encoded_public_key)
        .map_err(|e| anyhow!("Failed to decode public key: {}", e))?;

    Ok(public_key)
}

// Function to decode an RSA private key from DER-encoded bytes.
pub fn decode_private_key(der_encoded_private_key: &[u8]) -> Result<RsaPrivateKey> {
    let public_key: RsaPrivateKey = pkcs8::DecodePrivateKey::from_pkcs8_der(der_encoded_private_key)
        .map_err(|e| anyhow!("Failed to decode public key: {}", e))?;

    Ok(public_key)
}

// Function to generate random bytes of a specified length.
pub fn random_bytes<const LENGTH: usize>() -> [u8; LENGTH] {
    let mut key = [0; LENGTH];
    OsRng.fill_bytes(&mut key);
    key
}
