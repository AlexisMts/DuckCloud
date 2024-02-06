use rsa::pkcs8;
use crate::client::consts::{CONTEXT_MPH, CONTEXT_SMK};
use crate::client::crypto::*;
use anyhow::{anyhow, Result};
use crate::client::file_manager::*;
use crate::client::session::*;
use crate::models::{DirectoryContentMap, DirectoryMetadata, UserMetadata};

// Function to register keys and create initial user data.
pub fn register_keys_create(username: &str, password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Generate a master key based on the username and password.
    let master_key = create_master_key(password, username)?;
    let stretched_master_key = hkdf(&master_key, CONTEXT_SMK)?;
    let master_password_hash = hkdf(&master_key, CONTEXT_MPH)?.as_ref().to_vec();

    // Generate a user-specific symmetric key.
    let user_symmetric_key = random_bytes::<32>();

    // Generate an RSA key pair for the user.
    let (private_key, public_key) = generate_key_pair_rsa()?;

    // Convert private and public keys to bytes.
    let private_key_bytes = pkcs8::EncodePrivateKey::to_pkcs8_der(&private_key)?.as_bytes().to_vec();
    let public_key_bytes = pkcs8::EncodePublicKey::to_public_key_der(&public_key)?.to_vec();

    // Encrypt the private key and symmetric key.
    let protected_private_key = encrypt_xchacha20_poly1305(&user_symmetric_key, &private_key_bytes, None)?;
    let protected_symmetric_key = encrypt_xchacha20_poly1305(&stretched_master_key, &user_symmetric_key, None)?;

    Ok((master_password_hash, protected_symmetric_key, protected_private_key, public_key_bytes))
}

// Function to compute the master password hash for login.
pub fn login_mph_compute(username: &str, password: &str) -> Result<Vec<u8>> {
    // Calculate the master key and hash.
    let master_key = create_master_key(password, username)?;
    Ok(hkdf(&master_key, CONTEXT_MPH)?.as_ref().to_vec())
}

// Function to compute the stretched master key for login.
pub fn login_smk_compute(username: &str, password: &str) -> Result<Vec<u8>> {
    // Calculate the master key and hash.
    let master_key = create_master_key(password, username)?;
    Ok(hkdf(&master_key, CONTEXT_SMK)?.as_ref().to_vec())
}

// Function to set the user session after login.
pub fn login_set_session(username: &str, user_data: &mut UserMetadata, stretched_master_key: Vec<u8>, directory_metadata: DirectoryMetadata) -> Result<String> {
    // Decrypt the user's symmetric key and private key.
    let symmetric_key = decrypt_xchacha20_poly1305(&stretched_master_key, &user_data.protected_symmetric_key)?;
    let private_key = decrypt_xchacha20_poly1305(&symmetric_key, user_data.protected_private_key.as_slice())?;
    let decoded_private_key = decode_private_key(&private_key)
        .map_err(|_| anyhow!("Failed to decode private key"))?;

    // Create and map the directory content map.
    let mut directory_map = DirectoryContentMap::default();
    map_folder_metadata(&directory_metadata, &mut directory_map, &symmetric_key)?;
    map_file_metadata(&directory_metadata, &mut directory_map, &symmetric_key)?;
    map_shared_folders_metadata(&mut directory_map, &decoded_private_key, &user_data.shares)?;

    // Set user session data.
    set_username(Some(username.to_string()));
    set_private_key(Some(decoded_private_key));
    add_folder_key_chain(&symmetric_key);
    set_current_directory_metadata(Some(directory_metadata));
    set_current_directory_map(Some(directory_map));
    set_shares(Some(user_data.shares.clone()));
    set_clear_path(Some("~/".to_string()));

    Ok("Session set successfully.".to_string())
}

// Function to change the user's password.
pub fn change_password(new_password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    // Retrieve the username from the session.
    let username = match get_username() {
        Some(val) => val,
        None => return Err(anyhow!("No username found in session")),
    };

    // Generate a new master key and hash for the new password.
    let master_key = create_master_key(new_password, &username)?;
    let stretched_master_key = hkdf(&master_key, CONTEXT_SMK)?;
    let master_password_hash = hkdf(&master_key, CONTEXT_MPH)?.as_ref().to_vec();

    // Retrieve the root symmetric key from the session.
    let root_symmetric_key = match get_first_folder_key_chain() {
        Some(val) => val,
        None => return Err(anyhow!("No symmetric key found in session")),
    };

    // Encrypt the new symmetric key with the stretched master key.
    let protected_symmetric_key = encrypt_xchacha20_poly1305(&stretched_master_key, &root_symmetric_key, None)?;

    Ok((master_password_hash, protected_symmetric_key))
}
