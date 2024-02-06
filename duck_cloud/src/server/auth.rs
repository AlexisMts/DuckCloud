use anyhow::{Result, anyhow};
use crate::models::{DirectoryMetadata, UserMetadata};
use crate::server::crypto::*;
use crate::server::file_manager::*;

// Function to register a new user
pub fn register(user_data: &mut UserMetadata) -> Result<()> {
    // Hash the master password
    user_data.master_password_hash = create_password_hash(&user_data.master_password_hash)?
        .as_bytes()
        .to_vec();

    // Create necessary registration files
    create_register_files(user_data)
}

// Function to handle user login
pub fn login(username: &str, master_password_hash: &Vec<u8>) -> Result<(String, UserMetadata, DirectoryMetadata)> {
    // Trim and convert the username to lowercase for consistency
    let username = username.trim().to_ascii_lowercase();

    // Attempt to read user metadata based on the provided username
    let user_data = match read_user_metadata(&username) {
        Ok(data) => data,
        Err(_) => return Err(anyhow!("Incorrect username or password.")),
    };

    // Verify the provided master password hash against the stored hash
    match verify_password_hash(master_password_hash, &user_data.master_password_hash) {
        Ok(_) => {
            // If the password is correct, attempt to read the user's directory metadata
            let directory_metadata = match read_directory_metadata(&(username.to_owned() + "/")) {
                Ok(data) => data,
                Err(_) => return Err(anyhow!("Incorrect username or password.")),
            };

            // Return a successful login message along with user and directory metadata
            Ok(("Login successful.".to_string(), user_data, directory_metadata))
        }
        Err(_) => Err(anyhow!("Incorrect username or password.")),
    }
}

// Function to change the user's password
pub fn change_password(username: &str, new_master_password_hash: Vec<u8>, new_protected_symmetric_key: Vec<u8>) -> Result<()> {
    // Attempt to read the user's existing metadata
    let user_data = match read_user_metadata(username) {
        Ok(data) => data,
        Err(_) => return Err(anyhow!("Failed to read user metadata")),
    };

    // Update the user's metadata with the new master password hash and symmetric key
    let mut user_data = UserMetadata {
        username: user_data.username,
        master_password_hash: new_master_password_hash,
        protected_symmetric_key: new_protected_symmetric_key,
        protected_private_key: user_data.protected_private_key,
        public_key_bytes: user_data.public_key_bytes,
        shares: user_data.shares,
    };

    // Hash the new master password
    user_data.master_password_hash = create_password_hash(&user_data.master_password_hash)?
        .as_bytes()
        .to_vec();

    // Update the user's password and associated data
    update_change_password(&user_data)
}
