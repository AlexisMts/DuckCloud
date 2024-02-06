use std::fs;
use std::io::Write;
use std::path::Path;
use anyhow::{Result, anyhow};
use rsa::RsaPrivateKey;
use crate::client::crypto::*;
use crate::client::session::*;
use crate::client::utils::{b64_to_vec, vec_to_b64};
use crate::models::*;
use crate::server::api::*;

#[derive(PartialEq)]
enum FolderType {
    Regular,
    Shared,
}

// Check if a file exists.
fn file_exists(file_name: &str) -> Result<String> {
    if !Path::new(file_name).exists() {
        return Err(anyhow!("File '{}' does not exist.", file_name));
    }
    Ok("File exists".to_string())
}

// Map folder metadata to the directory content map.
pub fn map_folder_metadata(new_directory_metadata: &DirectoryMetadata, new_directory_map: &mut DirectoryContentMap, symmetric_key: &[u8]) -> Result<()> {
    for folder_metadata in &new_directory_metadata.folders {
        let decoded_folder_name = match b64_to_vec(&folder_metadata.name) {
            Ok(val) => val,
            Err(_) => return Err(anyhow!("Failed to decode folder name")),
        };

        let decrypted_name = decrypt_xchacha20_poly1305(symmetric_key, decoded_folder_name.as_slice())
            .map_err(|err| anyhow!("Failed to decrypt folder name: {}", err))?;

        let decrypted_name_str = String::from_utf8(decrypted_name)
            .map_err(|_| anyhow!("Failed to convert decrypted folder name to string"))?;

        new_directory_map.folders.insert(decrypted_name_str.clone(), folder_metadata.name.clone());
        new_directory_map.sharing_state.insert(decrypted_name_str, false);
    }
    Ok(())
}

// Map file metadata to the directory content map.
pub fn map_file_metadata(new_directory_metadata: &DirectoryMetadata, new_directory_map: &mut DirectoryContentMap, symmetric_key: &[u8]) -> Result<()> {
    for file_metadata in &new_directory_metadata.files {
        let decoded_file_name = match b64_to_vec(&file_metadata.name) {
            Ok(val) => val,
            Err(_) => return Err(anyhow!("Failed to decode file name")),
        };

        let decrypted_name = decrypt_xchacha20_poly1305(symmetric_key, decoded_file_name.as_slice())
            .map_err(|err| anyhow!("Failed to decrypt file name: {}", err))?;

        let decrypted_name_str = String::from_utf8(decrypted_name)
            .map_err(|_| anyhow!("Failed to convert decrypted file name to string"))?;

        new_directory_map.files.insert(decrypted_name_str, file_metadata.name.clone());
    }
    Ok(())
}

// Map shared folders metadata to the directory content map.
pub fn map_shared_folders_metadata(new_directory_map: &mut DirectoryContentMap, private_key: &RsaPrivateKey, shares: &[UserShareData]) -> Result<()> {
    for share in shares {
        let decoded_name = b64_to_vec(&share.encrypted_name)
            .map_err(|_| anyhow!("Failed to decode encrypted shared folder name"))?;

        let decrypted_folder_name = decrypt_rsa_oaep(private_key, &decoded_name)
            .map_err(|err| anyhow!("Failed to decrypt shared folder name: {}", err))?;

        let decrypted_name_str = String::from_utf8(decrypted_folder_name)
            .map_err(|_| anyhow!("Failed to convert decrypted shared folder name to string"))?;

        let encrypted_folder_name = vec_to_b64(&decoded_name);

        new_directory_map.folders.insert(decrypted_name_str.clone(), encrypted_folder_name);
        new_directory_map.sharing_state.insert(decrypted_name_str, true);
    }
    Ok(())
}

// Change the current directory.
pub fn change_directory(folder_name: &str) -> Result<String> {
    let folder_type = if folder_name == ".." {
        if get_current_directory_metadata().unwrap().owner != get_username().unwrap() && get_length_folder_key_chain() == 2 {
            FolderType::Shared
        } else {
            FolderType::Regular
        }
    } else {
        match get_current_directory_map_sharing_state_value(folder_name) {
            Some(true) => FolderType::Shared,
            Some(false) => FolderType::Regular,
            None => return Err(anyhow!("Folder '{}' does not exist.", folder_name)),
        }
    };

    if folder_name == ".." {
        change_directory_up(folder_type)?;
        remove_clear_path();
    } else {
        change_directory_down(folder_name, folder_type)?;
        add_clear_path(folder_name);
    }

    Ok(format!("Changed directory to '{}'.", folder_name))
}

// Change the current directory to its parent directory.
fn change_directory_up(folder_type: FolderType) -> Result<()> {
    let root_folder_path = get_username().unwrap() + "/";
    let current_folder_path = get_current_folder_path()
        .ok_or_else(|| anyhow!("Current folder path not found"))?;

    if current_folder_path == root_folder_path {
        return Err(anyhow!("Already at root folder"));
    }

    let (new_folder_path, symmetric_key) = match folder_type {
        FolderType::Regular => {
            let mut path_vec: Vec<&str> = current_folder_path.split('/').collect();
            path_vec.pop();
            path_vec.pop();
            path_vec.push("");
            let path = path_vec.join("/");
            remove_folder_key_chain();
            let key = get_last_folder_key_chain()
                .ok_or_else(|| anyhow!("Current symmetric key not found"))?;
            (path, key)
        },
        FolderType::Shared => {
            remove_folder_key_chain();
            let key = get_last_folder_key_chain()
                .ok_or_else(|| anyhow!("Root symmetric key not found"))?;
            (root_folder_path.clone(), key)
        },
    };

    let new_directory_metadata = read_directory_metadata_endpoint(&new_folder_path)?;

    let mut new_directory_map = DirectoryContentMap::default();
    map_folder_metadata(&new_directory_metadata, &mut new_directory_map, &symmetric_key)?;
    map_file_metadata(&new_directory_metadata, &mut new_directory_map, &symmetric_key)?;

    if get_length_folder_key_chain() == 1 && folder_type == FolderType::Shared {
        let shares = get_shares()
            .ok_or_else(|| anyhow!("Failed to retrieve shares"))?;

        let private_key = get_private_key()
            .ok_or_else(|| anyhow!("Private key not found"))?;

        map_shared_folders_metadata(&mut new_directory_map, &private_key, &shares)?;
    }

    set_current_directory_metadata(Some(new_directory_metadata));
    set_current_directory_map(Some(new_directory_map));

    Ok(())
}

// Change the current directory to a child directory.
fn change_directory_down(folder_name: &str, folder_type: FolderType) -> Result<()> {
    let encrypted_child_folder_name = get_current_directory_map_folder_value(folder_name)
        .ok_or_else(|| anyhow!("Folder '{}' not found in directory map.", folder_name))?;

    let (symmetric_key,  path) = match folder_type {
        FolderType::Regular => {
            let directory_metadata = get_current_directory_metadata()
                .ok_or_else(|| anyhow!("Current directory metadata not found"))?;

            let folder = directory_metadata.folders.iter()
                .find(|&folder| folder.name == encrypted_child_folder_name)
                .ok_or_else(|| anyhow!("Folder '{}' not found.", encrypted_child_folder_name))?;

            let current_symmetric_key = get_last_folder_key_chain()
                .ok_or_else(|| anyhow!("Current symmetric key not found"))?;

            let symmetric_key = decrypt_xchacha20_poly1305(&current_symmetric_key, &folder.protected_symmetric_key)?;

            let new_path = get_current_folder_path().unwrap_or_default() + &folder.name + "/";
            (symmetric_key, new_path)
        },
        FolderType::Shared => {
            let share = get_share(&encrypted_child_folder_name)
                .ok_or_else(|| anyhow!("Share for folder '{}' not found.", encrypted_child_folder_name))?;

            let private_key = get_private_key()
                .ok_or_else(|| anyhow!("Private key not found"))?;

            let symmetric_key = decrypt_rsa_oaep(&private_key, &share.protected_symmetric_key)?;
            (symmetric_key, share.path.clone())
        },
    };

    let new_directory_metadata = read_directory_metadata_endpoint(&path)?;

    let mut new_directory_map = DirectoryContentMap::default();
    map_folder_metadata(&new_directory_metadata, &mut new_directory_map, &symmetric_key)?;
    map_file_metadata(&new_directory_metadata, &mut new_directory_map, &symmetric_key)?;

    set_current_directory_metadata(Some(new_directory_metadata));
    set_current_directory_map(Some(new_directory_map));
    add_folder_key_chain(&symmetric_key);

    Ok(())
}

// Create a new folder.
pub fn create_folder(folder_name: &str) -> Result<()> {
    if get_current_directory_map_file_value(folder_name).is_some() {
        return Err(anyhow!("Folder '{}' already exists", folder_name));
    }

    let symmetric_key = get_last_folder_key_chain()
        .ok_or_else(|| anyhow!("Current symmetric key not found"))?;

    let encrypted_new_folder_symmetric_key = match encrypt_xchacha20_poly1305(&symmetric_key, &random_bytes::<32>(), None) {
        Ok(val) => val,
        Err(_) => return Err(anyhow!("Failed to encrypt folder symmetric key")),
    };

    let encrypted_folder_name = match encrypt_xchacha20_poly1305(&symmetric_key, folder_name.as_bytes(), None) {
        Ok(val) => vec_to_b64(&val),
        Err(_) => return Err(anyhow!("Failed to encrypt folder name")),
    };

    let folder_metadata = FolderMetadata {
        name: encrypted_folder_name.clone(),
        protected_symmetric_key: encrypted_new_folder_symmetric_key,
        shares: vec![],
    };

    let mut current_metadata = get_current_directory_metadata()
        .ok_or_else(|| anyhow!("Current directory metadata not found"))?;

    current_metadata.folders.push(folder_metadata);

    let folder_path = get_current_folder_path().unwrap() + &encrypted_folder_name + "/";
    create_new_folder_endpoint(&folder_path, &current_metadata)?;

    set_current_directory_metadata(Some(current_metadata));
    add_current_directory_map_folder(folder_name, &encrypted_folder_name);
    add_current_directory_map_sharing_state(folder_name, false);

    Ok(())
}

// Upload a file to the current folder.
pub fn upload_file(file_name: &str) -> Result<()> {
    file_exists(file_name)?;

    let file_data = fs::read(file_name)?;
    let symmetric_key = get_last_folder_key_chain()
        .ok_or_else(|| anyhow!("Symmetric key not found"))?;

    let encrypted_file_content = encrypt_xchacha20_poly1305(&symmetric_key, &file_data, None)?;

    let symmetric_key = get_last_folder_key_chain()
        .ok_or_else(|| anyhow!("Symmetric key not found"))?;

    let encrypted_file_name_base64 = match get_current_directory_map_file_value(file_name) {
        Some(val) => val,
        None => {
            let encrypted_file_name = encrypt_xchacha20_poly1305(
                &symmetric_key,
                file_name.as_bytes(),
                None
            )?;
            vec_to_b64(&encrypted_file_name)
        }
    };

    let file_path = get_current_folder_path().unwrap();

    let file_metadata = FileMetadata {
        name: encrypted_file_name_base64.clone(),
    };

    let mut current_metadata = get_current_directory_metadata()
        .ok_or_else(|| anyhow!("Current directory metadata not found"))?;

    current_metadata.files.push(file_metadata);

    let file_data = FileData {
        file_name: encrypted_file_name_base64.clone(),
        file_path,
        file_content: encrypted_file_content,
    };

    upload_file_endpoint(&file_data, &current_metadata)?;

    set_current_directory_metadata(Some(current_metadata));
    add_current_directory_map_file(file_name, &encrypted_file_name_base64);

    Ok(())
}

// Download a file from the current folder.
pub fn download_file(file_name: &str) -> Result<()> {
    let dir_map = get_current_directory_map()
        .ok_or_else(|| anyhow!("Current directory map not found"))?;

    let encrypted_file_name = dir_map.files.get(file_name)
        .ok_or_else(|| anyhow!("File '{}' not found", file_name))?;

    let file_data = download_file_endpoint(&get_current_folder_path().unwrap(), encrypted_file_name)?;

    let symmetric_key = get_last_folder_key_chain()
        .ok_or_else(|| anyhow!("Symmetric key not found"))?;

    let decrypted_file_content = decrypt_xchacha20_poly1305(&symmetric_key, &file_data.file_content)?;

    fs::File::create(file_name)?.write_all(&decrypted_file_content)?;

    Ok(())
}

// Delete a file from the current folder.
pub fn delete_file(file_name: &str) -> Result<()> {
    let dir_map = get_current_directory_map()
        .ok_or_else(|| anyhow!("Current directory map not found"))?;

    let encrypted_file_name = dir_map.files.get(file_name)
        .ok_or_else(|| anyhow!("File '{}' not found", file_name))?;

    let file_path = get_current_folder_path().unwrap();

    let mut current_metadata = get_current_directory_metadata()
        .ok_or_else(|| anyhow!("Current directory metadata not found"))?;

    current_metadata.files.retain(|file| file.name != *encrypted_file_name);

    delete_file_endpoint(&file_path, encrypted_file_name, &current_metadata)?;

    set_current_directory_metadata(Some(current_metadata));
    remove_current_directory_map_file(file_name);

    Ok(())
}

// Share a folder with another user.
pub fn share_folder(username: &str, folder_name: &str, encrypted_child_folder_name: &str, directory_metadata: &mut DirectoryMetadata, decrypted_symmetric_key: Vec<u8>) -> Result<()> {
    if let Some(folder) = directory_metadata.folders.iter_mut()
        .find(|f| f.name == encrypted_child_folder_name) {

        // Retrieve the user's metadata using an endpoint.
        let mut user_metadata = retrieve_user_metadata_endpoint(username)?;

        // Decode the user's public key.
        let public_key = decode_public_key(&user_metadata.public_key_bytes)
            .map_err(|err| anyhow!("Failed to decode public key: {}", err))?;

        // Encrypt the symmetric key with the user's public key.
        let encrypted_symmetric_key = encrypt_rsa_oaep(&public_key, &decrypted_symmetric_key)
            .map_err(|err| anyhow!("Failed to encrypt symmetric key: {}", err))?;

        // Create a folder share entry.
        let folder_share = FolderShareData {
            username: username.to_string(),
        };

        // Add the folder share to the folder's shares.
        folder.shares.push(folder_share);

        // Construct the folder path.
        let mut folder_path = directory_metadata.path.clone();
        folder_path.push_str(&folder.name);
        folder_path.push('/');

        // Encrypt the folder name with the user's public key.
        let encrypted_folder_name = vec_to_b64(&encrypt_rsa_oaep(&public_key, folder_name.as_bytes())
            .map_err(|err| anyhow!("Failed to encrypt folder path: {}", err))?);

        // Create a user share entry.
        let user_share = UserShareData {
            owner: directory_metadata.owner.clone(),
            path: folder_path,
            encrypted_name: encrypted_folder_name,
            protected_symmetric_key: encrypted_symmetric_key,
        };

        // Add the user share to the user's shares.
        user_metadata.shares.push(user_share);

        // Call an endpoint to share the folder with the user.
        share_folder_endpoint(&user_metadata, &directory_metadata)?;
    }

    // Update the current directory metadata.
    set_current_directory_metadata(Some(directory_metadata.clone()));

    Ok(())
}

// Unshare a folder with a user.
pub fn unshare_folder(encrypted_folder_name: &str, directory_metadata: &mut DirectoryMetadata) -> Result<()> {
    if let Some(folder) = directory_metadata.folders.iter_mut()
        .find(|f| f.name == encrypted_folder_name) {

        for folder_share in &folder.shares {
            // Retrieve the user's metadata using an endpoint.
            let mut user_metadata = retrieve_user_metadata_endpoint(&folder_share.username)?;

            // Remove the folder share entry from the user's shares.
            user_metadata.shares.retain(|share| share.path != (directory_metadata.path.clone() + folder.name.clone().as_str() + "/"));

            // Update the user's metadata.
            update_user_metadata_endpoint(&user_metadata)?;
        }

        // Clear the folder's shares.
        folder.shares.clear();

        // Update the directory metadata.
        update_directory_metadata_endpoint(&directory_metadata)?;
    }

    // Update the current directory metadata.
    set_current_directory_metadata(Some(directory_metadata.clone()));

    Ok(())
}

