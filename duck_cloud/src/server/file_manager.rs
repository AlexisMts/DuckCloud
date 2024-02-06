use std::{fs};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use anyhow::{Result, anyhow};
use crate::models::{DirectoryMetadata, FileData, UserMetadata};
use crate::server::consts::{STORAGE_FOLDER_USERS_METADATA, STORAGE_FOLDER_USERS_ROOT};

// Function to create registration files for a new user
pub fn create_register_files(user_data: &UserMetadata) -> Result<()> {
    // Get the lowercase username
    let username = user_data.username.trim().to_ascii_lowercase();

    // Define file paths for user metadata and user root directory
    let user_metadata_file_path = format!("{}{}.json", STORAGE_FOLDER_USERS_METADATA, username);

    // Check if the user metadata file already exists
    if Path::new(&user_metadata_file_path).exists() {
        return Err(anyhow!("Account information invalid."));
    }

    // Create the user metadata file and write user data to it
    let file = File::create(&user_metadata_file_path)
        .map_err(|_e| anyhow!("Failed to create user's metadata"))?;
    serde_json::to_writer(file, &user_data)
        .map_err(|_e| anyhow!("Failed to write user's metadata"))?;

    // Create the user root directory
    let user_root_path = format!("{}{}", STORAGE_FOLDER_USERS_ROOT, username);
    fs::create_dir_all(&user_root_path)
        .map_err(|e| anyhow!("Failed to create user directory: {}", e))?;

    // Create the metadata file for the user's root directory
    let user_metadata_path = Path::new(&user_root_path).join("metadata.json");
    let file = File::create(user_metadata_path)
        .map_err(|_e| anyhow!("Failed to write user's folder metadata"))?;
    serde_json::to_writer(file, &DirectoryMetadata::init(&username, &(username.to_owned() + "/")))
        .map_err(|_e| anyhow!("Failed to write user's folder metadata"))?;

    Ok(())
}

// Function to read user metadata from a file
pub fn read_user_metadata(username: &str) -> Result<UserMetadata> {
    let file_path = format!("{}{}.json", STORAGE_FOLDER_USERS_METADATA, username);
    let file_contents = fs::read_to_string(file_path)
        .map_err(|e| anyhow!("Failed to read user file: {}", e))?;

    let user_data: UserMetadata = serde_json::from_str(&file_contents)
        .map_err(|e| anyhow!("Failed to parse user data: {}", e))?;

    Ok(user_data)
}

// Function to update user metadata to a file
pub fn update_user_metadata(user_data: &UserMetadata) -> Result<()> {
    let user_metadata_file_path = format!("{}{}.json", STORAGE_FOLDER_USERS_METADATA, user_data.username);

    let file = File::create(user_metadata_file_path)
        .map_err(|_e| anyhow!("Failed to create user's metadata"))?;
    serde_json::to_writer(file, &user_data)
        .map_err(|_e| anyhow!("Failed to write user's metadata"))?;

    Ok(())
}

// Function to update directory metadata to a file
pub fn update_directory_metadata(directory_metadata: &DirectoryMetadata) -> Result<()> {
    let directory_metadata_file_path = format!("{}{}metadata.json", STORAGE_FOLDER_USERS_ROOT, directory_metadata.path);

    let file = File::create(directory_metadata_file_path)
        .map_err(|_e| anyhow!("Failed to create directory's metadata"))?;
    serde_json::to_writer(file, &directory_metadata)
        .map_err(|_e| anyhow!("Failed to write directory's metadata"))?;

    Ok(())
}

// Function to read directory metadata from a file
pub fn read_directory_metadata(relative_path: &str) -> Result<DirectoryMetadata> {
    let directory_metadata_path = format!("{}{}metadata.json", STORAGE_FOLDER_USERS_ROOT, relative_path);

    let file = File::open(directory_metadata_path)
        .map_err(|e| anyhow!("Failed to open directory metadata file: {}", e))?;
    let directory_metadata: DirectoryMetadata = serde_json::from_reader(file)
        .map_err(|e| anyhow!("Failed to parse directory metadata: {}", e))?;

    Ok(directory_metadata)
}

// Function to list all user directories
pub fn list_users() -> Result<Vec<String>> {
    let mut users = Vec::new();

    for entry in fs::read_dir(STORAGE_FOLDER_USERS_METADATA)? {
        let entry = entry?;
        let path = entry.path();

        // Check if the path is a file and has a .json extension
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                users.push(stem.to_string());
            }
        }
    }

    Ok(users)
}

// Function to create a new folder
pub fn create_new_folder(folder_path: &str, directory_metadata: &DirectoryMetadata) -> Result<()> {
    let full_path = format!("{}{}", STORAGE_FOLDER_USERS_ROOT, &folder_path);
    let parent_metadata_file_path: String = format!("{}{}/metadata.json", STORAGE_FOLDER_USERS_ROOT, &directory_metadata.path);
    let new_directory_metadata_file_path: String = format!("{}{}/metadata.json", STORAGE_FOLDER_USERS_ROOT, &folder_path);

    // Create the new folder and its parent directories
    match fs::create_dir_all(full_path) {
        Ok(_) => (),
        Err(e) => return Err(anyhow!("Failed to create new folder: {}", e))
    }

    // Update the metadata file for the parent directory
    let metadata_file = File::create(parent_metadata_file_path)
        .map_err(|e| anyhow!("Failed to create metadata file: {}", e))?;
    serde_json::to_writer(metadata_file, &directory_metadata)
        .map_err(|e| anyhow!("Failed to write to metadata file: {}", e))?;

    // Create a metadata file for the new folder
    let child_metadata = File::create(new_directory_metadata_file_path)
        .map_err(|e| anyhow!("Failed to create metadata file: {}", e))?;
    serde_json::to_writer(child_metadata, &DirectoryMetadata::init(folder_path.split('/').collect::<Vec<_>>().first().unwrap(), folder_path))
        .map_err(|e| anyhow!("Failed to write to metadata file: {}", e))?;

    Ok(())
}

// Function to upload a file
pub fn upload_file(file: &FileData, directory_metadata: &DirectoryMetadata) -> Result<()> {
    let file_path: String = format!("{}{}{}", STORAGE_FOLDER_USERS_ROOT, file.file_path, file.file_name);
    let metadata_file_path: String = format!("{}{}/metadata.json", STORAGE_FOLDER_USERS_ROOT, file.file_path);

    let mut new_file = File::create(file_path)
        .map_err(|e| anyhow!("Failed to create file: {}", e))?;
    new_file.write_all(&file.file_content)
        .map_err(|e| anyhow!("Failed to write to file: {}", e))?;

    let metadata_file = File::create(metadata_file_path)
        .map_err(|e| anyhow!("Failed to create metadata file: {}", e))?;
    serde_json::to_writer(metadata_file, &directory_metadata)
        .map_err(|e| anyhow!("Failed to write to metadata file: {}", e))?;


    Ok(())
}

// Function to download a file
pub fn download_file(file_path: &str, file_name: &str) -> Result<FileData> {
    let file_path: String = format!("{}{}{}", STORAGE_FOLDER_USERS_ROOT, file_path, file_name);

    let file_content = fs::read(&file_path)
        .map_err(|e| anyhow!("Failed to read file: {}", e))?;

    let file_name = Path::new(&file_path).file_name().unwrap().to_str().unwrap().to_string();
    let file_data = FileData {
        file_name,
        file_path,
        file_content
    };

    Ok(file_data)
}

// Function to delete a file
pub fn delete_file(file_path: &str, encrypted_file_name: &str, current_metadata: &DirectoryMetadata) -> Result<()> {
    let file_path: String = format!("{}{}{}", STORAGE_FOLDER_USERS_ROOT, file_path, encrypted_file_name);
    let metadata_file_path: String = format!("{}{}/metadata.json", STORAGE_FOLDER_USERS_ROOT, current_metadata.path);

    // Remove the file
    fs::remove_file(file_path)
        .map_err(|e| anyhow!("Failed to delete file: {}", e))?;

    // Update the metadata file for the current directory
    let metadata_file = File::create(metadata_file_path)
        .map_err(|e| anyhow!("Failed to create metadata file: {}", e))?;
    serde_json::to_writer(metadata_file, &current_metadata)
        .map_err(|e| anyhow!("Failed to write to metadata file: {}", e))?;

    Ok(())
}

// Function to update user metadata when changing the password
pub fn update_change_password(user_data: &UserMetadata) -> Result<()> {
    let user_metadata_file_path = format!("{}{}.json", STORAGE_FOLDER_USERS_METADATA, user_data.username);

    let file = File::create(user_metadata_file_path)
        .map_err(|_e| anyhow!("Failed to create user's metadata"))?;
    serde_json::to_writer(file, &user_data)
        .map_err(|_e| anyhow!("Failed to write user's metadata"))?;

    Ok(())
}

// Function to share a folder with another user
pub fn share_folder(user_metadata: &UserMetadata, directory_metadata: &DirectoryMetadata) -> Result<()>{
    let user_metadata_file_path = format!("{}{}.json", STORAGE_FOLDER_USERS_METADATA, user_metadata.username);
    let file = File::create(user_metadata_file_path)
        .map_err(|_e| anyhow!("Failed to create user's metadata"))?;
    serde_json::to_writer(file, &user_metadata)
        .map_err(|_e| anyhow!("Failed to write user's metadata"))?;

    let parent_metadata_file_path: String = format!("{}{}metadata.json", STORAGE_FOLDER_USERS_ROOT, directory_metadata.path);

    let metadata_file = File::create(parent_metadata_file_path)
        .map_err(|e| anyhow!("Failed to create metadata file: {}", e))?;
    serde_json::to_writer(metadata_file, &directory_metadata)
        .map_err(|e| anyhow!("Failed to write to metadata file: {}", e))?;

    Ok(())
}
