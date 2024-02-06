use crate::models::{DirectoryMetadata, FileData, UserMetadata};
use crate::server::auth::*;
use anyhow::{anyhow, Result};
use crate::server::file_manager::*;

pub fn register_endpoint(user_data: &mut UserMetadata) -> Result<()> {
    register(user_data)
}

pub fn login_endpoint(username: &str, password: &Vec<u8>) -> Result<(String, UserMetadata, DirectoryMetadata)> {
    login(username, password)
}

pub fn create_new_folder_endpoint(folder_path: &str, directory_metadata: &DirectoryMetadata) -> Result<()> {
    create_new_folder(folder_path, directory_metadata)
}

pub fn upload_file_endpoint(file: &FileData, directory_metadata: &DirectoryMetadata) -> Result<()> {
    upload_file(file, directory_metadata)
}

pub fn download_file_endpoint(file_path: &str, file_name: &str) -> Result<FileData> {
    download_file(file_path, file_name)
}

pub fn delete_file_endpoint(file_path: &str, encrypted_file_name: &str, current_metadata: &DirectoryMetadata) -> Result<()> {
    delete_file(file_path, encrypted_file_name, current_metadata)
}


pub fn read_directory_metadata_endpoint(folder_path: &str) -> Result<DirectoryMetadata> {
    read_directory_metadata(folder_path)
}

pub fn change_password_endpoint(username: &str, new_master_password_hash: Vec<u8>, new_protected_symmetric_key: Vec<u8>) -> Result<()> {
    change_password(username, new_master_password_hash, new_protected_symmetric_key)
}

pub fn retrieve_user_metadata_endpoint(username: &str) -> Result<UserMetadata> {
    let user_data = match read_user_metadata(username) {
        Ok(data) => data,
        Err(_) => return Err(anyhow!("Failed to read user metadata")),
    };

    Ok(user_data)
}

pub fn update_user_metadata_endpoint(user_data: &UserMetadata) -> Result<()> {
    update_user_metadata(user_data)
}

pub fn update_directory_metadata_endpoint(directory_metadata: &DirectoryMetadata) -> Result<()> {
    update_directory_metadata(directory_metadata)
}

pub fn list_users_endpoint() -> Result<Vec<String>> {
    list_users()
}

pub fn share_folder_endpoint(user_metadata: &UserMetadata, directory_metadata: &DirectoryMetadata) -> Result<()> {
    share_folder(user_metadata, directory_metadata)
}