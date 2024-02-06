use lazy_static::lazy_static;
use std::sync::Mutex;
use rsa::RsaPrivateKey;
use crate::models::{DirectoryContentMap, DirectoryMetadata, UserShareData};

// Define lazy-static variables to store session data
lazy_static! {
    static ref USERNAME: Mutex<Option<String>> = Mutex::new(None);
    static ref PRIVATE_KEY: Mutex<Option<RsaPrivateKey>> = Mutex::new(None);
    static ref FOLDER_KEY_CHAIN: Mutex<Vec<Vec<u8>>> = Mutex::new(vec![]);
    static ref CURRENT_DIRECTORY_METADATA: Mutex<Option<DirectoryMetadata>> = Mutex::new(None);
    static ref CURRENT_DIRECTORY_MAP: Mutex<Option<DirectoryContentMap>> = Mutex::new(None);
    static ref SHARES: Mutex<Option<Vec<UserShareData>>> = Mutex::new(None);
    static ref CLEAR_PATH: Mutex<Option<String>> = Mutex::new(None);
}

// Function to set the username in the session
pub fn set_username(username_val: Option<String>) {
    let mut username = USERNAME.lock().unwrap();
    *username = username_val
}

// Function to get the username from the session
pub fn get_username() -> Option<String> {
    USERNAME.lock().unwrap().clone()
}

// Function to set the private key in the session
pub fn set_private_key(key: Option<RsaPrivateKey>) {
    let mut private_key = PRIVATE_KEY.lock().unwrap();
    *private_key = key
}

// Function to get the private key from the session
pub fn get_private_key() -> Option<RsaPrivateKey> {
    PRIVATE_KEY.lock().unwrap().clone()
}

// Function to add a folder key to the key chain
pub fn add_folder_key_chain(key: &Vec<u8>) {
    let mut folder_key_chain = FOLDER_KEY_CHAIN.lock().unwrap();
    folder_key_chain.push(key.clone());
}

// Function to remove the last folder key from the key chain
pub fn remove_folder_key_chain() {
    let mut folder_key_chain = FOLDER_KEY_CHAIN.lock().unwrap();
    folder_key_chain.pop();
}

// Function to get the first folder key from the key chain
pub fn get_first_folder_key_chain() -> Option<Vec<u8>> {
    let folder_key_chain = FOLDER_KEY_CHAIN.lock().unwrap();
    match folder_key_chain.first() {
        Some(val) => Some(val.clone()),
        None => None
    }
}

// Function to get the last folder key from the key chain
pub fn get_last_folder_key_chain() -> Option<Vec<u8>> {
    let folder_key_chain = FOLDER_KEY_CHAIN.lock().unwrap();
    match folder_key_chain.last() {
        Some(val) => Some(val.clone()),
        None => None
    }
}

// Function to get the length of the folder key chain
pub fn get_length_folder_key_chain() -> usize {
    let folder_key_chain = FOLDER_KEY_CHAIN.lock().unwrap();
    folder_key_chain.len()
}

// Function to get the current folder path from the directory metadata
pub fn get_current_folder_path() -> Option<String> {
    CURRENT_DIRECTORY_METADATA.lock().unwrap().clone().map(|metadata| metadata.path)
}

// Function to set the current directory metadata in the session
pub fn set_current_directory_metadata(metadata: Option<DirectoryMetadata>) {
    let mut current_directory_metadata = CURRENT_DIRECTORY_METADATA.lock().unwrap();
    *current_directory_metadata = metadata;
}

// Function to get the current directory metadata from the session
pub fn get_current_directory_metadata() -> Option<DirectoryMetadata> {
    CURRENT_DIRECTORY_METADATA.lock().unwrap().clone()
}

// Function to add a file entry to the current directory map
pub fn add_current_directory_map_file(plain_name: &str, cipher_name: &str) {
    let mut current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    current_directory_map.as_mut().unwrap().files.insert(plain_name.to_string(), cipher_name.to_string());
}

// Function to remove a file entry from the current directory map
pub fn remove_current_directory_map_file(plain_name: &str) {
    let mut current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    current_directory_map.as_mut().unwrap().files.remove(plain_name);
}

// Function to add a folder entry to the current directory map
pub fn add_current_directory_map_folder(plain_name: &str, cipher_name: &str) {
    let mut current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    current_directory_map.as_mut().unwrap().folders.insert(plain_name.to_string(), cipher_name.to_string());
}

// Function to add a sharing state entry to the current directory map
pub fn add_current_directory_map_sharing_state(plain_name: &str, state: bool) {
    let mut current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    current_directory_map.as_mut().unwrap().sharing_state.insert(plain_name.to_string(), state);
}

// Function to get the encrypted file name from the current directory map
pub fn get_current_directory_map_file_value(file_name: &str) -> Option<String> {
    let current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    match current_directory_map.as_ref().unwrap().files.get(file_name) {
        Some(val) => Some(val.clone()),
        None => None
    }
}

// Function to get the encrypted folder name from the current directory map
pub fn get_current_directory_map_folder_value(folder_name: &str) -> Option<String> {
    let current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    match current_directory_map.as_ref().unwrap().folders.get(folder_name) {
        Some(val) => Some(val.clone()),
        None => None
    }
}

// Function to get the sharing state from the current directory map
pub fn get_current_directory_map_sharing_state_value(folder_name: &str) -> Option<bool> {
    let current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    match current_directory_map.as_ref().unwrap().sharing_state.get(folder_name) {
        Some(val) => Some(val.clone()),
        None => None
    }
}

// Function to set the current directory map in the session
pub fn set_current_directory_map(map: Option<DirectoryContentMap>) {
    let mut current_directory_map = CURRENT_DIRECTORY_MAP.lock().unwrap();
    *current_directory_map = map;
}

// Function to get the current directory map from the session
pub fn get_current_directory_map() -> Option<DirectoryContentMap> {
    CURRENT_DIRECTORY_MAP.lock().unwrap().clone()
}

// Function to set the shares in the session
pub fn set_shares(shares_to_copy: Option<Vec<UserShareData>>) {
    let mut shares = SHARES.lock().unwrap();
    *shares = shares_to_copy;
}

// Function to get the shares from the session
pub fn get_shares() -> Option<Vec<UserShareData>> {
    SHARES.lock().unwrap().clone()
}

// Function to get a specific share by its encrypted name
pub fn get_share(encrypted_name: &str) -> Option<UserShareData> {
    let shares = SHARES.lock().unwrap();
    match shares.as_ref().unwrap().iter().find(|share| {
        share.encrypted_name == encrypted_name
    }) {
        Some(val) => Some(val.clone()),
        None => None
    }
}

// Function to clear all session-related data
pub fn clear_session() {
    set_username(None);
    set_private_key(None);
    set_current_directory_metadata(None);
    set_current_directory_map(None);
    set_shares(None);
    FOLDER_KEY_CHAIN.lock().unwrap().clear();
}

// Function to get the clear path from the session
pub fn get_clear_path() -> Option<String> {
    CLEAR_PATH.lock().unwrap().clone()
}

// Function to set the clear path in the session
pub fn set_clear_path(path: Option<String>) {
    let mut clear_path = CLEAR_PATH.lock().unwrap();
    *clear_path = path;
}

// Function to add a path to the clear path in the session
pub fn add_clear_path(path: &str) {
    let mut clear_path = CLEAR_PATH.lock().unwrap();
    clear_path.as_mut().map(|val| val.push_str(path));
    clear_path.as_mut().map(|val| val.push_str("/"));
}

// Function to remove the last path segment from the clear path in the session
pub fn remove_clear_path() {
    let mut clear_path = CLEAR_PATH.lock().unwrap();
    if let Some(path) = clear_path.as_mut() {
        let mut parts: Vec<&str> = path.split("/").collect();
        parts.pop();
        parts.pop();
        parts.push("");
        *path = parts.join("/");
    }
}
