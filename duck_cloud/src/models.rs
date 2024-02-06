use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::format;

// Struct used to construct user's metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct UserMetadata {
    pub username: String,
    #[serde(with = "format")]
    pub master_password_hash: Vec<u8>,
    #[serde(with = "format")]
    pub protected_symmetric_key: Vec<u8>,
    #[serde(with = "format")]
    pub protected_private_key: Vec<u8>,
    #[serde(with = "format")]
    pub public_key_bytes: Vec<u8>,
    pub shares: Vec<UserShareData>,
}

// Struct used to map clean names with encrypted names, it also says if a folder is shared
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirectoryContentMap {
    pub folders: HashMap<String, String>,
    pub files: HashMap<String, String>,
    pub sharing_state: HashMap<String, bool>,
}

// Struct used to represent the content of the current directory with its folders, files, etc...
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirectoryMetadata {
    pub owner: String,
    pub path: String,
    pub folders: Vec<FolderMetadata>,
    pub files: Vec<FileMetadata>,
}

// Struct used to represent the metadata of a folder
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FolderMetadata {
    pub name: String,
    #[serde(with = "format")]
    pub protected_symmetric_key: Vec<u8>,
    pub shares: Vec<FolderShareData>,
}

// Struct used to represent the metadata of a file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileMetadata {
    pub name: String,
}

// Struct used to represent the sharing metadata in a folder
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct FolderShareData {
    pub username: String,
}

// Struct used to represent a file
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileData {
    pub file_name: String,
    pub file_content: Vec<u8>,
    pub file_path: String,
}

// Struct used to represent the sharing metadata of a user
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserShareData {
    pub owner: String,
    pub path: String,
    pub encrypted_name: String,
    #[serde(with = "format")]
    pub protected_symmetric_key: Vec<u8>,
}

impl Default for DirectoryContentMap {
    fn default() -> Self {
        DirectoryContentMap {
            folders: HashMap::new(),
            files: HashMap::new(),
            sharing_state: HashMap::new(),
        }
    }
}

impl Default for DirectoryMetadata {
    fn default() -> Self {
        DirectoryMetadata {
            owner: "".to_string(),
            path: "".to_string(),
            folders: Vec::new(),
            files: Vec::new(),
        }
    }
}

impl DirectoryMetadata {
    pub fn init(owner: &str, path: &str) -> Self {
        DirectoryMetadata {
            owner: owner.to_string(),
            path: path.to_string(),
            folders: Vec::new(),
            files: Vec::new(),
        }
    }
}

