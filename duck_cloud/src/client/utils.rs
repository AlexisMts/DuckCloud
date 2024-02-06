use base64::Engine;
use base64::engine::general_purpose;
use anyhow::{Result};

pub fn vec_to_b64(data: &Vec<u8>) -> String {
    let mut encrypted_file_name_base64 = String::new();
    general_purpose::STANDARD.encode_string(data, &mut encrypted_file_name_base64);
    encrypted_file_name_base64.replace('/', "_")
}

pub fn b64_to_vec(data: &str) -> Result<Vec<u8>> {
    let mut encrypted_file_name = Vec::new();
    general_purpose::STANDARD.decode_vec(data.replace('_', "/").as_bytes(), &mut encrypted_file_name)?;
    Ok(encrypted_file_name)
}

pub fn contains_non_alphanumeric(input: &str) -> bool {
    input.chars().any(|c| !c.is_alphanumeric())
}

