use base64::Engine;
use base64::engine::general_purpose;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S: Serializer>(v: &Vec<u8>, s:S) -> anyhow::Result<S::Ok, S::Error> {
    let base64 = general_purpose::STANDARD.encode(v);
    let format_base64 = base64.replace('/', "_");
    String::serialize(&format_base64, s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> anyhow::Result<Vec<u8>, D::Error> {
    let base64 = String::deserialize(d)?;
    let format_base64 = base64.replace('_', "/");
    general_purpose::STANDARD.decode(format_base64.as_bytes()).map_err(serde::de::Error::custom)
}