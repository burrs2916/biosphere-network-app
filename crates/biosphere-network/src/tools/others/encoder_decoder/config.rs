use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncodingType {
    Base64,
    Base64Url,
    Url,
    Html,
    Hex,
    Base32,
    Base58,
    Jwt,
    Rot13,
    Rot47,
    Unicode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    Encode,
    Decode,
    Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncoderConfig {
    pub encoding_type: EncodingType,
    pub operation: Operation,
    pub input: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashConfig {
    pub hash_type: HashType,
    pub input: String,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            encoding_type: EncodingType::Base64,
            operation: Operation::Encode,
            input: String::new(),
        }
    }
}
