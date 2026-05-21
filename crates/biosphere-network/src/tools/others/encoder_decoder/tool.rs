use crate::core::{Tool, ToolInfo, ToolArgs, ToolOutput, ToolCategory, Result, ProgressReporter, ToolError};
use base64::{engine::general_purpose, Engine as _};
use sha1::{Sha1, Digest};
use sha2::{Sha256, Sha384, Sha512};
use md5::{Md5};

use super::{EncoderResult, EncodingType, Operation};

pub struct EncoderDecoderTool;

macro_rules! impl_hash {
    ($($name:ident => $hasher:ty),*) => {
        $(
            fn $name(input: &str) -> String {
                let mut hasher = <$hasher>::new();
                hasher.update(input.as_bytes());
                format!("{:x}", hasher.finalize())
            }
        )*
    };
}

impl EncoderDecoderTool {
    pub fn new() -> Self {
        Self
    }

    fn encode(&self, encoding_type: &EncodingType, input: &str) -> Result<String> {
        match encoding_type {
            EncodingType::Base64 => self.encode_base64(input),
            EncodingType::Base64Url => self.encode_base64url(input),
            EncodingType::Url => self.encode_url(input),
            EncodingType::Html => self.encode_html(input),
            EncodingType::Hex => self.encode_hex(input),
            EncodingType::Base32 => self.encode_base32(input),
            EncodingType::Base58 => self.encode_base58(input),
            EncodingType::Jwt => Err(ToolError::ExecutionError("JWT encoding not supported".to_string())),
            EncodingType::Rot13 => self.encode_rot13(input),
            EncodingType::Rot47 => self.encode_rot47(input),
            EncodingType::Unicode => self.encode_unicode(input),
        }
    }

    fn decode(&self, encoding_type: &EncodingType, input: &str) -> Result<String> {
        match encoding_type {
            EncodingType::Base64 => self.decode_base64(input),
            EncodingType::Base64Url => self.decode_base64url(input),
            EncodingType::Url => self.decode_url(input),
            EncodingType::Html => self.decode_html(input),
            EncodingType::Hex => self.decode_hex(input),
            EncodingType::Base32 => self.decode_base32(input),
            EncodingType::Base58 => self.decode_base58(input),
            EncodingType::Jwt => self.decode_jwt(input),
            EncodingType::Rot13 => self.encode_rot13(input),
            EncodingType::Rot47 => self.encode_rot47(input),
            EncodingType::Unicode => self.decode_unicode(input),
        }
    }

    fn compute_hash(&self, hash_type: &str, input: &str) -> String {
        match hash_type {
            "md5" => Self::hash_md5(input),
            "sha1" => Self::hash_sha1(input),
            "sha256" => Self::hash_sha256(input),
            "sha384" => Self::hash_sha384(input),
            "sha512" => Self::hash_sha512(input),
            _ => Self::hash_sha256(input),
        }
    }

    impl_hash!(
        hash_md5 => Md5,
        hash_sha1 => Sha1,
        hash_sha256 => Sha256,
        hash_sha384 => Sha384,
        hash_sha512 => Sha512
    );

    fn encode_base64(&self, input: &str) -> Result<String> {
        Ok(general_purpose::STANDARD.encode(input.as_bytes()))
    }

    fn decode_base64(&self, input: &str) -> Result<String> {
        let decoded = general_purpose::STANDARD
            .decode(input)
            .map_err(|e| ToolError::ExecutionError(format!("Base64 decode error: {}", e)))?;
        String::from_utf8(decoded).map_err(|e| ToolError::ExecutionError(format!("UTF-8 conversion error: {}", e)))
    }

    fn encode_base64url(&self, input: &str) -> Result<String> {
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(input.as_bytes()))
    }

    fn decode_base64url(&self, input: &str) -> Result<String> {
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|e| ToolError::ExecutionError(format!("Base64URL decode error: {}", e)))?;
        String::from_utf8(decoded).map_err(|e| ToolError::ExecutionError(format!("UTF-8 conversion error: {}", e)))
    }

    fn encode_url(&self, input: &str) -> Result<String> {
        Ok(urlencoding::encode(input).into_owned())
    }

    fn decode_url(&self, input: &str) -> Result<String> {
        urlencoding::decode(input)
            .map(|s| s.into_owned())
            .map_err(|e| ToolError::ExecutionError(format!("URL decode error: {}", e)))
    }

    fn encode_html(&self, input: &str) -> Result<String> {
        let mut result = String::new();
        for c in input.chars() {
            match c {
                '&' => result.push_str("&amp;"),
                '<' => result.push_str("&lt;"),
                '>' => result.push_str("&gt;"),
                '"' => result.push_str("&quot;"),
                '\'' => result.push_str("&#39;"),
                _ => result.push(c),
            }
        }
        Ok(result)
    }

    fn decode_html(&self, input: &str) -> Result<String> {
        let mut result = input.to_string();
        result = result.replace("&amp;", "&");
        result = result.replace("&lt;", "<");
        result = result.replace("&gt;", ">");
        result = result.replace("&quot;", "\"");
        result = result.replace("&#39;", "'");
        result = result.replace("&nbsp;", " ");
        Ok(result)
    }

    fn encode_hex(&self, input: &str) -> Result<String> {
        Ok(input
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""))
    }

    fn decode_hex(&self, input: &str) -> Result<String> {
        if input.len() % 2 != 0 {
            return Err(ToolError::ExecutionError("Hex string must have even length".to_string()));
        }

        let decoded = (0..input.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&input[i..i + 2], 16)
                    .map_err(|e| ToolError::ExecutionError(format!("Hex decode error at position {}: {}", i, e)))
            })
            .collect::<Result<Vec<u8>>>()?;

        String::from_utf8(decoded).map_err(|e| ToolError::ExecutionError(format!("UTF-8 conversion error: {}", e)))
    }

    fn encode_bytes(&self, encoding_type: &str, input: &[u8]) -> Result<String> {
        match encoding_type {
            "base64" | "base64url" | "hex" | "base32" | "base58" => {
                let str_input = std::str::from_utf8(input)
                    .map_err(|e| ToolError::ExecutionError(format!("UTF-8 error: {}", e)))?;
                self.encode(&Self::str_to_encoding(encoding_type)?, str_input)
            }
            _ => Err(ToolError::ExecutionError(format!("Unsupported encoding type for binary data: {}", encoding_type))),
        }
    }

    fn decode_bytes(&self, encoding_type: &str, input: &str) -> Result<Vec<u8>> {
        let decoded = self.decode(&Self::str_to_encoding(encoding_type)?, input)?;
        Ok(decoded.into_bytes())
    }

    fn encode_base32(&self, input: &str) -> Result<String> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bytes = input.as_bytes();
        let mut result = String::new();
        
        for chunk in bytes.chunks(5) {
            let mut buffer = [0u8; 8];
            let mut bits: u64 = 0;
            let mut remaining = chunk.len();
            
            for &byte in chunk {
                bits <<= 8;
                bits |= u64::from(byte);
            }
            
            bits <<= (5 - remaining) * 8;
            
            for i in (0..8).rev() {
                if remaining > 0 {
                    buffer[i] = ALPHABET[(bits & 0x1F) as usize];
                    bits >>= 5;
                    remaining -= 1;
                } else {
                    buffer[i] = b'=';
                }
            }
            
            result.push_str(std::str::from_utf8(&buffer).unwrap_or(""));
        }
        
        Ok(result)
    }

    fn decode_base32(&self, input: &str) -> Result<String> {
        let input = input.trim().replace("=", "");
        let mut result = Vec::new();
        
        for chunk in input.as_bytes().chunks(8) {
            let mut bits: u64 = 0;
            let mut count = 0;
            
            for &c in chunk {
                if c == b'=' { break; }
                
                let val = if (b'A'..=b'Z').contains(&c) {
                    c - b'A'
                } else if (b'2'..=b'7').contains(&c) {
                    c - b'2' + 26
                } else {
                    return Err(ToolError::ExecutionError(format!("Invalid Base32 character: {}", c as char)));
                };
                
                bits <<= 5;
                bits |= u64::from(val);
                count += 1;
            }
            
            bits <<= (8 - count) * 5;
            let byte_count = (count * 5) / 8;
            
            for i in (0..byte_count).rev() {
                result.push(((bits >> (i * 8)) & 0xFF) as u8);
            }
        }
        
        String::from_utf8(result).map_err(|e| ToolError::ExecutionError(format!("UTF-8 conversion error: {}", e)))
    }

    fn encode_base58(&self, input: &str) -> Result<String> {
        Ok(bs58::encode(input.as_bytes()).into_string())
    }

    fn decode_base58(&self, input: &str) -> Result<String> {
        let decoded = bs58::decode(input)
            .into_vec()
            .map_err(|e| ToolError::ExecutionError(format!("Base58 decode error: {:?}", e)))?;
        String::from_utf8(decoded).map_err(|e| ToolError::ExecutionError(format!("UTF-8 conversion error: {}", e)))
    }

    fn str_to_encoding(s: &str) -> Result<EncodingType> {
        match s {
            "base64" => Ok(EncodingType::Base64),
            "base64url" => Ok(EncodingType::Base64Url),
            "url" => Ok(EncodingType::Url),
            "html" => Ok(EncodingType::Html),
            "hex" => Ok(EncodingType::Hex),
            "base32" => Ok(EncodingType::Base32),
            "base58" => Ok(EncodingType::Base58),
            "jwt" => Ok(EncodingType::Jwt),
            "rot13" => Ok(EncodingType::Rot13),
            "rot47" => Ok(EncodingType::Rot47),
            "unicode" => Ok(EncodingType::Unicode),
            _ => Err(ToolError::ExecutionError(format!("Unsupported encoding type: {}", s))),
        }
    }

    fn str_to_operation(s: &str) -> Result<Operation> {
        match s {
            "encode" => Ok(Operation::Encode),
            "decode" => Ok(Operation::Decode),
            "hash" => Ok(Operation::Hash),
            _ => Err(ToolError::ExecutionError(format!("Unsupported operation: {}", s))),
        }
    }

    fn encoding_type_name(encoding_type: &EncodingType) -> &'static str {
        match encoding_type {
            EncodingType::Base64 => "Base64",
            EncodingType::Base64Url => "Base64URL",
            EncodingType::Url => "URL",
            EncodingType::Html => "HTML",
            EncodingType::Hex => "Hex",
            EncodingType::Base32 => "Base32",
            EncodingType::Base58 => "Base58",
            EncodingType::Jwt => "JWT",
            EncodingType::Rot13 => "ROT13",
            EncodingType::Rot47 => "ROT47",
            EncodingType::Unicode => "Unicode",
        }
    }

    fn operation_name(operation: &Operation) -> &'static str {
        match operation {
            Operation::Encode => "Encode",
            Operation::Decode => "Decode",
            Operation::Hash => "Hash",
        }
    }

    pub fn detect_encoding(input: &str) -> Result<(EncodingType, f64)> {
        let trimmed = input.trim();
        
        if trimmed.is_empty() {
            return Err(ToolError::ExecutionError("Empty input".to_string()));
        }

        if Self::is_valid_jwt(trimmed) {
            return Ok((EncodingType::Jwt, 0.95));
        }

        if Self::is_valid_base64(trimmed) {
            return Ok((EncodingType::Base64, 0.9));
        }

        if Self::is_valid_base64url(trimmed) {
            return Ok((EncodingType::Base64Url, 0.85));
        }

        if Self::is_valid_hex(trimmed) {
            return Ok((EncodingType::Hex, 0.8));
        }

        if trimmed.contains('%') && Self::is_valid_url_encoded(trimmed) {
            return Ok((EncodingType::Url, 0.95));
        }

        if trimmed.contains('&') && trimmed.contains(';') && Self::is_valid_html_encoded(trimmed) {
            return Ok((EncodingType::Html, 0.9));
        }

        if Self::is_valid_unicode(trimmed) {
            return Ok((EncodingType::Unicode, 0.85));
        }

        if Self::is_valid_base32(trimmed) {
            return Ok((EncodingType::Base32, 0.7));
        }

        if Self::is_valid_base58(trimmed) {
            return Ok((EncodingType::Base58, 0.6));
        }

        Err(ToolError::ExecutionError("Unable to detect encoding type".to_string()))
    }

    fn is_valid_base64(s: &str) -> bool {
        if s.is_empty() || s.len() % 4 != 0 {
            return false;
        }
        
        let valid_chars = s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
        });
        
        if !valid_chars {
            return false;
        }

        general_purpose::STANDARD.decode(s).is_ok()
    }

    fn is_valid_base64url(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        
        let valid_chars = s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        });
        
        if !valid_chars {
            return false;
        }

        general_purpose::URL_SAFE_NO_PAD.decode(s).is_ok()
    }

    fn is_valid_hex(s: &str) -> bool {
        if s.is_empty() || s.len() % 2 != 0 {
            return false;
        }
        
        s.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn is_valid_url_encoded(s: &str) -> bool {
        let mut chars = s.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '%' {
                let next_two: String = chars.by_ref().take(2).collect();
                if next_two.len() != 2 || !next_two.chars().all(|c| c.is_ascii_hexdigit()) {
                    return false;
                }
            }
        }
        
        true
    }

    fn is_valid_html_encoded(s: &str) -> bool {
        let re = regex::Regex::new(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z]+);").unwrap();
        re.is_match(s)
    }

    fn is_valid_base32(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        
        let s_upper = s.to_uppercase().replace("=", "");
        s_upper.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    }

    fn is_valid_base58(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        
        const BASE58_CHARS: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        s.chars().all(|c| BASE58_CHARS.contains(c))
    }

    fn is_valid_jwt(s: &str) -> bool {
        let parts: Vec<&str> = s.split('.').collect();
        
        if parts.len() != 3 {
            return false;
        }

        parts.iter().all(|part| {
            !part.is_empty() && part.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '-' || c == '_'
            })
        })
    }

    fn is_valid_unicode(s: &str) -> bool {
        let re = regex::Regex::new(r"(\\u[0-9a-fA-F]{4})+").unwrap();
        re.is_match(s) && s.contains("\\u")
    }

    fn decode_jwt(&self, input: &str) -> Result<String> {
        let parts: Vec<&str> = input.split('.').collect();
        
        if parts.len() != 3 {
            return Err(ToolError::ExecutionError("Invalid JWT format: expected 3 parts".to_string()));
        }

        let header = self.decode_base64url(parts[0])
            .map_err(|e| ToolError::ExecutionError(format!("Failed to decode JWT header: {}", e)))?;
        
        let payload = self.decode_base64url(parts[1])
            .map_err(|e| ToolError::ExecutionError(format!("Failed to decode JWT payload: {}", e)))?;
        
        let signature = parts[2];

        let result = serde_json::json!({
            "header": serde_json::from_str::<serde_json::Value>(&header)
                .unwrap_or_else(|_| header.clone().into()),
            "payload": serde_json::from_str::<serde_json::Value>(&payload)
                .unwrap_or_else(|_| payload.clone().into()),
            "signature": signature
        });

        Ok(serde_json::to_string_pretty(&result)
            .map_err(|e| ToolError::ExecutionError(format!("JSON formatting error: {}", e)))?)
    }

    fn encode_rot13(&self, input: &str) -> Result<String> {
        Ok(input.chars().map(|c| {
            match c {
                'A'..='M' | 'a'..='m' => ((c as u8) + 13) as char,
                'N'..='Z' | 'n'..='z' => ((c as u8) - 13) as char,
                _ => c,
            }
        }).collect())
    }

    fn encode_rot47(&self, input: &str) -> Result<String> {
        Ok(input.chars().map(|c| {
            let code = c as u8;
            if code >= 33 && code <= 126 {
                (((code - 33 + 47) % 94) + 33) as char
            } else {
                c
            }
        }).collect())
    }

    fn encode_unicode(&self, input: &str) -> Result<String> {
        Ok(input.chars().map(|c| {
            format!("\\u{:04x}", c as u32)
        }).collect())
    }

    fn decode_unicode(&self, input: &str) -> Result<String> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        
        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'u') {
                chars.next();
                let hex: String = chars.by_ref().take(4).collect();
                if let Ok(code) = u32::from_str_radix(&hex, 16) {
                    if let Some(unicode_char) = char::from_u32(code) {
                        result.push(unicode_char);
                    } else {
                        result.push_str(&format!("\\u{}", hex));
                    }
                } else {
                    result.push_str(&format!("\\u{}", hex));
                }
            } else {
                result.push(c);
            }
        }
        
        Ok(result)
    }
}

impl Tool for EncoderDecoderTool {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            id: "encoder_decoder".to_string(),
            name: "Encoder/Decoder".to_string(),
            description: "Multi-format encoding and decoding tool with hash calculation".to_string(),
            category: ToolCategory::Other,
            installed: true,
        }
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let encoding_type_str = args.get_option("encoding_type")
            .ok_or_else(|| ToolError::MissingArgument("encoding_type".to_string()))?;
        let operation_str = args.get_option("operation")
            .ok_or_else(|| ToolError::MissingArgument("operation".to_string()))?;
        let input = args.get_target()?;

        let encoding_type = Self::str_to_encoding(&encoding_type_str)?;
        let operation = Self::str_to_operation(&operation_str)?;

        let result = match operation {
            Operation::Encode => self.encode(&encoding_type, &input),
            Operation::Decode => self.decode(&encoding_type, &input),
            Operation::Hash => Ok(self.compute_hash(&encoding_type_str, &input)),
        };

        match result {
            Ok(output) => {
                let encoder_result = EncoderResult::success(
                    input.clone(),
                    output,
                    Self::encoding_type_name(&encoding_type).to_string(),
                    Self::operation_name(&operation).to_string(),
                );
                let json = serde_json::to_string(&encoder_result)
                    .map_err(|e| ToolError::ExecutionError(e.to_string()))?;
                Ok(ToolOutput::success(json))
            }
            Err(e) => Ok(ToolOutput::error(e.to_string())),
        }
    }
}

pub async fn encode_decode(
    encoding_type: String,
    operation: String,
    input: String,
) -> Result<EncoderResult> {
    let tool = EncoderDecoderTool::new();
    let args = ToolArgs::new(Some(input))
        .with_option("encoding_type".to_string(), encoding_type)
        .with_option("operation".to_string(), operation);
    
    let output = tool.run(args, None)?;
    
    if output.success {
        serde_json::from_str(&output.data)
            .map_err(|e| ToolError::ExecutionError(e.to_string()))
    } else {
        Err(ToolError::ExecutionError(output.error.unwrap_or_else(|| "Unknown error".to_string())))
    }
}

pub fn encode_bytes(encoding_type: String, input: Vec<u8>) -> Result<String> {
    EncoderDecoderTool::new().encode_bytes(&encoding_type, &input)
}

pub fn decode_bytes(encoding_type: String, input: String) -> Result<Vec<u8>> {
    EncoderDecoderTool::new().decode_bytes(&encoding_type, &input)
}

pub fn compute_hash(hash_type: String, input: String) -> Result<String> {
    Ok(EncoderDecoderTool::new().compute_hash(&hash_type, &input))
}

pub fn timestamp_to_datetime(timestamp: i64) -> Result<String> {
    if timestamp == 0 {
        return Err(ToolError::ExecutionError("Invalid timestamp".to_string()));
    }
    
    let datetime = chrono::DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| ToolError::ExecutionError("Invalid timestamp".to_string()))?;
    
    Ok(datetime.format("%Y-%m-%d %H:%M:%S").to_string())
}

pub fn datetime_to_timestamp(datetime_str: String) -> Result<i64> {
    let datetime = chrono::NaiveDateTime::parse_from_str(&datetime_str, "%Y-%m-%d %H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(&datetime_str, "%Y-%m-%dT%H:%M:%S"))
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(&datetime_str, "%Y/%m/%d %H:%M:%S"))
        .map_err(|e| ToolError::ExecutionError(format!("Failed to parse datetime: {}", e)))?;
    
    Ok(datetime.and_utc().timestamp())
}

pub fn get_current_timestamp() -> String {
    let now = chrono::Utc::now().timestamp();
    format!("{}", now)
}