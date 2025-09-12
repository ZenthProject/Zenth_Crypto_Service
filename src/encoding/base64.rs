use base64::{engine::general_purpose, Engine};

pub trait EncodeSecure {
    fn base64encode(data: &[u8]) -> String;
    fn base64decode(encoded_message: &str) -> Result<String, String>;
    fn base64_vecdecode(encoded_message: &str) -> Result<Vec<u8>, String>;
}

pub struct EncodeImpl;

impl EncodeSecure for EncodeImpl {

    fn base64_vecdecode(encoded_message: &str) -> Result<Vec<u8>, String> {
        general_purpose::STANDARD
            .decode(encoded_message)
            .map_err(|e| format!("Base64 decode error: {}", e))
    }

    fn base64decode(encoded_message: &str) -> Result<String, String> {
        let decoded_bytes = general_purpose::STANDARD
            .decode(encoded_message)
            .map_err(|e| format!("Base64 decode error: {}", e))?;
        String::from_utf8(decoded_bytes).map_err(|e| format!("UTF-8 decode error: {}", e))
    }   

    fn base64encode(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }
}







