use hex;

pub trait HexEncodeSecure {
    fn hexencode(data: &[u8]) -> String;
    fn hexdecode(encoded_message: &str) -> Result<Vec<u8>, String>;
    fn hexdecode_to_string(encoded_message: &str) -> Result<String, String>;
}

pub struct HexEncodeImpl;

impl HexEncodeSecure for HexEncodeImpl {

    fn hexencode(data: &[u8]) -> String {
        hex::encode(data)
    }

    fn hexdecode(encoded_message: &str) -> Result<Vec<u8>, String> {
        hex::decode(encoded_message)
            .map_err(|e| format!("Hex decode error: {}", e))
    }

    fn hexdecode_to_string(encoded_message: &str) -> Result<String, String> {
        let bytes = hex::decode(encoded_message)
            .map_err(|e| format!("Hex decode error: {}", e))?;
        String::from_utf8(bytes)
            .map_err(|e| format!("UTF-8 decode error: {}", e))
    }
}
