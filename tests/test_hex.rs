#[cfg(test)]
mod tests {
    use zenth_crypto_service::{encoding::hex::HexEncodeImpl, HexEncodeSecure};


    #[test]
    fn test_hex_encode_basic() {
        let data = b"hello";
        let encoded = HexEncodeImpl::hexencode(data);
        assert_eq!(encoded, "68656c6c6f");
    }

    #[test]
    fn test_hex_decode_basic() {
        let encoded = "68656c6c6f";
        let decoded = HexEncodeImpl::hexdecode(encoded).expect("Decoding failed");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_hex_decode_to_string() {
        let encoded = "48657820656e636f64696e67"; // "Hex encoding"
        let decoded = HexEncodeImpl::hexdecode_to_string(encoded).expect("UTF-8 decoding failed");
        assert_eq!(decoded, "Hex encoding");
    }

    #[test]
    fn test_hex_decode_invalid_input() {
        let invalid = "zzzz";
        let result = HexEncodeImpl::hexdecode(invalid);
        assert!(result.is_err());
        assert!(result.unwrap_err().starts_with("Hex decode error"));
    }

    #[test]
    fn test_hex_decode_to_string_invalid_utf8() {
        // "ff" is not valid UTF-8
        let encoded = "ff";
        let result = HexEncodeImpl::hexdecode_to_string(encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().starts_with("UTF-8 decode error"));
    }

    #[test]
    fn test_hex_encode_empty() {
        let data: &[u8] = b"";
        let encoded = HexEncodeImpl::hexencode(data);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_hex_decode_empty() {
        let encoded = "";
        let decoded = HexEncodeImpl::hexdecode(encoded).expect("Decoding empty string failed");
        assert_eq!(decoded, b"");
    }
}
