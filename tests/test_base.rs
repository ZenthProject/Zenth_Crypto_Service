use zenth_crypto_service::hashs::{base64decode, base64encode, base64_vecdecode};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic_ascii() {
        let input = b"Hello, World!";
        let expected = "SGVsbG8sIFdvcmxkIQ==";
        assert_eq!(base64encode(input), expected);
    }

    #[test]
    fn test_encode_empty() {
        let input = b"";
        let expected = "";
        assert_eq!(base64encode(input), expected);
    }

    #[test]
    fn test_decode_basic_ascii() {
        let encoded = "SGVsbG8sIFdvcmxkIQ==";
        let expected = "Hello, World!";
        assert_eq!(base64decode(encoded).unwrap(), expected);
    }

    #[test]
    fn test_decode_empty_string() {
        let encoded = "";
        let expected = "";
        assert_eq!(base64decode(encoded).unwrap(), expected);
    }

    #[test]
    fn test_decode_invalid_base64() {
        let encoded = "!!!";
        let result = base64decode(encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Base64 decode error"));
    }

    #[test]
    fn test_decode_invalid_utf8() {
        let binary_data = vec![0xff, 0xfe, 0xfd];
        let encoded = base64encode(&binary_data);
        let result = base64decode(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("UTF-8 decode error"));
    }

    #[test]
    fn test_vecdecode_valid() {
        let input = b"\x01\x02\x03\x04";
        let encoded = base64encode(input);
        let decoded = base64_vecdecode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_vecdecode_invalid_base64() {
        let encoded = "@@@";
        let result = base64_vecdecode(encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Base64 decode error"));
    }

    #[test]
    fn test_roundtrip_ascii() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let encoded = base64encode(original);
        let decoded = base64decode(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), original);
    }

    #[test]
    fn test_roundtrip_binary() {
        let original = (0..=255).collect::<Vec<u8>>();
        let encoded = base64encode(&original);
        let decoded = base64_vecdecode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_base64_encoding_decoding() {
        let data = b"Hello, Base64!";
        let encoded = base64encode(data);
        let decoded = base64decode(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), data);
    }
}
