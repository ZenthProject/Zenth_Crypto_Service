use zenth_crypto_service::encoding::pem::{PemEncodeImpl,PemEncodeSecure};

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};

    #[test]
    fn test_pem_encode_decode_roundtrip() {
        let label = "TEST BLOCK";
        let data = b"some binary data";

        let encoded = PemEncodeImpl::pemencode(label, data);
        let decoded = PemEncodeImpl::pemdecode(&encoded).expect("PEM decoding failed");

        assert_eq!(decoded, data);
        assert!(encoded.contains("BEGIN TEST BLOCK"));
        assert!(encoded.contains("END TEST BLOCK"));
    }

    #[test]
    fn test_pem_encode_format() {
        let label = "MY DATA";
        let data = b"hello world";

        let pem = PemEncodeImpl::pemencode(label, data);
        let base64_data = general_purpose::STANDARD.encode(data);

        assert!(pem.contains("BEGIN MY DATA"));
        assert!(pem.contains(&base64_data));
        assert!(pem.contains("END MY DATA"));
    }

    #[test]
    fn test_pem_decode_invalid_format() {
        let invalid_pem = "-----BEGIN INVALID-----\nnot base64\n-----END INVALID-----";

        let result = PemEncodeImpl::pemdecode(invalid_pem);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .starts_with("PEM decode error:"), "Error message should be prefixed");
    }
}
