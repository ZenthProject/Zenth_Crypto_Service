use pem::{Pem, encode, parse};

pub trait PemEncodeSecure {
    fn pemencode(label: &str, data: &[u8]) -> String;
    fn pemdecode(pem_str: &str) -> Result<Vec<u8>, String>;
}

pub struct PemEncodeImpl;

impl PemEncodeSecure for PemEncodeImpl {
    fn pemencode(label: &str, data: &[u8]) -> String {
        let pem_struct = Pem::new(label.to_string(), data.to_vec());
        encode(&pem_struct)
        
    }

    fn pemdecode(pem_str: &str) -> Result<Vec<u8>, String> {
        let pem = parse(pem_str)
            .map_err(|e| format!("PEM decode error: {}", e))?;
        Ok(pem.contents().to_vec())
        
    }
}
