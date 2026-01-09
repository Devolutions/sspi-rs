//! Tests for pass-the-hash authentication

#[cfg(test)]
mod tests {
    use sspi::{AuthIdentityBuffers, NtlmHash};

    #[test]
    fn test_ntlm_hash_from_hex_string() {
        // Test valid 32-character hex string
        let hash_str = "32ed87bdb5fdc5e9cba88547376818d4";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_ok());
        
        let hash = result.unwrap();
        assert_eq!(hash.as_bytes().len(), 16);
    }

    #[test]
    fn test_ntlm_hash_from_bytes() {
        let bytes = [
            0x32, 0xed, 0x87, 0xbd, 0xb5, 0xfd, 0xc5, 0xe9,
            0xcb, 0xa8, 0x85, 0x47, 0x37, 0x68, 0x18, 0xd4,
        ];
        
        let result: Result<NtlmHash, _> = bytes.as_slice().try_into();
        assert!(result.is_ok());
        
        let hash = result.unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_ntlm_hash_invalid_hex_length() {
        // Too short
        let hash_str = "32ed87bdb5fdc5e9cba885473768";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_err());
        
        // Too long
        let hash_str = "32ed87bdb5fdc5e9cba88547376818d4ff";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_ntlm_hash_invalid_hex_characters() {
        let hash_str = "32ed87bdb5fdc5e9cba88547376818zz";
        let result: Result<NtlmHash, _> = hash_str.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_ntlm_hash_invalid_byte_length() {
        let bytes = [0x32, 0xed, 0x87, 0xbd, 0xb5];
        let result: Result<NtlmHash, _> = bytes.as_slice().try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_identity_buffers_with_hash() {
        let hash_str = "32ed87bdb5fdc5e9cba88547376818d4";
        let hash: NtlmHash = hash_str.try_into().unwrap();
        
        let credentials = AuthIdentityBuffers::from_utf8_with_hash(
            "Administrator",
            "CONTOSO",
            *hash.as_bytes(),
        );
        
        assert!(!credentials.user.is_empty());
        assert!(!credentials.domain.is_empty());
        assert!(credentials.ntlm_hash().is_some());
        assert!(credentials.password().is_none());
        assert!(credentials.credential_type().is_ntlm_hash());
        assert!(!credentials.credential_type().is_password());
    }

    #[test]
    fn test_auth_identity_buffers_with_password() {
        let credentials = AuthIdentityBuffers::from_utf8(
            "Administrator",
            "CONTOSO",
            "MyPassword123",
        );
        
        assert!(!credentials.user.is_empty());
        assert!(!credentials.domain.is_empty());
        assert!(credentials.password().is_some());
        assert!(credentials.ntlm_hash().is_none());
        assert!(credentials.credential_type().is_password());
        assert!(!credentials.credential_type().is_ntlm_hash());
    }

    #[test]
    fn test_ntlm_hash_case_insensitive() {
        let lowercase = "32ed87bdb5fdc5e9cba88547376818d4";
        let uppercase = "32ED87BDB5FDC5E9CBA88547376818D4";
        let mixed = "32Ed87BdB5FdC5e9CbA88547376818D4";
        
        let hash1: NtlmHash = lowercase.try_into().unwrap();
        let hash2: NtlmHash = uppercase.try_into().unwrap();
        let hash3: NtlmHash = mixed.try_into().unwrap();
        
        assert_eq!(hash1.as_bytes(), hash2.as_bytes());
        assert_eq!(hash2.as_bytes(), hash3.as_bytes());
    }
}
