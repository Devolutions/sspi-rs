//! Integration test for pass-the-hash with NTLM authentication flow

#[cfg(test)]
mod ntlm_pth_integration {
    use sspi::{ntlm::Ntlm, AuthIdentityBuffers, NtlmHash, Sspi, SspiImpl};

    /// Test NT hash from a known password
    /// Password: "Password123!" -> NT hash: 32ed87bdb5fdc5e9cba88547376818d4
    const TEST_NT_HASH: &str = "32ed87bdb5fdc5e9cba88547376818d4";
    const TEST_USERNAME: &str = "testuser";
    const TEST_DOMAIN: &str = "TESTDOMAIN";

    #[test]
    fn test_ntlm_negotiate_with_hash() {
        // Create NTLM instance with hash-based credentials
        let nt_hash: NtlmHash = TEST_NT_HASH.try_into().expect("valid hash");
        let credentials = AuthIdentityBuffers::from_utf8_with_hash(TEST_USERNAME, TEST_DOMAIN, *nt_hash.as_bytes());

        let mut ntlm = Ntlm::with_auth_identity(Some(credentials.clone()), Default::default());

        // Initialize security context (NEGOTIATE phase)
        let mut output = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];

        let mut binding = Some(credentials.clone());

        let mut builder = ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut binding)
            .with_context_requirements(sspi::ClientRequestFlags::CONFIDENTIALITY)
            .with_target_data_representation(sspi::DataRepresentation::Native)
            .with_output(&mut output);

        let result = ntlm.initialize_security_context_impl(&mut builder);

        // Should succeed in creating NEGOTIATE message
        assert!(result.is_ok(), "Failed to create NEGOTIATE message: {:?}", result);
        let result = result.unwrap().resolve_to_result().unwrap();
        assert_eq!(result.status, sspi::SecurityStatus::ContinueNeeded);
        assert!(!output[0].buffer.is_empty(), "NEGOTIATE token should not be empty");
    }

    #[test]
    fn test_credential_type_detection() {
        // Hash-based credentials
        let nt_hash: NtlmHash = TEST_NT_HASH.try_into().expect("valid hash");
        let hash_creds = AuthIdentityBuffers::from_utf8_with_hash(TEST_USERNAME, TEST_DOMAIN, *nt_hash.as_bytes());

        assert!(hash_creds.credential_type().is_ntlm_hash());
        assert!(!hash_creds.credential_type().is_password());
        assert!(hash_creds.ntlm_hash().is_some());
        assert!(hash_creds.password().is_none());

        // Password-based credentials
        let pwd_creds = AuthIdentityBuffers::from_utf8(TEST_USERNAME, TEST_DOMAIN, "TestPassword");

        assert!(!pwd_creds.credential_type().is_ntlm_hash());
        assert!(pwd_creds.credential_type().is_password());
        assert!(pwd_creds.password().is_some());
        assert!(pwd_creds.ntlm_hash().is_none());
    }

    #[test]
    fn test_ntlm_hash_validation() {
        // Valid hash
        let valid: Result<NtlmHash, _> = "32ed87bdb5fdc5e9cba88547376818d4".try_into();
        assert!(valid.is_ok());

        // Invalid length
        let invalid_len: Result<NtlmHash, _> = "32ed87bd".try_into();
        assert!(invalid_len.is_err());

        // Invalid characters
        let invalid_chars: Result<NtlmHash, _> = "32ed87bdb5fdc5e9cba88547376818zz".try_into();
        assert!(invalid_chars.is_err());

        // Empty string
        let empty: Result<NtlmHash, _> = "".try_into();
        assert!(empty.is_err());
    }
}
