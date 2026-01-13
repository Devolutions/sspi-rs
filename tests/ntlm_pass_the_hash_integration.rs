//! Integration test for pass-the-hash with NTLM authentication flow

#[cfg(test)]
mod ntlm_pth_integration {
    use md4::{Digest, Md4};
    use sspi::{ntlm::Ntlm, AuthIdentityBuffers, NtlmHash, Sspi, SspiImpl};

    /// Test NT hash from a known password
    /// Password: "Password123!" -> NT hash: 2B576ACBE6BCFDA7294D6BD18041B8FE
    const TEST_NT_HASH: &str = "2B576ACBE6BCFDA7294D6BD18041B8FE";
    const TEST_USERNAME: &str = "testuser";
    const TEST_DOMAIN: &str = "TESTDOMAIN";

    fn password_to_ntlm_hash(password: &str) -> [u8; 16] {
        // Convert password to UTF-16 Little Endian
        let utf16_password: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        // Create MD4 hasher and hash the UTF-16LE encoded password
        let mut hasher = Md4::new();
        hasher.update(&utf16_password);
        let result = hasher.finalize();
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&result);
        hash
    }

    #[test]
    fn test_ntlm_negotiate_with_hash() {
        // Create NTLM instance with hash-based credentials
        let nt_hash: NtlmHash = TEST_NT_HASH.try_into().expect("valid hash");

        assert_eq!(nt_hash, password_to_ntlm_hash("Password123!").into());

        let credentials = AuthIdentityBuffers::from_utf8_with_hash(TEST_USERNAME, TEST_DOMAIN, nt_hash);

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
        let hash_creds = AuthIdentityBuffers::from_utf8_with_hash(TEST_USERNAME, TEST_DOMAIN, nt_hash);

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
}
