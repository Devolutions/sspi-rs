use std::fmt;

use crate::{utils, Error, Secret};

/// Type alias for NT hash bytes (16 bytes)
pub type NtlmHashBytes = [u8; 16];

/// Represents an NT hash (16 bytes) used for pass-the-hash authentication
#[derive(Clone, Eq, PartialEq)]
pub struct NtlmHash([u8; 16]);

impl NtlmHash {
    /// Creates a new NtlmHash from a byte array
    pub fn new(hash: [u8; 16]) -> Self {
        Self(hash)
    }

    /// Returns a reference to the hash bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<&[u8]> for NtlmHash {
    type Error = NtlmHashError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err(NtlmHashError::ByteLength);
        }

        let mut hash = [0u8; 16];
        hash.copy_from_slice(value);
        Ok(NtlmHash(hash))
    }
}

impl From<NtlmHash> for [u8; 16] {
    fn from(hash: NtlmHash) -> Self {
        hash.0
    }
}

impl TryFrom<&str> for NtlmHash {
    type Error = NtlmHashError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(NtlmHashError::StringLength);
        }

        let mut hash = [0u8; 16];
        for i in 0..16 {
            let hex_byte = &value[i * 2..i * 2 + 2];
            hash[i] = u8::from_str_radix(hex_byte, 16).map_err(|_| NtlmHashError::Hex)?;
        }

        Ok(NtlmHash(hash))
    }
}

impl AsRef<NtlmHash> for NtlmHash {
    fn as_ref(&self) -> &NtlmHash {
        self
    }
}

impl fmt::Debug for NtlmHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtlmHash([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NtlmHashError {
    /// Invalid string length for NTLM hash (must be 32-character hex string)
    StringLength,
    /// Invalid byte length for NTLM hash (must be 16 bytes)
    ByteLength,
    /// Invalid hex string
    Hex,
}

impl std::error::Error for NtlmHashError {}

impl fmt::Display for NtlmHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtlmHashError::StringLength => {
                write!(f, "invalid length: expected 32-character hex string for NTLM hash")
            }
            NtlmHashError::ByteLength => write!(f, "invalid length: expected 16 bytes for NTLM hash"),
            NtlmHashError::Hex => write!(f, "invalid hex string for NTLM hash"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsernameError {
    MixedFormat,
    InvalidUtf16,
}

impl std::error::Error for UsernameError {}

impl fmt::Display for UsernameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsernameError::MixedFormat => write!(f, "mixed username format"),
            UsernameError::InvalidUtf16 => write!(f, "invalid UTF-16 string"),
        }
    }
}

/// Enumeration of the supported [User Name Formats].
///
/// [User Name Formats]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UserNameFormat {
    /// [User principal name] (UPN) format is used to specify an Internet-style name, such as UserName@Example.Microsoft.com.
    ///
    /// [User principal name]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#user-principal-name
    UserPrincipalName,
    /// The [down-level logon name] format is used to specify a domain and a user account in that domain, for example, DOMAIN\UserName.
    ///
    /// [down-level logon name]: https://learn.microsoft.com/en-us/windows/win32/secauthn/user-name-formats#down-level-logon-name
    DownLevelLogonName,
}

/// A username formatted as either UPN or Down-Level Logon Name
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Username {
    value: String,
    format: UserNameFormat,
    sep_idx: Option<usize>,
}

impl Username {
    /// Builds a user principal name from an account name and an UPN suffix
    pub fn new_upn(account_name: &str, upn_suffix: &str) -> Result<Self, UsernameError> {
        // NOTE: AD usernames may contain `@`
        if account_name.contains(['\\']) {
            return Err(UsernameError::MixedFormat);
        }

        if upn_suffix.contains(['\\', '@']) {
            return Err(UsernameError::MixedFormat);
        }

        Ok(Self {
            value: format!("{account_name}@{upn_suffix}"),
            format: UserNameFormat::UserPrincipalName,
            sep_idx: Some(account_name.len()),
        })
    }

    /// Builds a down-level logon name from an account name and a NetBIOS domain name
    pub fn new_down_level_logon_name(account_name: &str, netbios_domain_name: &str) -> Result<Self, UsernameError> {
        if account_name.contains(['\\', '@']) {
            return Err(UsernameError::MixedFormat);
        }

        if netbios_domain_name.contains(['\\', '@']) {
            return Err(UsernameError::MixedFormat);
        }

        Ok(Self {
            value: format!("{netbios_domain_name}\\{account_name}"),
            format: UserNameFormat::DownLevelLogonName,
            sep_idx: Some(netbios_domain_name.len()),
        })
    }

    /// Attempts to guess the right name format for the account name/domain combo
    ///
    /// If no netbios domain name is provided, or if it is an empty string, the username will
    /// be parsed as either a user principal name or a down-level logon name.
    ///
    /// It falls back to a down-level logon name when the format can’t be guessed.
    pub fn new(account_name: &str, netbios_domain_name: Option<&str>) -> Result<Self, UsernameError> {
        match netbios_domain_name {
            Some(netbios_domain_name) if !netbios_domain_name.is_empty() => {
                Self::new_down_level_logon_name(account_name, netbios_domain_name)
            }
            _ => Self::parse(account_name),
        }
    }

    /// Parses the value in order to find if the value is a user principal name or a down-level logon name
    ///
    /// If there is no `\` or `@` separator, the value is considered to be a down-level logon name with
    /// an empty NetBIOS domain.
    pub fn parse(value: &str) -> Result<Self, UsernameError> {
        match (value.split_once('\\'), value.rsplit_once('@')) {
            (None, None) => Ok(Self {
                value: value.to_owned(),
                format: UserNameFormat::DownLevelLogonName,
                sep_idx: None,
            }),
            (Some((netbios_domain_name, account_name)), _) => {
                Self::new_down_level_logon_name(account_name, netbios_domain_name)
            }
            (_, Some((account_name, upn_suffix))) => Self::new_upn(account_name, upn_suffix),
        }
    }

    /// Returns the internal representation, as-is
    pub fn inner(&self) -> &str {
        &self.value
    }

    /// Returns the [`UserNameFormat`] for this username
    pub fn format(&self) -> UserNameFormat {
        self.format
    }

    /// May return an UPN suffix or NetBIOS domain name depending on the internal format
    pub fn domain_name(&self) -> Option<&str> {
        self.sep_idx.map(|idx| match self.format {
            UserNameFormat::UserPrincipalName => &self.value[idx + 1..],
            UserNameFormat::DownLevelLogonName => &self.value[..idx],
        })
    }

    /// Returns the account name
    pub fn account_name(&self) -> &str {
        if let Some(idx) = self.sep_idx {
            match self.format {
                UserNameFormat::UserPrincipalName => &self.value[..idx],
                UserNameFormat::DownLevelLogonName => &self.value[idx + 1..],
            }
        } else {
            &self.value
        }
    }
}

/// Allows you to pass a particular user name and password to the run-time library for the purpose of authentication
///
/// # MSDN
///
/// * [SEC_WINNT_AUTH_IDENTITY_W structure](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_w)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthIdentity {
    pub username: Username,
    pub password: Secret<String>,
}

impl AuthIdentity {
    /// Creates a new AuthIdentity with a password
    pub fn new_password(username: Username, password: String) -> Self {
        Self {
            username,
            password: Secret::new(password),
        }
    }
}

/// Credential type for AuthIdentityBuffers
#[derive(Clone, Eq, PartialEq)]
pub enum CredentialType {
    /// Password-based credential (UTF-16 encoded)
    Password(Secret<Vec<u8>>),
    /// NT hash-based credential (16 bytes)
    NtlmHash(Secret<NtlmHashBytes>),
}

impl CredentialType {
    /// Returns true if this is a password credential
    pub fn is_password(&self) -> bool {
        matches!(self, CredentialType::Password(_))
    }

    /// Returns true if this is an NT hash credential
    pub fn is_ntlm_hash(&self) -> bool {
        matches!(self, CredentialType::NtlmHash(_))
    }

    /// Returns the password bytes if this is a password credential
    pub fn password(&self) -> Option<&[u8]> {
        match self {
            CredentialType::Password(p) => Some(p.as_ref()),
            CredentialType::NtlmHash(_) => None,
        }
    }

    /// Returns the NT hash if this is an NT hash credential
    pub fn ntlm_hash(&self) -> Option<&NtlmHashBytes> {
        match self {
            CredentialType::NtlmHash(h) => Some(h.as_ref()),
            CredentialType::Password(_) => None,
        }
    }
}

impl fmt::Debug for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialType::Password(_) => write!(f, "Password([redacted])"),
            CredentialType::NtlmHash(_) => write!(f, "NtlmHash([redacted])"),
        }
    }
}

/// Auth identity buffers for password-based logon.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthIdentityBuffers {
    /// Username.
    ///
    /// Must be UTF-16 encoded.
    pub user: Vec<u8>,
    /// Domain.
    ///
    /// Must be UTF-16 encoded.
    pub domain: Vec<u8>,
    /// Password or NT hash.
    ///
    /// For passwords, must be UTF-16 encoded.
    /// For NT hashes, must be 16 bytes.
    pub credential: CredentialType,
}

impl AuthIdentityBuffers {
    /// Creates a new [AuthIdentityBuffers] object based on provided credentials.
    ///
    /// Provided credentials must be UTF-16 encoded.
    pub fn new(user: Vec<u8>, domain: Vec<u8>, password: Vec<u8>) -> Self {
        Self {
            user,
            domain,
            credential: CredentialType::Password(password.into()),
        }
    }

    /// Creates a new [AuthIdentityBuffers] object with an NT hash.
    pub fn new_with_hash(user: Vec<u8>, domain: Vec<u8>, hash: NtlmHashBytes) -> Self {
        Self {
            user,
            domain,
            credential: CredentialType::NtlmHash(hash.into()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.user.is_empty()
    }

    /// Creates a new [AuthIdentityBuffers] object based on UTF-8 credentials.
    ///
    /// It converts the provided credentials to UTF-16 byte vectors automatically.
    pub fn from_utf8(user: &str, domain: &str, password: &str) -> Self {
        Self {
            user: utils::string_to_utf16(user),
            domain: utils::string_to_utf16(domain),
            credential: CredentialType::Password(utils::string_to_utf16(password).into()),
        }
    }

    /// Creates a new [AuthIdentityBuffers] object with a UTF-8 username/domain and NT hash.
    pub fn from_utf8_with_hash(user: &str, domain: &str, hash: NtlmHashBytes) -> Self {
        Self {
            user: utils::string_to_utf16(user),
            domain: utils::string_to_utf16(domain),
            credential: CredentialType::NtlmHash(hash.into()),
        }
    }

    /// Returns the credential type (password or NT hash)
    pub fn credential_type(&self) -> &CredentialType {
        &self.credential
    }

    /// Returns the password if using password authentication (for backward compatibility)
    pub fn password(&self) -> Option<&[u8]> {
        self.credential.password()
    }

    /// Returns the NT hash if using hash authentication
    pub fn ntlm_hash(&self) -> Option<&NtlmHashBytes> {
        self.credential.ntlm_hash()
    }
}

impl Default for AuthIdentityBuffers {
    fn default() -> Self {
        Self {
            user: Vec::new(),
            domain: Vec::new(),
            credential: CredentialType::Password(Vec::new().into()),
        }
    }
}

impl fmt::Debug for AuthIdentityBuffers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthIdentityBuffers {{ user: 0x")?;
        self.user.iter().try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", domain: 0x")?;
        self.domain.iter().try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", credential: {:?} }}", self.credential)?;

        Ok(())
    }
}

impl From<AuthIdentity> for AuthIdentityBuffers {
    fn from(credentials: AuthIdentity) -> Self {
        Self {
            user: utils::string_to_utf16(credentials.username.account_name()),
            domain: credentials
                .username
                .domain_name()
                .map(utils::string_to_utf16)
                .unwrap_or_default(),
            credential: CredentialType::Password(utils::string_to_utf16(credentials.password.as_ref()).into()),
        }
    }
}

impl TryFrom<&AuthIdentityBuffers> for AuthIdentity {
    type Error = UsernameError;

    fn try_from(credentials_buffers: &AuthIdentityBuffers) -> Result<Self, Self::Error> {
        let account_name =
            utils::bytes_to_utf16_string(&credentials_buffers.user).map_err(|_| UsernameError::InvalidUtf16)?;
        let domain_name = if !credentials_buffers.domain.is_empty() {
            Some(utils::bytes_to_utf16_string(&credentials_buffers.domain).map_err(|_| UsernameError::InvalidUtf16)?)
        } else {
            None
        };

        let username = Username::new(&account_name, domain_name.as_deref())?;

        // Only password credentials can be converted to AuthIdentity
        let password = match &credentials_buffers.credential {
            CredentialType::Password(pwd) => utils::bytes_to_utf16_string(pwd.as_ref())
                .map_err(|_| UsernameError::InvalidUtf16)?
                .into(),
            CredentialType::NtlmHash(_) => {
                // Can't convert hash back to password
                return Err(UsernameError::InvalidUtf16);
            }
        };

        Ok(Self { username, password })
    }
}

impl TryFrom<AuthIdentityBuffers> for AuthIdentity {
    type Error = UsernameError;

    fn try_from(credentials_buffers: AuthIdentityBuffers) -> Result<Self, Self::Error> {
        AuthIdentity::try_from(&credentials_buffers)
    }
}

#[cfg(feature = "scard")]
mod scard_credentials {
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::PathBuf;

    use picky::key::PrivateKey;
    use picky_asn1_x509::Certificate;

    use crate::secret::SecretPrivateKey;
    use crate::{utils, Error, ErrorKind, Secret};

    /// Smart card type.
    #[derive(Clone, Eq, PartialEq, Debug)]
    pub enum SmartCardType {
        /// Emulated smart card.
        ///
        /// No real device is used. All smart card functionality is emulated using the [winscard] crate.
        Emulated {
            /// Emulated smart card PIN code.
            ///
            /// This is smart card PIN code, not the PIN code provided by the user.
            scard_pin: Secret<Vec<u8>>,
        },
        #[cfg(not(target_arch = "wasm32"))]
        /// System-provided smart card.
        ///
        /// Real smart card device in use.
        SystemProvided {
            /// Path to the PKCS11 module.
            pkcs11_module_path: PathBuf,
        },
        /// System-provided smart card, but the Windows native API will be used for accessing smart card.
        ///
        /// Available only on Windows.
        #[cfg(target_os = "windows")]
        WindowsNative,
    }

    /// Represents raw data needed for smart card authentication
    #[derive(Clone, Eq, PartialEq, Debug)]
    pub struct SmartCardIdentityBuffers {
        /// UTF-16 encoded username
        pub username: Vec<u8>,
        /// DER-encoded X509 certificate
        pub certificate: Vec<u8>,
        /// UTF-16 encoded smart card name
        pub card_name: Option<Vec<u8>>,
        /// UTF-16 encoded smart card reader name
        pub reader_name: Vec<u8>,
        /// UTF-16 encoded smart card key container name
        pub container_name: Option<Vec<u8>>,
        /// UTF-16 encoded smart card CSP name
        pub csp_name: Vec<u8>,
        /// UTF-16 encoded smart card PIN code
        pub pin: Secret<Vec<u8>>,
        /// UTF-16 string with PEM-encoded RSA 2048-bit private key
        pub private_key_pem: Option<Vec<u8>>,
        /// Smart card type.
        pub scard_type: SmartCardType,
    }

    /// Represents data needed for smart card authentication
    #[derive(Debug, Clone, PartialEq)]
    pub struct SmartCardIdentity {
        /// Username
        pub username: String,
        /// X509 certificate
        pub certificate: Certificate,
        /// Smart card reader name
        pub reader_name: String,
        /// Smart card name
        pub card_name: Option<String>,
        /// Smart card key container name
        pub container_name: Option<String>,
        /// Smart card CSP name
        pub csp_name: String,
        /// ASCII encoded mart card PIN code
        pub pin: Secret<Vec<u8>>,
        /// RSA 2048-bit private key
        pub private_key: Option<SecretPrivateKey>,
        /// Smart card type.
        pub scard_type: SmartCardType,
    }

    impl TryFrom<SmartCardIdentity> for SmartCardIdentityBuffers {
        type Error = Error;

        fn try_from(value: SmartCardIdentity) -> Result<Self, Self::Error> {
            let private_key = if let Some(key) = value.private_key {
                Some(utils::string_to_utf16(key.as_ref().to_pem_str().map_err(|e| {
                    Error::new(
                        ErrorKind::InternalError,
                        format!("Unable to serialize a smart card private key: {}", e),
                    )
                })?))
            } else {
                None
            };

            Ok(Self {
                certificate: picky_asn1_der::to_vec(&value.certificate)?,
                reader_name: utils::string_to_utf16(value.reader_name),
                pin: utils::string_to_utf16(String::from_utf8_lossy(value.pin.as_ref())).into(),
                username: utils::string_to_utf16(value.username),
                card_name: value.card_name.map(utils::string_to_utf16),
                container_name: value.container_name.map(utils::string_to_utf16),
                csp_name: utils::string_to_utf16(value.csp_name),
                private_key_pem: private_key,
                scard_type: value.scard_type,
            })
        }
    }

    impl TryFrom<&SmartCardIdentityBuffers> for SmartCardIdentity {
        type Error = Error;

        fn try_from(value: &SmartCardIdentityBuffers) -> Result<Self, Self::Error> {
            let private_key = if let Some(key) = &value.private_key_pem {
                Some(SecretPrivateKey::new(
                    PrivateKey::from_pem_str(&utils::bytes_to_utf16_string(key)?).map_err(|e| {
                        Error::new(
                            ErrorKind::InternalError,
                            format!("Unable to create a PrivateKey from a PEM string: {}", e),
                        )
                    })?,
                ))
            } else {
                None
            };

            Ok(Self {
                certificate: picky_asn1_der::from_bytes(&value.certificate)?,
                reader_name: utils::bytes_to_utf16_string(&value.reader_name)?,
                pin: utils::bytes_to_utf16_string(value.pin.as_ref())?.into_bytes().into(),
                username: utils::bytes_to_utf16_string(&value.username)?,
                card_name: value
                    .card_name
                    .as_deref()
                    .map(utils::bytes_to_utf16_string)
                    .transpose()?,
                container_name: value
                    .container_name
                    .as_deref()
                    .map(utils::bytes_to_utf16_string)
                    .transpose()?,
                csp_name: utils::bytes_to_utf16_string(&value.csp_name)?,
                private_key,
                scard_type: value.scard_type.clone(),
            })
        }
    }
}

#[cfg(feature = "scard")]
pub use self::scard_credentials::{SmartCardIdentity, SmartCardIdentityBuffers, SmartCardType};

/// Generic enum that encapsulates raw credentials for any type of authentication
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CredentialsBuffers {
    /// Raw auth identity buffers for the password based authentication
    AuthIdentity(AuthIdentityBuffers),
    #[cfg(feature = "scard")]
    /// Raw smart card identity buffers for the smart card based authentication
    SmartCard(SmartCardIdentityBuffers),
}

impl CredentialsBuffers {
    pub fn auth_identity(self) -> Option<AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            #[cfg(feature = "scard")]
            _ => None,
        }
    }

    pub fn as_auth_identity(&self) -> Option<&AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            #[cfg(feature = "scard")]
            _ => None,
        }
    }

    pub fn as_mut_auth_identity(&mut self) -> Option<&mut AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            #[cfg(feature = "scard")]
            _ => None,
        }
    }
}

/// Generic enum that encapsulates credentials for any type of authentication
#[derive(Clone, PartialEq, Debug)]
pub enum Credentials {
    /// Auth identity for the password based authentication
    AuthIdentity(AuthIdentity),
    /// Smart card identity for the smart card based authentication
    #[cfg(feature = "scard")]
    SmartCard(Box<SmartCardIdentity>),
}

impl Credentials {
    pub fn auth_identity(self) -> Option<AuthIdentity> {
        match self {
            Credentials::AuthIdentity(identity) => Some(identity),
            #[cfg(feature = "scard")]
            _ => None,
        }
    }
}

#[cfg(feature = "scard")]
impl From<SmartCardIdentity> for Credentials {
    fn from(value: SmartCardIdentity) -> Self {
        Self::SmartCard(Box::new(value))
    }
}

impl From<AuthIdentity> for Credentials {
    fn from(value: AuthIdentity) -> Self {
        Self::AuthIdentity(value)
    }
}

impl TryFrom<Credentials> for CredentialsBuffers {
    type Error = Error;

    fn try_from(value: Credentials) -> Result<Self, Self::Error> {
        Ok(match value {
            Credentials::AuthIdentity(identity) => Self::AuthIdentity(identity.into()),
            #[cfg(feature = "scard")]
            Credentials::SmartCard(identity) => Self::SmartCard((*identity).try_into()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn username_format_conversion() {
        proptest!(|(value in "[a-zA-Z0-9.]{1,3}@?\\\\?[a-zA-Z0-9.]{1,3}@?\\\\?[a-zA-Z0-9.]{1,3}")| {
            let res = Username::parse(&value);
            prop_assume!(res.is_ok());
            let initial_username = res.unwrap();
            assert_eq!(initial_username.inner(), value);

            if let Some(domain_name) = initial_username.domain_name() {
                let upn = Username::new_upn(initial_username.account_name(), domain_name).expect("UPN");
                assert_eq!(upn.account_name(), initial_username.account_name());
                assert_eq!(upn.domain_name(), initial_username.domain_name());
            }

            // A down-level user name can't contain a @ in the account name
            if !initial_username.account_name().contains('@') {
                let netbios_name = Username::new(initial_username.account_name(), initial_username.domain_name()).expect("NetBIOS");
                assert_eq!(netbios_name.format(), UserNameFormat::DownLevelLogonName);
                assert_eq!(netbios_name.account_name(), initial_username.account_name());
                assert_eq!(netbios_name.domain_name(), initial_username.domain_name());
            }
        })
    }

    fn check_round_trip_property(username: &Username) {
        let round_trip = Username::parse(username.inner()).expect("round-trip parse");
        assert_eq!(*username, round_trip);
    }

    #[test]
    fn upn_round_trip() {
        proptest!(|(account_name in "[a-zA-Z0-9@.]{1,3}", domain_name in "[a-z0-9.]{1,3}")| {
            let username = Username::new_upn(&account_name, &domain_name).expect("UPN");

            assert_eq!(username.account_name(), account_name);
            assert_eq!(username.domain_name(), Some(domain_name.as_str()));
            assert_eq!(username.format(), UserNameFormat::UserPrincipalName);

            check_round_trip_property(&username);
        })
    }

    #[test]
    fn down_level_logon_name_round_trip() {
        proptest!(|(account_name in "[a-zA-Z0-9.]{1,3}", domain_name in "[A-Z0-9.]{1,3}")| {
            let username = Username::new_down_level_logon_name(&account_name, &domain_name).expect("down-level logon name");

            assert_eq!(username.account_name(), account_name);
            assert_eq!(username.domain_name(), Some(domain_name.as_str()));
            assert_eq!(username.format(), UserNameFormat::DownLevelLogonName);

            check_round_trip_property(&username);
        })
    }

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
            0x32, 0xed, 0x87, 0xbd, 0xb5, 0xfd, 0xc5, 0xe9, 0xcb, 0xa8, 0x85, 0x47, 0x37, 0x68, 0x18, 0xd4,
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

        // Invalid length
        let invalid_len: Result<NtlmHash, _> = "32ed87bd".try_into();
        assert!(invalid_len.is_err());

        let empty: Result<NtlmHash, _> = "".try_into();
        assert!(empty.is_err());
    }

    #[test]
    fn test_auth_identity_buffers_with_hash() {
        let hash_str = "32ed87bdb5fdc5e9cba88547376818d4";
        let hash: NtlmHash = hash_str.try_into().unwrap();

        let credentials = AuthIdentityBuffers::from_utf8_with_hash("Administrator", "CONTOSO", *hash.as_bytes());

        assert!(!credentials.user.is_empty());
        assert!(!credentials.domain.is_empty());
        assert!(credentials.ntlm_hash().is_some());
        assert!(credentials.password().is_none());
        assert!(credentials.credential_type().is_ntlm_hash());
        assert!(!credentials.credential_type().is_password());
    }

    #[test]
    fn test_auth_identity_buffers_with_password() {
        let credentials = AuthIdentityBuffers::from_utf8("Administrator", "CONTOSO", "MyPassword123");

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
