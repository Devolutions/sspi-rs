use std::fmt;

use picky_krb::crypto::CipherSuite;

use crate::utf16string::ZeroizedUtf16String;
use crate::{Error, Secret, Utf16String, Utf16StringExt};

/// A component of a [`Username`] used in validation errors.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsernameComponent {
    /// The account portion of a user principal name.
    UserPrincipalNameAccount,
    /// The suffix portion of a user principal name.
    UserPrincipalNameSuffix,
    /// The account portion of a down-level logon name.
    DownLevelAccountName,
    /// The NetBIOS domain portion of a down-level logon name.
    NetbiosDomain,
}

impl fmt::Display for UsernameComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserPrincipalNameAccount => f.write_str("user principal name account"),
            Self::UserPrincipalNameSuffix => f.write_str("user principal name suffix"),
            Self::DownLevelAccountName => f.write_str("down-level account name"),
            Self::NetbiosDomain => f.write_str("NetBIOS domain"),
        }
    }
}

/// An error in the structure of a [`Username`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsernameError {
    /// A component contains a delimiter that is not valid in that position.
    ForbiddenDelimiter {
        component: UsernameComponent,
        delimiter: char,
    },
    /// A required component is empty.
    EmptyComponent { component: UsernameComponent },
}

impl std::error::Error for UsernameError {}

impl fmt::Display for UsernameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenDelimiter { component, delimiter } => {
                write!(f, "delimiter {delimiter:?} is forbidden in the {component}")
            }
            Self::EmptyComponent { component } => write!(f, "the {component} is empty"),
        }
    }
}

/// An error converting a tagged [`AuthIdentity`] to raw [`AuthIdentityBuffers`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthIdentityBuffersError {
    /// A raw empty-domain buffer cannot distinguish this name from a user principal name.
    UnrepresentableDomainlessDownLevelLogonName,
}

impl std::error::Error for AuthIdentityBuffersError {}

impl fmt::Display for AuthIdentityBuffersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnrepresentableDomainlessDownLevelLogonName => f.write_str(
                "a domain-less down-level account containing '@' cannot be represented in raw user/domain buffers",
            ),
        }
    }
}

/// An opaque, validated user principal name.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserPrincipalName {
    value: String,
    separator_index: usize,
}

impl UserPrincipalName {
    fn new(account_name: &str, suffix: &str) -> Result<Self, UsernameError> {
        if account_name.is_empty() {
            return Err(UsernameError::EmptyComponent {
                component: UsernameComponent::UserPrincipalNameAccount,
            });
        }
        if account_name.contains('\\') {
            return Err(UsernameError::ForbiddenDelimiter {
                component: UsernameComponent::UserPrincipalNameAccount,
                delimiter: '\\',
            });
        }
        if suffix.is_empty() {
            return Err(UsernameError::EmptyComponent {
                component: UsernameComponent::UserPrincipalNameSuffix,
            });
        }
        for delimiter in ['\\', '@'] {
            if suffix.contains(delimiter) {
                return Err(UsernameError::ForbiddenDelimiter {
                    component: UsernameComponent::UserPrincipalNameSuffix,
                    delimiter,
                });
            }
        }

        Ok(Self {
            value: format!("{account_name}@{suffix}"),
            separator_index: account_name.len(),
        })
    }

    /// Returns the account name before the format-defining `@`.
    pub fn account_name(&self) -> &str {
        &self.value[..self.separator_index]
    }

    /// Returns the UPN suffix after the format-defining `@`.
    pub fn suffix(&self) -> &str {
        &self.value[self.separator_index + 1..]
    }

    /// Returns the complete user principal name.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// An opaque, validated down-level logon name.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DownLevelLogonName {
    value: String,
    separator_index: Option<usize>,
}

impl DownLevelLogonName {
    fn new(account_name: &str, netbios_domain: Option<&str>) -> Result<Self, UsernameError> {
        if let Some(netbios_domain) = netbios_domain {
            if netbios_domain.is_empty() {
                return Err(UsernameError::EmptyComponent {
                    component: UsernameComponent::NetbiosDomain,
                });
            }
            for delimiter in ['\\', '@'] {
                if netbios_domain.contains(delimiter) {
                    return Err(UsernameError::ForbiddenDelimiter {
                        component: UsernameComponent::NetbiosDomain,
                        delimiter,
                    });
                }
            }
        }

        if account_name.is_empty() && netbios_domain.is_some() {
            return Err(UsernameError::EmptyComponent {
                component: UsernameComponent::DownLevelAccountName,
            });
        }
        if account_name.contains('\\') {
            return Err(UsernameError::ForbiddenDelimiter {
                component: UsernameComponent::DownLevelAccountName,
                delimiter: '\\',
            });
        }

        if let Some(netbios_domain) = netbios_domain {
            Ok(Self {
                value: format!("{netbios_domain}\\{account_name}"),
                separator_index: Some(netbios_domain.len()),
            })
        } else {
            Ok(Self {
                value: account_name.to_owned(),
                separator_index: None,
            })
        }
    }

    /// Returns the account name after `\`, or the complete value when unqualified.
    pub fn account_name(&self) -> &str {
        match self.separator_index {
            Some(index) => &self.value[index + 1..],
            None => &self.value,
        }
    }

    /// Returns the NetBIOS domain before `\`, or `None` when unqualified.
    pub fn netbios_domain(&self) -> Option<&str> {
        self.separator_index.map(|index| &self.value[..index])
    }

    /// Returns the complete down-level logon name.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// A validated, explicitly tagged Windows username.
///
/// Equality compares the tagged representation. It does not determine whether two names resolve to
/// the same directory account.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Username {
    /// A user principal name such as `account@example.com`.
    UserPrincipalName(UserPrincipalName),
    /// A down-level logon name such as `DOMAIN\account`, or an unqualified account.
    DownLevelLogonName(DownLevelLogonName),
}

impl Username {
    /// Builds a user principal name from an account name and UPN suffix.
    ///
    /// # Errors
    ///
    /// Returns [`UsernameError::EmptyComponent`] when either component is empty. Returns
    /// [`UsernameError::ForbiddenDelimiter`] when the account contains `\`, or the suffix contains
    /// `\` or `@`. This validates representation consistency, not complete Windows account-name validity.
    pub fn new_upn(account_name: &str, upn_suffix: &str) -> Result<Self, UsernameError> {
        UserPrincipalName::new(account_name, upn_suffix).map(Self::UserPrincipalName)
    }

    /// Builds a down-level logon name from an account name and optional NetBIOS domain.
    ///
    /// The account name may contain `@`, including when `netbios_domain` is `None`. Such a domain-less
    /// name is explicitly tagged but cannot be converted to [`AuthIdentityBuffers`] without losing
    /// that tag.
    ///
    /// An empty account is allowed only with `None`, as the credential-less SSPI sentinel.
    ///
    /// # Errors
    ///
    /// Returns [`UsernameError::EmptyComponent`] for an empty supplied domain or a qualified empty
    /// account. Returns [`UsernameError::ForbiddenDelimiter`] when the account contains `\`, or the
    /// domain contains `\` or `@`. This validates representation consistency, not complete Windows
    /// account-name validity.
    pub fn new_down_level_logon_name(account_name: &str, netbios_domain: Option<&str>) -> Result<Self, UsernameError> {
        DownLevelLogonName::new(account_name, netbios_domain).map(Self::DownLevelLogonName)
    }

    /// Parses a combined username spelling using deterministic separator precedence.
    ///
    /// A `\` establishes down-level syntax and takes precedence over `@`. Otherwise the last `@`
    /// establishes UPN syntax. A value with neither delimiter is an unqualified down-level name.
    /// The empty string is accepted as the credential-less SSPI sentinel.
    ///
    /// # Errors
    ///
    /// Returns [`UsernameError::EmptyComponent`] for delimiter-bearing forms with an empty component,
    /// and [`UsernameError::ForbiddenDelimiter`] for additional delimiters forbidden by the selected
    /// format. This validates representation consistency, not complete Windows account-name validity.
    pub fn parse(value: &str) -> Result<Self, UsernameError> {
        if let Some((netbios_domain, account_name)) = value.split_once('\\') {
            Self::new_down_level_logon_name(account_name, Some(netbios_domain))
        } else if let Some((account_name, upn_suffix)) = value.rsplit_once('@') {
            Self::new_upn(account_name, upn_suffix)
        } else {
            Self::new_down_level_logon_name(value, None)
        }
    }

    /// Returns the complete stored spelling.
    ///
    /// This rendering is not injective: an explicitly domain-less down-level account containing `@`
    /// has the same spelling as a UPN and will parse as a UPN.
    pub fn as_str(&self) -> &str {
        match self {
            Self::UserPrincipalName(upn) => upn.as_str(),
            Self::DownLevelLogonName(down_level) => down_level.as_str(),
        }
    }

    /// Compares two tagged username representations, ignoring ASCII case within each component.
    ///
    /// Different variants compare unequal. This does not determine whether two names resolve to the
    /// same directory account.
    pub fn eq_ignore_ascii_case(&self, other: &Username) -> bool {
        match (self, other) {
            (Self::UserPrincipalName(lhs), Self::UserPrincipalName(rhs)) => {
                lhs.account_name().eq_ignore_ascii_case(rhs.account_name())
                    && lhs.suffix().eq_ignore_ascii_case(rhs.suffix())
            }
            (Self::DownLevelLogonName(lhs), Self::DownLevelLogonName(rhs)) => {
                lhs.account_name().eq_ignore_ascii_case(rhs.account_name())
                    && match (lhs.netbios_domain(), rhs.netbios_domain()) {
                        (Some(lhs_domain), Some(rhs_domain)) => lhs_domain.eq_ignore_ascii_case(rhs_domain),
                        (None, None) => true,
                        _ => false,
                    }
            }
            _ => false,
        }
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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

/// Client credentials backed by a pre-derived Kerberos long-term key.
///
/// Unlike [`AuthIdentity`], no password is supplied: the raw long-term key
/// (as stored in a keytab) is used directly to encrypt the PA-ENC-TIMESTAMP
/// pre-authentication value and to decrypt the AS-REP, skipping the
/// string-to-key derivation. This is the credential a service uses when it
/// acts as a Kerberos *client* (e.g. inter-service authentication) without a
/// human password.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeytabIdentity {
    /// Client principal, e.g. `"svc@REALM"` or `"svc/host@REALM"`.
    pub principal: Username,
    /// Raw long-term key bytes for `key_enctype`.
    pub key: Secret<Vec<u8>>,
    /// Kerberos encryption type of `key` (e.g. aes256-cts-hmac-sha1-96).
    pub key_enctype: CipherSuite,
}

/// Auth identity buffers for password-based logon.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct AuthIdentityBuffers {
    /// Username.
    ///
    /// Must be UTF-16 encoded.
    pub user: Utf16String,
    /// Domain.
    ///
    /// Must be UTF-16 encoded.
    pub domain: Utf16String,
    /// Password.
    ///
    /// Must be UTF-16 encoded.
    ///
    /// If the password is an NT hash, it should be prefixed with [`NTLM_HASH_PREFIX`](crate::NTLM_HASH_PREFIX) followed by the hash in hexadecimal format.
    ///
    /// See [`NtlmHash`](crate::NtlmHash) for more details.
    pub password: Secret<ZeroizedUtf16String>,
}

impl AuthIdentityBuffers {
    /// Creates a new [AuthIdentityBuffers] object based on provided credentials.
    ///
    /// Provided credentials must be UTF-16 encoded.
    pub fn new(user: Utf16String, domain: Utf16String, password: Utf16String) -> Self {
        Self {
            user,
            domain,
            password: ZeroizedUtf16String(password).into(),
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
            user: user.into(),
            domain: domain.into(),
            password: ZeroizedUtf16String(Utf16String::from(password)).into(),
        }
    }

    /// Creates a new [AuthIdentityBuffers] object based on UTF-8 username and domain, and NT hash for the password.
    pub fn from_utf8_with_hash(user: &str, domain: &str, nt_hash: &crate::NtlmHash) -> Self {
        Self {
            user: user.into(),
            domain: domain.into(),
            password: ZeroizedUtf16String(Utf16String::from(nt_hash.to_sspi_password())).into(),
        }
    }
}

impl fmt::Debug for AuthIdentityBuffers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthIdentityBuffers {{ user: 0x")?;
        self.user
            .as_bytes_le()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", domain: 0x")?;
        self.domain
            .as_bytes_le()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", password: {:?} }}", self.password)?;

        Ok(())
    }
}

impl TryFrom<&AuthIdentity> for AuthIdentityBuffers {
    type Error = AuthIdentityBuffersError;

    fn try_from(credentials: &AuthIdentity) -> Result<Self, Self::Error> {
        let password: &str = credentials.password.as_ref().as_ref();
        let (user, domain) = match &credentials.username {
            Username::UserPrincipalName(upn) => (upn.as_str(), ""),
            Username::DownLevelLogonName(down_level) => {
                let domain = down_level.netbios_domain().unwrap_or_default();
                if domain.is_empty() && down_level.account_name().contains('@') {
                    return Err(AuthIdentityBuffersError::UnrepresentableDomainlessDownLevelLogonName);
                }
                (down_level.account_name(), domain)
            }
        };

        Ok(Self {
            user: user.into(),
            domain: domain.into(),
            password: ZeroizedUtf16String(password.into()).into(),
        })
    }
}

impl TryFrom<AuthIdentity> for AuthIdentityBuffers {
    type Error = AuthIdentityBuffersError;

    fn try_from(credentials: AuthIdentity) -> Result<Self, Self::Error> {
        Self::try_from(&credentials)
    }
}

impl TryFrom<&AuthIdentityBuffers> for AuthIdentity {
    type Error = UsernameError;

    fn try_from(credentials_buffers: &AuthIdentityBuffers) -> Result<Self, Self::Error> {
        let account_name = credentials_buffers.user.to_string();

        let username = if credentials_buffers.domain.is_empty() {
            Username::parse(&account_name)?
        } else {
            let domain_name = credentials_buffers.domain.to_string();
            Username::new_down_level_logon_name(&account_name, Some(&domain_name))?
        };
        let password = credentials_buffers.password.as_ref().as_ref().to_string().into();

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
    use picky_asn1_der::Asn1DerError;
    use picky_asn1_x509::Certificate;

    use crate::secret::SecretPrivateKey;
    use crate::utf16string::ZeroizedUtf16String;
    use crate::{Error, ErrorKind, NonEmpty, Secret, Utf16String};

    /// DER-encoded x509 certificate.
    #[derive(Clone, Eq, PartialEq, Debug)]
    pub struct CertificateRaw(Vec<u8>);

    impl AsRef<[u8]> for CertificateRaw {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl TryFrom<Vec<u8>> for CertificateRaw {
        type Error = Asn1DerError;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            let _: Certificate = picky_asn1_der::from_bytes(value.as_ref())?;
            Ok(Self(value))
        }
    }

    impl From<CertificateRaw> for Vec<u8> {
        fn from(value: CertificateRaw) -> Self {
            value.0
        }
    }

    impl TryFrom<&Certificate> for CertificateRaw {
        type Error = Asn1DerError;

        fn try_from(value: &Certificate) -> Result<Self, Self::Error> {
            picky_asn1_der::to_vec(value).map(Self)
        }
    }

    impl TryFrom<Certificate> for CertificateRaw {
        type Error = Asn1DerError;

        fn try_from(value: Certificate) -> Result<Self, Self::Error> {
            Self::try_from(&value)
        }
    }

    impl From<&CertificateRaw> for Certificate {
        fn from(value: &CertificateRaw) -> Self {
            picky_asn1_der::from_bytes(&value.0).expect("value.0 is convertible to Certificate (checked on creation)")
        }
    }

    impl From<CertificateRaw> for Certificate {
        fn from(value: CertificateRaw) -> Self {
            Self::from(&value)
        }
    }

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
        pub username: Utf16String,
        /// DER-encoded X509 certificate
        pub certificate: CertificateRaw,
        /// UTF-16 encoded smart card name
        pub card_name: Option<NonEmpty<Utf16String>>,
        /// UTF-16 encoded smart card reader name
        pub reader_name: Utf16String,
        /// UTF-16 encoded smart card key container name
        pub container_name: Option<NonEmpty<Utf16String>>,
        /// UTF-16 encoded smart card CSP name
        pub csp_name: Utf16String,
        /// UTF-16 encoded smart card PIN code
        pub pin: Secret<ZeroizedUtf16String>,
        /// UTF-16 string with PEM-encoded RSA 2048-bit private key
        pub private_key_pem: Option<NonEmpty<Utf16String>>,
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
                NonEmpty::new(Utf16String::from(key.as_ref().to_pem_str().map_err(|e| {
                    Error::new(
                        ErrorKind::InternalError,
                        format!("Unable to serialize a smart card private key: {e}"),
                    )
                })?))
            } else {
                None
            };

            Ok(Self {
                certificate: value.certificate.try_into()?,
                reader_name: value.reader_name.into(),
                pin: ZeroizedUtf16String(String::from_utf8_lossy(value.pin.as_ref()).as_ref().into()).into(),
                username: value.username.into(),
                card_name: value.card_name.and_then(|value| NonEmpty::new(value.into())),
                container_name: value.container_name.and_then(|value| NonEmpty::new(value.into())),
                csp_name: value.csp_name.into(),
                private_key_pem: private_key,
                scard_type: value.scard_type,
            })
        }
    }

    impl TryFrom<&SmartCardIdentityBuffers> for SmartCardIdentity {
        type Error = Error;

        fn try_from(value: &SmartCardIdentityBuffers) -> Result<Self, Self::Error> {
            let private_key = if let Some(key) = &value.private_key_pem {
                let pem_string = key.as_ref().to_string();

                Some(SecretPrivateKey::new(PrivateKey::from_pem_str(&pem_string).map_err(
                    |e| {
                        Error::new(
                            ErrorKind::InternalError,
                            format!("Unable to create a PrivateKey from a PEM string: {e}"),
                        )
                    },
                )?))
            } else {
                None
            };

            Ok(Self {
                certificate: Certificate::from(&value.certificate),
                reader_name: value.reader_name.to_string(),
                pin: value.pin.as_ref().0.to_string().into_bytes().into(),
                username: value.username.to_string(),
                card_name: value.card_name.as_ref().map(NonEmpty::as_ref).map(ToString::to_string),
                container_name: value
                    .container_name
                    .as_ref()
                    .map(NonEmpty::as_ref)
                    .map(ToString::to_string),
                csp_name: value.csp_name.to_string(),
                private_key,
                scard_type: value.scard_type.clone(),
            })
        }
    }
}

#[cfg(feature = "scard")]
pub use self::scard_credentials::{CertificateRaw, SmartCardIdentity, SmartCardIdentityBuffers, SmartCardType};

/// Generic enum that encapsulates raw credentials for any type of authentication
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CredentialsBuffers {
    /// Raw auth identity buffers for the password based authentication
    AuthIdentity(AuthIdentityBuffers),
    #[cfg(feature = "scard")]
    /// Raw smart card identity buffers for the smart card based authentication
    SmartCard(SmartCardIdentityBuffers),
    /// Pre-derived Kerberos long-term key for keytab-based client authentication
    Keytab(KeytabIdentity),
}

impl CredentialsBuffers {
    pub fn into_auth_identity(self) -> Option<AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            _ => None,
        }
    }

    pub fn to_auth_identity(&self) -> Option<AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity.clone()),
            _ => None,
        }
    }

    pub fn as_auth_identity(&self) -> Option<&AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
            _ => None,
        }
    }

    pub fn as_mut_auth_identity(&mut self) -> Option<&mut AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
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
    /// Pre-derived Kerberos long-term key for keytab-based client authentication
    Keytab(KeytabIdentity),
}

impl Credentials {
    pub fn to_auth_identity(&self) -> Option<AuthIdentity> {
        match self {
            Credentials::AuthIdentity(identity) => Some(identity.clone()),
            _ => None,
        }
    }

    pub fn auth_identity(self) -> Option<AuthIdentity> {
        match self {
            Credentials::AuthIdentity(identity) => Some(identity),
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

impl From<KeytabIdentity> for Credentials {
    fn from(value: KeytabIdentity) -> Self {
        Self::Keytab(value)
    }
}

impl TryFrom<Credentials> for CredentialsBuffers {
    type Error = Error;

    fn try_from(value: Credentials) -> Result<Self, Self::Error> {
        Ok(match value {
            Credentials::AuthIdentity(identity) => Self::AuthIdentity(identity.try_into()?),
            #[cfg(feature = "scard")]
            Credentials::SmartCard(identity) => Self::SmartCard((*identity).try_into()?),
            Credentials::Keytab(identity) => Self::Keytab(identity),
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::ErrorKind;

    #[test]
    fn explicit_upn_has_owned_tagged_components() {
        proptest!(|(account_name in "[a-zA-Z0-9@.]{1,3}", domain_name in "[a-z0-9.]{1,3}")| {
            let username = Username::new_upn(&account_name, &domain_name).expect("UPN");
            let Username::UserPrincipalName(upn) = &username else {
                panic!("explicit UPN constructor returned a down-level name");
            };
            assert_eq!(upn.account_name(), account_name);
            assert_eq!(upn.suffix(), domain_name);
            assert_eq!(upn.as_str(), format!("{account_name}@{domain_name}"));
            assert_eq!(Username::parse(username.as_str()).unwrap(), username);
        })
    }

    #[test]
    fn explicit_qualified_down_level_name_has_owned_tagged_components() {
        proptest!(|(account_name in "[a-zA-Z0-9@.]{1,3}", domain_name in "[A-Z0-9.]{1,3}")| {
            let username =
                Username::new_down_level_logon_name(&account_name, Some(&domain_name)).expect("down-level name");
            let Username::DownLevelLogonName(down_level) = &username else {
                panic!("explicit down-level constructor returned a UPN");
            };
            assert_eq!(down_level.account_name(), account_name);
            assert_eq!(down_level.netbios_domain(), Some(domain_name.as_str()));
            assert_eq!(down_level.as_str(), format!("{domain_name}\\{account_name}"));
            assert_eq!(Username::parse(username.as_str()).unwrap(), username);
        })
    }

    #[test]
    fn bare_name_parses_as_unqualified_down_level_name() {
        proptest!(|(account_name in "[a-zA-Z0-9.]{1,3}")| {
            let username = Username::parse(&account_name).expect("parse");
            let Username::DownLevelLogonName(down_level) = &username else {
                panic!("bare name parsed as a UPN");
            };
            assert_eq!(down_level.account_name(), account_name);
            assert_eq!(down_level.netbios_domain(), None);
            assert_eq!(Username::parse(username.as_str()).unwrap(), username);
        })
    }

    #[test]
    fn parser_uses_backslash_precedence_and_last_at() {
        let qualified = Username::parse("MicrosoftAccount\\me@example.com").unwrap();
        let Username::DownLevelLogonName(down_level) = qualified else {
            panic!("qualified Microsoft account parsed as UPN");
        };
        assert_eq!(down_level.account_name(), "me@example.com");
        assert_eq!(down_level.netbios_domain(), Some("MicrosoftAccount"));

        let upn = Username::parse("account@department@example.com").unwrap();
        let Username::UserPrincipalName(upn) = upn else {
            panic!("UPN parsed as down-level name");
        };
        assert_eq!(upn.account_name(), "account@department");
        assert_eq!(upn.suffix(), "example.com");
    }

    #[test]
    fn empty_component_semantics_are_explicit() {
        let empty = Username::parse("").unwrap();
        assert!(matches!(
            &empty,
            Username::DownLevelLogonName(down_level)
                if down_level.account_name().is_empty() && down_level.netbios_domain().is_none()
        ));
        assert_eq!(Username::new_down_level_logon_name("", None).unwrap(), empty);

        for (value, component) in [
            ("@suffix", UsernameComponent::UserPrincipalNameAccount),
            ("user@", UsernameComponent::UserPrincipalNameSuffix),
            ("@", UsernameComponent::UserPrincipalNameAccount),
            ("\\user", UsernameComponent::NetbiosDomain),
            ("\\", UsernameComponent::NetbiosDomain),
            ("DOMAIN\\", UsernameComponent::DownLevelAccountName),
        ] {
            assert_eq!(
                Username::parse(value),
                Err(UsernameError::EmptyComponent { component }),
                "{value:?}"
            );
        }

        assert_eq!(
            Username::new_down_level_logon_name("user", Some("")),
            Err(UsernameError::EmptyComponent {
                component: UsernameComponent::NetbiosDomain,
            })
        );
        assert_eq!(
            Username::new_down_level_logon_name("", Some("DOMAIN")),
            Err(UsernameError::EmptyComponent {
                component: UsernameComponent::DownLevelAccountName,
            })
        );
    }

    #[test]
    fn forbidden_delimiters_identify_the_component() {
        assert_eq!(
            Username::new_upn("DOMAIN\\user", "example.com"),
            Err(UsernameError::ForbiddenDelimiter {
                component: UsernameComponent::UserPrincipalNameAccount,
                delimiter: '\\',
            })
        );
        assert_eq!(
            Username::new_upn("user", "example@com"),
            Err(UsernameError::ForbiddenDelimiter {
                component: UsernameComponent::UserPrincipalNameSuffix,
                delimiter: '@',
            })
        );
        assert_eq!(
            Username::new_down_level_logon_name("DOMAIN\\user", None),
            Err(UsernameError::ForbiddenDelimiter {
                component: UsernameComponent::DownLevelAccountName,
                delimiter: '\\',
            })
        );
        assert_eq!(
            Username::new_down_level_logon_name("user", Some("DOMAIN@UPN")),
            Err(UsernameError::ForbiddenDelimiter {
                component: UsernameComponent::NetbiosDomain,
                delimiter: '@',
            })
        );
    }

    #[test]
    fn ascii_case_comparison_is_structural() {
        let upn = Username::new_upn("Alice", "Example.COM").expect("upn");
        let upn_other_case = Username::new_upn("alice", "example.com").expect("upn");
        assert!(upn.eq_ignore_ascii_case(&upn_other_case));

        let dlln = Username::new_down_level_logon_name("Bob", Some("EXAMPLE")).expect("dlln");
        let dlln_other_case = Username::new_down_level_logon_name("bob", Some("example")).expect("dlln");
        assert!(dlln.eq_ignore_ascii_case(&dlln_other_case));

        let same_rendering_dlln = Username::new_down_level_logon_name("Alice@Example.COM", None).unwrap();
        assert_eq!(same_rendering_dlln.as_str(), upn.as_str());
        assert_ne!(same_rendering_dlln, upn);
        assert!(!same_rendering_dlln.eq_ignore_ascii_case(&upn));
    }

    #[test]
    fn representable_auth_identity_buffers_round_trip_structurally() {
        for username in [
            Username::new_upn("alice", "example.com").expect("upn"),
            Username::new_upn("bob@dept", "example.com").expect("upn with @ in account name"),
            Username::new_down_level_logon_name("carol@example.com", Some("MicrosoftAccount")).expect("dlln"),
            Username::new_down_level_logon_name("erin", None).expect("dlln without domain"),
            Username::parse("dave").expect("bare name"),
            Username::parse("").expect("empty sentinel"),
        ] {
            let identity = AuthIdentity {
                username: username.clone(),
                password: String::new().into(),
            };
            let buffers = AuthIdentityBuffers::try_from(&identity).expect("forward conversion");
            let round_trip = AuthIdentity::try_from(&buffers).expect("round-trip");
            assert_eq!(round_trip.username, username);
        }
    }

    #[test]
    fn domainless_down_level_at_is_explicit_but_not_buffer_representable() {
        let username = Username::new_down_level_logon_name("me@example.com", None).unwrap();
        assert_eq!(username.as_str(), "me@example.com");
        assert!(matches!(
            username,
            Username::DownLevelLogonName(ref down_level)
                if down_level.account_name() == "me@example.com" && down_level.netbios_domain().is_none()
        ));
        assert!(matches!(
            Username::parse(username.as_str()).unwrap(),
            Username::UserPrincipalName(_)
        ));

        let identity = AuthIdentity {
            username,
            password: String::new().into(),
        };
        assert_eq!(
            AuthIdentityBuffers::try_from(&identity),
            Err(AuthIdentityBuffersError::UnrepresentableDomainlessDownLevelLogonName)
        );
        assert_eq!(
            AuthIdentityBuffers::try_from(identity),
            Err(AuthIdentityBuffersError::UnrepresentableDomainlessDownLevelLogonName)
        );
    }

    #[test]
    fn raw_buffers_use_deterministic_username_interpretation() {
        let raw_upn = AuthIdentityBuffers::from_utf8("me@example.com", "", "");
        assert!(matches!(
            AuthIdentity::try_from(&raw_upn).unwrap().username,
            Username::UserPrincipalName(_)
        ));

        let raw_dlln = AuthIdentityBuffers::from_utf8("me@example.com", "MicrosoftAccount", "");
        assert!(matches!(
            AuthIdentity::try_from(&raw_dlln).unwrap().username,
            Username::DownLevelLogonName(ref down_level)
                if down_level.account_name() == "me@example.com"
                    && down_level.netbios_domain() == Some("MicrosoftAccount")
        ));

        let empty = AuthIdentity::try_from(&AuthIdentityBuffers::default()).unwrap();
        assert!(matches!(
            empty.username,
            Username::DownLevelLogonName(ref down_level)
                if down_level.account_name().is_empty() && down_level.netbios_domain().is_none()
        ));

        let malformed = AuthIdentityBuffers::from_utf8("", "DOMAIN", "");
        assert_eq!(
            AuthIdentity::try_from(&malformed),
            Err(UsernameError::EmptyComponent {
                component: UsernameComponent::DownLevelAccountName,
            })
        );
    }

    #[test]
    fn username_boundary_errors_map_to_invalid_parameter() {
        let syntax_error: Error = UsernameError::EmptyComponent {
            component: UsernameComponent::UserPrincipalNameSuffix,
        }
        .into();
        assert_eq!(syntax_error.error_type, ErrorKind::InvalidParameter);

        let buffer_error: Error = AuthIdentityBuffersError::UnrepresentableDomainlessDownLevelLogonName.into();
        assert_eq!(buffer_error.error_type, ErrorKind::InvalidParameter);
    }
}
