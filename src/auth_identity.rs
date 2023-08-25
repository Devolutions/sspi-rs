use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{utils, Error, Secret};

/// Allows you to pass a particular user name and password to the run-time library for the purpose of authentication
///
/// # MSDN
///
/// * [SEC_WINNT_AUTH_IDENTITY_W structure](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_w)
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct AuthIdentity {
    pub username: String,
    pub password: Secret<String>,
    pub domain: Option<String>,
}

#[derive(Clone, Eq, PartialEq, Default)]
pub struct AuthIdentityBuffers {
    pub user: Vec<u8>,
    pub domain: Vec<u8>,
    pub password: Secret<Vec<u8>>,
}

impl AuthIdentityBuffers {
    pub fn new(user: Vec<u8>, domain: Vec<u8>, password: Vec<u8>) -> Self {
        Self {
            user,
            domain,
            password: password.into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.user.is_empty()
    }
}

impl fmt::Debug for AuthIdentityBuffers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthIdentityBuffers {{ user: 0x")?;
        self.user.iter().try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", domain: 0x")?;
        self.domain.iter().try_for_each(|byte| write!(f, "{byte:02X}"))?;
        write!(f, ", password: {:?} }}", self.password)?;

        Ok(())
    }
}

impl From<AuthIdentity> for AuthIdentityBuffers {
    fn from(credentials: AuthIdentity) -> Self {
        Self {
            user: utils::string_to_utf16(credentials.username.as_str()),
            domain: credentials
                .domain
                .map(|v| utils::string_to_utf16(v.as_str()))
                .unwrap_or_default(),
            password: utils::string_to_utf16(credentials.password.as_ref()).into(),
        }
    }
}

impl From<AuthIdentityBuffers> for AuthIdentity {
    fn from(credentials_buffers: AuthIdentityBuffers) -> Self {
        Self {
            username: utils::bytes_to_utf16_string(credentials_buffers.user.as_ref()),
            password: utils::bytes_to_utf16_string(credentials_buffers.password.as_ref()).into(),
            domain: if credentials_buffers.domain.is_empty() {
                None
            } else {
                Some(utils::bytes_to_utf16_string(credentials_buffers.domain.as_ref()))
            },
        }
    }
}

#[cfg(feature = "scard")]
mod scard_credentials {
    use picky_asn1_x509::Certificate;

    use crate::{utils, Error, Secret};

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
        pub container_name: Vec<u8>,
        /// UTF-16 encoded smart card CSP name
        pub csp_name: Vec<u8>,
        /// UTF-16 encoded smart card PIN code
        pub pin: Secret<Vec<u8>>,
        /// Private key file index
        /// This value is used for the APDU message generation
        pub private_key_file_index: Option<u8>,
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
        pub container_name: String,
        /// Smart card CSP name
        pub csp_name: String,
        /// ASCII encoded mart card PIN code
        pub pin: Secret<Vec<u8>>,
        /// Private key file index
        /// This value is used for the APDU message generation
        pub private_key_file_index: Option<u8>,
    }

    impl TryFrom<SmartCardIdentity> for SmartCardIdentityBuffers {
        type Error = Error;

        fn try_from(value: SmartCardIdentity) -> Result<Self, Self::Error> {
            Ok(Self {
                certificate: picky_asn1_der::to_vec(&value.certificate)?,
                reader_name: utils::string_to_utf16(value.reader_name),
                pin: value.pin.as_ref().clone().into(),
                username: utils::string_to_utf16(value.username),
                card_name: value.card_name.map(utils::string_to_utf16),
                container_name: utils::string_to_utf16(value.container_name),
                csp_name: utils::string_to_utf16(value.csp_name),
                private_key_file_index: value.private_key_file_index,
            })
        }
    }

    impl TryFrom<SmartCardIdentityBuffers> for SmartCardIdentity {
        type Error = Error;

        fn try_from(value: SmartCardIdentityBuffers) -> Result<Self, Self::Error> {
            Ok(Self {
                certificate: picky_asn1_der::from_bytes(&value.certificate)?,
                reader_name: utils::bytes_to_utf16_string(&value.reader_name),
                pin: utils::bytes_to_utf16_string(value.pin.as_ref()).into_bytes().into(),
                username: utils::bytes_to_utf16_string(&value.username),
                card_name: value.card_name.map(|name| utils::bytes_to_utf16_string(&name)),
                container_name: utils::bytes_to_utf16_string(&value.container_name),
                csp_name: utils::bytes_to_utf16_string(&value.csp_name),
                private_key_file_index: value.private_key_file_index,
            })
        }
    }
}

#[cfg(feature = "scard")]
pub use self::scard_credentials::{SmartCardIdentity, SmartCardIdentityBuffers};

/// Generic enum that encapsulates raw credentials for any type of authentication
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CredentialsBuffers {
    /// Raw auth identity buffers for the password based authentication
    AuthIdentity(AuthIdentityBuffers),
    #[cfg(feature = "scard")]
    /// Raw smart card identity buffers for the smart card based authentication
    SmartCard(SmartCardIdentityBuffers),
}

#[allow(unreachable_patterns)]
impl CredentialsBuffers {
    pub fn auth_identity(self) -> Option<AuthIdentityBuffers> {
        match self {
            CredentialsBuffers::AuthIdentity(identity) => Some(identity),
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
    #[cfg(feature = "scard")]
    /// Smart card identity for the smart card based authentication
    SmartCard(Box<SmartCardIdentity>),
}

impl Credentials {
    #[allow(unreachable_patterns)]
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
