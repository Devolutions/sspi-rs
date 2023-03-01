use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{utils, Secret};

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
