#[cfg(feature = "network_client")]
use std::env;
#[cfg(feature = "network_client")]
use std::str::FromStr;

use lazy_static::lazy_static;
#[cfg(feature = "network_client")]
use url::Url;

use super::pku2u::Pku2uConfig;
use crate::internal::SspiImpl;
#[cfg(feature = "network_client")]
use crate::kerberos::config::KdcType;
#[cfg(feature = "network_client")]
use crate::kerberos::network_client::reqwest_network_client::ReqwestNetworkClient;
#[cfg(feature = "network_client")]
use crate::kerberos::SSPI_KDC_URL_ENV;
use crate::sspi::{Result, PACKAGE_ID_NONE};
#[cfg(feature = "network_client")]
use crate::utils::get_domain_from_fqdn;
use crate::utils::is_azure_ad_username;
#[cfg(feature = "network_client")]
use crate::utils::resolve_kdc_host;
use crate::{
    builders, AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers,
    CertTrustStatus, ContextNames, ContextSizes, CredentialUse, DecryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, Kerberos, KerberosConfig, Ntlm, PackageCapabilities, PackageInfo, Pku2u,
    SecurityBuffer, SecurityPackageType, SecurityStatus, Sspi, SspiEx,
};

pub const PKG_NAME: &str = "Negotiate";

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
        name: SecurityPackageType::Negotiate,
        comment: String::from("Microsoft Package Negotiator"),
    };
}

#[derive(Debug, Clone)]
pub struct NegotiateConfig {
    pub krb_config: Option<KerberosConfig>,
    pub pku2u_config: Option<Pku2uConfig>,
}

impl NegotiateConfig {
    pub fn new() -> Self {
        Self {
            krb_config: None,
            pku2u_config: None,
        }
    }

    pub fn new_with_kerberos(krb_config: KerberosConfig) -> Self {
        Self {
            krb_config: Some(krb_config),
            pku2u_config: None,
        }
    }

    pub fn new_with_pku2u(pku2u_config: Pku2uConfig) -> Self {
        Self {
            krb_config: None,
            pku2u_config: Some(pku2u_config),
        }
    }
}

impl Default for NegotiateConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NegotiatedProtocol {
    Pku2u(Pku2u),
    Kerberos(Kerberos),
    Ntlm(Ntlm),
}

#[derive(Debug, Clone)]
pub struct Negotiate {
    protocol: NegotiatedProtocol,
    auth_identity: Option<AuthIdentityBuffers>,
}

impl Negotiate {
    pub fn new(config: NegotiateConfig) -> Result<Self> {
        let protocol = if let Some(krb_config) = config.krb_config {
            Kerberos::new_client_from_config(krb_config)
                .map(NegotiatedProtocol::Kerberos)
                .unwrap_or_else(|_| NegotiatedProtocol::Ntlm(Ntlm::new()))
        } else if let Some(pku2u_config) = config.pku2u_config {
            Pku2u::new_client_from_config(pku2u_config)
                .map(NegotiatedProtocol::Pku2u)
                .unwrap_or_else(|_| NegotiatedProtocol::Ntlm(Ntlm::new()))
        } else {
            #[cfg(feature = "network_client")]
            if env::var(SSPI_KDC_URL_ENV).is_ok() {
                Kerberos::new_client_from_config(KerberosConfig::from_env())
                    .map(NegotiatedProtocol::Kerberos)
                    .unwrap_or_else(|_| NegotiatedProtocol::Ntlm(Ntlm::new()))
            } else {
                NegotiatedProtocol::Ntlm(Ntlm::new())
            }
            #[cfg(not(feature = "network_client"))]
            NegotiatedProtocol::Ntlm(Ntlm::new())
        };

        Ok(Negotiate {
            protocol,
            auth_identity: None,
        })
    }

    fn negotiate_protocol(&mut self, username: &[u8]) -> Result<()> {
        if let NegotiatedProtocol::Ntlm(_) = &self.protocol {
            if is_azure_ad_username(username) {
                self.protocol = NegotiatedProtocol::Pku2u(Pku2u::new_client_from_config(Pku2uConfig::default())?);
                return Ok(());
            }

            #[cfg(feature = "network_client")]
            if let Some(domain) = get_domain_from_fqdn(username) {
                if let Some(host) = resolve_kdc_host(&domain) {
                    self.protocol = NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(KerberosConfig {
                        url: Url::from_str(&host).unwrap(),
                        kdc_type: KdcType::Kdc,
                        network_client: Box::new(ReqwestNetworkClient::new()),
                    })?)
                }
            }
        }

        Ok(())
    }
}

impl SspiEx for Negotiate {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.clone().into());

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.custom_set_auth_identity(identity),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.custom_set_auth_identity(identity),
        }
    }
}

impl Sspi for Negotiate {
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.complete_auth_token(token),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.complete_auth_token(token),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.complete_auth_token(token),
        }
    }

    fn encrypt_message(
        &mut self,
        flags: crate::EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> Result<SecurityStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.encrypt_message(flags, message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.encrypt_message(flags, message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.encrypt_message(flags, message, sequence_number),
        }
    }

    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], sequence_number: u32) -> Result<DecryptionFlags> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.decrypt_message(message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.decrypt_message(message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.decrypt_message(message, sequence_number),
        }
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_sizes(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_sizes(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_sizes(),
        }
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_names(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_names(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_names(),
        }
    }

    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_package_info(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_package_info(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_package_info(),
        }
    }

    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_cert_trust_status(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
        }
    }

    fn change_password(&mut self, change_password: builders::ChangePassword) -> Result<()> {
        self.negotiate_protocol(change_password.account_name.as_bytes())?;

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.change_password(change_password),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.change_password(change_password),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.change_password(change_password),
        }
    }
}

impl SspiImpl for Negotiate {
    type CredentialsHandle = Option<AuthIdentityBuffers>;
    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                String::from("The client must specify the auth data"),
            ));
        }

        if let Some(identity) = builder.auth_data {
            self.negotiate_protocol(identity.username.as_bytes())?;
        }

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.acquire_credentials_handle_impl(builder)?,
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.acquire_credentials_handle_impl(builder)?,
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.acquire_credentials_handle_impl(builder)?,
        };

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut builders::FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        if let Some(Some(identity)) = builder.credentials_handle {
            self.negotiate_protocol(&identity.user)?;
        }

        if let NegotiatedProtocol::Kerberos(kerberos) = &mut self.protocol {
            match kerberos.initialize_security_context_impl(builder) {
                Result::Err(Error {
                    error_type: ErrorKind::NoCredentials,
                    description: _,
                }) => {
                    self.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_auth_identity(self.auth_identity.clone()));
                }
                result => return result,
            };
        }

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.initialize_security_context_impl(builder),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.initialize_security_context_impl(builder),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.initialize_security_context_impl(builder),
        }
    }

    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.accept_security_context_impl(builder),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.accept_security_context_impl(builder),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.accept_security_context_impl(builder),
        }
    }
}
