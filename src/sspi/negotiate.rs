use std::env;
use std::str::FromStr;

use lazy_static::lazy_static;
use url::Url;

use crate::internal::SspiImpl;
use crate::kerberos::config::KdcType;
#[cfg(feature = "network_client")]
use crate::kerberos::network_client::reqwest_network_client::ReqwestNetworkClient;
use crate::kerberos::SSPI_KDC_URL_ENV;
use crate::sspi::{Result, PACKAGE_ID_NONE};
use crate::utils::get_domain_from_fqdm;
use crate::{
    builders, AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers,
    CertTrustStatus, ContextNames, ContextSizes, CredentialUse, DecryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, Kerberos, KerberosConfig, Ntlm, PackageCapabilities, PackageInfo, SecurityBuffer,
    SecurityPackageType, SecurityStatus, Sspi, SspiEx,
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
}

impl NegotiateConfig {
    pub fn new(krb_config: Option<KerberosConfig>) -> Self {
        Self { krb_config }
    }
}

#[derive(Debug, Clone)]
pub enum NegotiatedProtocol {
    Kerberos(Kerberos),
    Ntlm(Ntlm),
}

#[derive(Debug, Clone)]
pub struct Negotiate {
    // config: NegotiateConfig,
    protocol: NegotiatedProtocol,
    auth_identity: Option<AuthIdentityBuffers>,
}

impl Negotiate {
    pub fn new(config: NegotiateConfig) -> Result<Self> {
        let protocol = if let Some(krb_config) = config.krb_config {
            Kerberos::new_client_from_config(krb_config)
                .map(|kerberos| NegotiatedProtocol::Kerberos(kerberos))
                .unwrap_or_else(|_| NegotiatedProtocol::Ntlm(Ntlm::new()))
        } else {
            #[cfg(feature = "network_client")]
            if env::var(SSPI_KDC_URL_ENV).is_ok() {
                Kerberos::new_client_from_config(KerberosConfig::from_env())
                    .map(|kerberos| NegotiatedProtocol::Kerberos(kerberos))
                    .unwrap_or_else(|_| NegotiatedProtocol::Ntlm(Ntlm::new()))
            } else {
                NegotiatedProtocol::Ntlm(Ntlm::new())
            }
            #[cfg(not(feature = "network_client"))]
            NegotiatedProtocol::Ntlm(Ntlm::new())
        };

        Ok(Negotiate {
            // config,
            protocol,
            auth_identity: None,
        })
    }
}

impl SspiEx for Negotiate {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.into());
    }
}

impl Sspi for Negotiate {
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        match &mut self.protocol {
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
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.encrypt_message(flags, message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.encrypt_message(flags, message, sequence_number),
        }
    }

    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], sequence_number: u32) -> Result<DecryptionFlags> {
        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.decrypt_message(message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.decrypt_message(message, sequence_number),
        }
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_sizes(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_sizes(),
        }
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_names(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_names(),
        }
    }

    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_package_info(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_package_info(),
        }
    }

    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
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

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        #[cfg(feature = "network_client")]
        if let Some(identity) = &self.auth_identity {
            if let NegotiatedProtocol::Ntlm(_) = self.protocol {
                if let Some(domain) = get_domain_from_fqdm(&identity.user) {
                    self.protocol = NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(KerberosConfig {
                        url: Url::from_str(format!("tcp://{}:88", domain).as_str()).unwrap(),
                        kdc_type: KdcType::Kdc,
                        network_client: Box::new(ReqwestNetworkClient::new()),
                    })?)
                }
            }
        }

        match &mut self.protocol {
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
        #[cfg(feature = "network_client")]
        if let NegotiatedProtocol::Ntlm(_) = self.protocol {
            if let Some(Some(auth_data)) = builder.credentials_handle.as_ref() {
                if let Some(domain) = get_domain_from_fqdm(&auth_data.user) {
                    self.protocol = NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(KerberosConfig {
                        url: Url::from_str(format!("tcp://{}:88", domain).as_str()).unwrap(),
                        kdc_type: KdcType::Kdc,
                        network_client: Box::new(ReqwestNetworkClient::new()),
                    })?)
                }
            }
        }

        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => {
                let result = kerberos.initialize_security_context_impl(builder);
                match result {
                    Result::Err(Error {
                        error_type: ErrorKind::NoCredentials,
                        description: _,
                    }) => {
                        self.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_auth_identity(self.auth_identity.clone()));
                    }
                    _ => return result,
                };
            }
            _ => {}
        };

        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.initialize_security_context_impl(builder),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.initialize_security_context_impl(builder),
        }
    }

    fn accept_security_context_impl(
        &mut self,
        _builder: builders::FilledAcceptSecurityContext<'_, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        Err(Error {
            error_type: ErrorKind::UnsupportedFunction,
            description: "Negotiate module is not supported for server".into(),
        })
    }
}
