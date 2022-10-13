use lazy_static::lazy_static;

use crate::internal::SspiImpl;
use crate::kdc::detect_kdc_url;
use crate::kerberos::client::generators::get_client_principal_realm;
#[cfg(feature = "network_client")]
use crate::kerberos::network_client::reqwest_network_client::ReqwestNetworkClient;
use crate::sspi::{Result, PACKAGE_ID_NONE};
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
    pub package_list: Option<String>,
    pub krb_config: Option<KerberosConfig>,
}

impl NegotiateConfig {
    pub fn new() -> Self {
        Self {
            package_list: None,
            krb_config: None,
        }
    }

    pub fn new_with_kerberos(krb_config: KerberosConfig) -> Self {
        Self {
            package_list: None,
            krb_config: Some(krb_config),
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
    Kerberos(Kerberos),
    Ntlm(Ntlm),
}

#[derive(Debug, Clone)]
pub struct Negotiate {
    protocol: NegotiatedProtocol,
    package_list: Option<String>,
    auth_identity: Option<AuthIdentityBuffers>,
}

impl Negotiate {
    pub fn new(config: NegotiateConfig) -> Result<Self> {
        let mut protocol = if let Some(krb_config) = config.krb_config {
            Kerberos::new_client_from_config(krb_config)
                .map(NegotiatedProtocol::Kerberos)
                .unwrap_or_else(|_| NegotiatedProtocol::Ntlm(Ntlm::new()))
        } else {
            NegotiatedProtocol::Ntlm(Ntlm::new())
        };

        if let Some(filtered_protocol) = Self::filter_protocol(&protocol, &config.package_list) {
            protocol = filtered_protocol;
        }

        Ok(Negotiate {
            protocol: protocol,
            package_list: config.package_list.clone(),
            auth_identity: None,
        })
    }

    #[cfg(feature = "network_client")]
    fn negotiate_protocol(&mut self, username: &str, domain: &str) -> Result<()> {
        if let NegotiatedProtocol::Ntlm(_) = &self.protocol {
            let realm = get_client_principal_realm(username, domain);
            if let Some(kdc_url) = detect_kdc_url(&realm) {
                self.protocol = NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(KerberosConfig {
                    url: Some(kdc_url),
                    network_client: Box::new(ReqwestNetworkClient::new()),
                })?)
            }
        }

        if let Some(filtered_protocol) = Self::filter_protocol(&self.protocol, &self.package_list) {
            self.protocol = filtered_protocol;
        }

        Ok(())
    }

    fn get_package_list_config(package_list: &Option<String>) -> (bool, bool) {
        let mut ntlm_package: bool = true;
        let mut kerberos_package: bool = true;

        if let Some(package_list) = &package_list {
            for package in package_list.split(",") {
                let (package_name, enabled) = if package.starts_with("!") {
                    let package_name = package[1..].to_lowercase();
                    (package_name, false)
                } else {
                    let package_name = package.to_lowercase();
                    (package_name, true)
                };

                match package_name.as_str() {
                    "ntlm" => { ntlm_package = enabled; }
                    "kerberos" => { kerberos_package = enabled; }
                    _ => { eprintln!("unexpected package name: {}", &package_name); }
                }
            }
        }

        (ntlm_package, kerberos_package)
    }

    fn filter_protocol(negotiated_protocol: &NegotiatedProtocol, package_list: &Option<String>) -> Option<NegotiatedProtocol> {
        let mut filtered_protocol = None;
        let (ntlm_package, kerberos_package) = Self::get_package_list_config(package_list);
        
        match &negotiated_protocol {
            NegotiatedProtocol::Kerberos(_) => {
                if !kerberos_package {
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::new()));
                }
            },
            NegotiatedProtocol::Ntlm(_) => {
                if !ntlm_package {
                    let kerberos_client = Kerberos::new_client_from_config(KerberosConfig::from_env()).unwrap();
                    filtered_protocol = Some(NegotiatedProtocol::Kerberos(kerberos_client));
                }
            }
        }

        filtered_protocol
    }
}

impl SspiEx for Negotiate {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.clone().into());

        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.custom_set_auth_identity(identity),
        }
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

    fn change_password(&mut self, change_password: builders::ChangePassword) -> Result<()> {
        #[cfg(feature = "network_client")]
        self.negotiate_protocol(&change_password.account_name, &change_password.domain_name)?;

        match &mut self.protocol {
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

        #[cfg(feature = "network_client")]
        if let Some(identity) = builder.auth_data {
            if let Some(domain) = &identity.domain {
                self.negotiate_protocol(&identity.username, &domain)?;
            } else {
                self.negotiate_protocol(&identity.username, "")?;
            }
        }

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

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
        if let Some(Some(identity)) = builder.credentials_handle {
            let auth_identity: AuthIdentity = (*identity).clone().into();
            let username = auth_identity.username.to_owned();
            if let Some(domain) = &auth_identity.domain {
                self.negotiate_protocol(&username, &domain)?;
            } else {
                self.negotiate_protocol(&username, "")?;
            }
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
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.initialize_security_context_impl(builder),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.initialize_security_context_impl(builder),
        }
    }

    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.accept_security_context_impl(builder),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.accept_security_context_impl(builder),
        }
    }
}
