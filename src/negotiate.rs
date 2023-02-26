use std::fmt::Debug;

use lazy_static::lazy_static;

use crate::kdc::detect_kdc_url;
use crate::kerberos::client::generators::get_client_principal_realm;
use crate::network_client::NetworkClientFactory;
use crate::ntlm::NtlmConfig;
#[allow(unused)]
use crate::utils::is_azure_ad_domain;
#[cfg(feature = "network_client")]
use crate::KerberosConfig;
use crate::{
    builders, kerberos, ntlm, pku2u, AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity,
    AuthIdentityBuffers, CertTrustStatus, ContextNames, ContextSizes, CredentialUse, DecryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, Kerberos, Ntlm, PackageCapabilities, PackageInfo, Pku2u, Result, SecurityBuffer,
    SecurityPackageType, SecurityStatus, Sspi, SspiEx, SspiImpl, PACKAGE_ID_NONE,
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

pub trait ProtocolConfig: Debug {
    fn new_client(&self) -> Result<NegotiatedProtocol>;
    fn clone(&self) -> Box<dyn ProtocolConfig + Send>;
}

#[derive(Debug)]
pub struct NegotiateConfig {
    pub protocol_config: Box<dyn ProtocolConfig + Send>,
    pub package_list: Option<String>,
    pub hostname: String,
    pub network_client_factory: Box<dyn NetworkClientFactory>,
}

impl NegotiateConfig {
    pub fn new(
        protocol_config: Box<dyn ProtocolConfig + Send>,
        package_list: Option<String>,
        hostname: String,
        network_client_factory: Box<dyn NetworkClientFactory>,
    ) -> Self {
        Self {
            protocol_config,
            package_list,
            hostname,
            network_client_factory,
        }
    }

    pub fn from_protocol_config(
        protocol_config: Box<dyn ProtocolConfig + Send>,
        hostname: String,
        network_client_factory: Box<dyn NetworkClientFactory>,
    ) -> Self {
        Self {
            protocol_config,
            package_list: None,
            hostname,
            network_client_factory,
        }
    }
}

impl Clone for NegotiateConfig {
    fn clone(&self) -> Self {
        Self {
            protocol_config: self.protocol_config.clone(),
            package_list: None,
            hostname: self.hostname.clone(),
            network_client_factory: self.network_client_factory.clone(),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NegotiatedProtocol {
    Pku2u(Pku2u),
    Kerberos(Kerberos),
    Ntlm(Ntlm),
}

impl NegotiatedProtocol {
    pub fn protocol_name(&self) -> &str {
        match self {
            NegotiatedProtocol::Pku2u(_) => pku2u::PKG_NAME,
            NegotiatedProtocol::Kerberos(_) => kerberos::PKG_NAME,
            NegotiatedProtocol::Ntlm(_) => ntlm::PKG_NAME,
        }
    }
}

#[derive(Debug)]
pub struct Negotiate {
    protocol: NegotiatedProtocol,
    package_list: Option<String>,
    auth_identity: Option<AuthIdentityBuffers>,
    hostname: String,
    network_client_factory: Box<dyn NetworkClientFactory>,
}

impl Clone for Negotiate {
    fn clone(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
            package_list: self.package_list.clone(),
            auth_identity: self.auth_identity.clone(),
            hostname: self.hostname.clone(),
            network_client_factory: self.network_client_factory.clone(),
        }
    }
}

struct PackageListConfig {
    ntlm: bool,
    kerberos: bool,
    pku2u: bool,
}

impl Negotiate {
    pub fn new(config: NegotiateConfig) -> Result<Self> {
        let mut protocol = config.protocol_config.new_client()?;
        if let Some(filtered_protocol) = Self::filter_protocol(&protocol, &config.package_list)? {
            protocol = filtered_protocol;
        }

        Ok(Negotiate {
            protocol,
            package_list: config.package_list,
            auth_identity: None,
            hostname: config.hostname,
            network_client_factory: config.network_client_factory,
        })
    }

    // negotiates the authorization protocol based on the username and the domain
    // Decision rules:
    // 1) if `self.protocol` is not NTLM then we've already negotiated a suitable protocol. Nothing to do.
    // 2) if the provided domain is Azure AD domain then it'll use Pku2u
    // 3) if the provided username is FQDN and we can resolve KDC then it'll use Kerberos
    // 4) if SSPI_KDC_URL_ENV is set then it'll also use Kerberos
    // 5) in any other cases, it'll use NTLM
    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip(self))]
    fn negotiate_protocol(&mut self, username: &str, domain: &str) -> Result<()> {
        if let NegotiatedProtocol::Ntlm(_) = &self.protocol {
            #[cfg(target_os = "windows")]
            if is_azure_ad_domain(domain) {
                use super::pku2u::Pku2uConfig;

                info!("Negotiate: try Pku2u");

                self.protocol = NegotiatedProtocol::Pku2u(Pku2u::new_client_from_config(
                    Pku2uConfig::default_client_config(self.hostname.clone())?,
                )?);
            }

            if let Some(host) = detect_kdc_url(&get_client_principal_realm(username, domain)) {
                info!("Negotiate: try Kerberos");

                self.protocol =
                    NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(crate::KerberosConfig {
                        url: Some(host),
                        network_client: self.network_client_factory.network_client(),
                        hostname: Some(self.hostname.clone()),
                    })?);
            }
        }

        if let Some(filtered_protocol) = Self::filter_protocol(&self.protocol, &self.package_list)? {
            self.protocol = filtered_protocol;
        }

        Ok(())
    }

    fn parse_package_list_config(package_list: &Option<String>) -> PackageListConfig {
        let mut ntlm: bool = true;
        let mut kerberos: bool = true;
        let mut pku2u: bool = true;

        if let Some(package_list) = &package_list {
            for package in package_list.split(',') {
                let (package_name, enabled) = if let Some(package_name) = package.strip_prefix('!') {
                    (package_name.to_lowercase(), false)
                } else {
                    let package_name = package.to_lowercase();
                    (package_name, true)
                };

                match package_name.as_str() {
                    "ntlm" => ntlm = enabled,
                    "kerberos" => kerberos = enabled,
                    "pku2u" => pku2u = enabled,
                    _ => eprintln!("unexpected package name: {}", &package_name),
                }
            }
        }

        PackageListConfig { ntlm, kerberos, pku2u }
    }

    fn filter_protocol(
        negotiated_protocol: &NegotiatedProtocol,
        package_list: &Option<String>,
    ) -> Result<Option<NegotiatedProtocol>> {
        let mut filtered_protocol = None;
        let PackageListConfig {
            ntlm,
            kerberos: is_kerberos,
            pku2u: is_pku2u,
        } = Self::parse_package_list_config(package_list);

        match &negotiated_protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                if !is_pku2u {
                    let ntlm_config = NtlmConfig::new(pku2u.config().hostname.clone());
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::new(ntlm_config)));
                }
            }
            NegotiatedProtocol::Kerberos(kerberos) => {
                if !is_kerberos {
                    let ntlm_config = kerberos
                        .config()
                        .hostname
                        .clone()
                        .map(NtlmConfig::new)
                        .unwrap_or_default();
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::new(ntlm_config)));
                }
            }
            NegotiatedProtocol::Ntlm(_) => {
                #[cfg(not(feature = "network_client"))]
                if !ntlm {
                    return Err(Error::new(
                        ErrorKind::InvalidParameter,
                        "Can not initialize Kerberos: network client is not provided".into(),
                    ));
                }
                #[cfg(feature = "network_client")]
                if !ntlm {
                    let kerberos_client = Kerberos::new_client_from_config(KerberosConfig::from_env())?;
                    filtered_protocol = Some(NegotiatedProtocol::Kerberos(kerberos_client));
                }
            }
        }

        Ok(filtered_protocol)
    }
}

impl SspiEx for Negotiate {
    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
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
    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip(self))]
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.complete_auth_token(token),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.complete_auth_token(token),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.complete_auth_token(token),
        }
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
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

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], sequence_number: u32) -> Result<DecryptionFlags> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.decrypt_message(message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.decrypt_message(message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.decrypt_message(message, sequence_number),
        }
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_sizes(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_sizes(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_sizes(),
        }
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_names(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_names(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_names(),
        }
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Negotiate)
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_package_info(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_package_info(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_package_info(),
        }
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_cert_trust_status(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
        }
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn change_password(&mut self, change_password: builders::ChangePassword) -> Result<()> {
        self.negotiate_protocol(&change_password.account_name, &change_password.domain_name)?;

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

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
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
            self.negotiate_protocol(&identity.username, identity.domain.as_deref().unwrap_or_default())?;
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

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut builders::FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        if let Some(Some(identity)) = builder.credentials_handle {
            let auth_identity: AuthIdentity = identity.clone().into();

            if let Some(domain) = &auth_identity.domain {
                self.negotiate_protocol(&auth_identity.username, domain)?;
            } else {
                self.negotiate_protocol(&auth_identity.username, "")?;
            }
        }

        if let NegotiatedProtocol::Kerberos(kerberos) = &mut self.protocol {
            match kerberos.initialize_security_context_impl(builder) {
                Result::Err(Error {
                    error_type: ErrorKind::NoCredentials,
                    description: _,
                }) => {
                    warn!("Negotiate: Fall back to the NTLM");

                    let ntlm_config = kerberos
                        .config()
                        .hostname
                        .clone()
                        .map(NtlmConfig::new)
                        .unwrap_or_default();
                    self.protocol =
                        NegotiatedProtocol::Ntlm(Ntlm::with_auth_identity(self.auth_identity.clone(), ntlm_config));
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

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
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
