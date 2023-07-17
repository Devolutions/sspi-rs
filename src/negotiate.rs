use std::fmt::Debug;
use std::net::IpAddr;

use lazy_static::lazy_static;

use crate::{kdc::detect_kdc_url, CredentialsBuffers};
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
    SecurityPackageType, SecurityStatus, Sspi, SspiEx, SspiImpl, PACKAGE_ID_NONE, Credentials,
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

pub trait ProtocolConfig: Debug + Send + Sync {
    fn new_client(&self) -> Result<NegotiatedProtocol>;
    fn clone(&self) -> Box<dyn ProtocolConfig>;
}

#[derive(Debug)]
pub struct NegotiateConfig {
    pub protocol_config: Box<dyn ProtocolConfig>,
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
            network_client_factory: self.network_client_factory.box_clone(),
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
    auth_identity: Option<CredentialsBuffers>,
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
            network_client_factory: self.network_client_factory.box_clone(),
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
        if let Some(filtered_protocol) = Self::filter_protocol(&protocol, &config.package_list, &config.hostname)? {
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

        if let Some(filtered_protocol) = Self::filter_protocol(&self.protocol, &self.package_list, &self.hostname)? {
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
        #[allow(unused_variables)] hostname: &str, // Unused if `network_client` feature is disabled
    ) -> Result<Option<NegotiatedProtocol>> {
        let mut filtered_protocol = None;
        let PackageListConfig {
            ntlm: is_ntlm,
            kerberos: is_kerberos,
            pku2u: is_pku2u,
        } = Self::parse_package_list_config(package_list);

        match &negotiated_protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                if !is_pku2u {
                    let ntlm_config = NtlmConfig::new(pku2u.config().hostname.clone());
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config)));
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
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config)));
                }
            }
            NegotiatedProtocol::Ntlm(_) => {
                #[cfg(not(feature = "network_client"))]
                if !is_ntlm {
                    return Err(Error::new(
                        ErrorKind::InvalidParameter,
                        "Can not initialize Kerberos: network client is not provided",
                    ));
                }
                #[cfg(feature = "network_client")]
                if !is_ntlm {
                    let mut config = KerberosConfig::from_env();
                    config.hostname = Some(hostname.to_owned());

                    let kerberos_client = Kerberos::new_client_from_config(config)?;
                    filtered_protocol = Some(NegotiatedProtocol::Kerberos(kerberos_client));
                }
            }
        }

        Ok(filtered_protocol)
    }

    fn is_protocol_ntlm(&self) -> bool {
        matches!(&self.protocol, NegotiatedProtocol::Ntlm(_))
    }

    fn can_downgrade_ntlm(&self) -> bool {
        let package_list = Self::parse_package_list_config(&self.package_list);
        package_list.ntlm
    }

    fn is_target_name_ip_address(address: &str) -> bool {
        let stripped_address = address.split('/').last().unwrap_or(address);
        stripped_address.parse::<IpAddr>().is_ok()
    }

    fn check_target_name_for_ntlm_downgrade(&mut self, target_name: &str) {
        let should_downgrade = Self::is_target_name_ip_address(target_name);
        let can_downgrade = self.can_downgrade_ntlm();

        if can_downgrade && should_downgrade && !self.is_protocol_ntlm() {
            let ntlm_config = NtlmConfig::new(self.hostname.clone());
            self.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config));
        }
    }
}

impl SspiEx for Negotiate {
    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.clone().try_into().unwrap());

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                pku2u.custom_set_auth_identity(identity.auth_identity().unwrap())
            },
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.custom_set_auth_identity(identity.auth_identity().unwrap()),
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
    type CredentialsHandle = Option<CredentialsBuffers>;
    type AuthenticationData = Credentials;

    // #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
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

        if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
            self.negotiate_protocol(&identity.username, identity.domain.as_deref().unwrap_or_default())?;
        }

        self.auth_identity = match builder.auth_data.cloned() {
            Some(auth_data) => Some(auth_data.try_into()?),
            None => None,
        };

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                let auth_identity = if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                    identity
                } else {
                    return Err(Error::new(ErrorKind::NoCredentials, "Auth identity is not provided for the Pku2u"));
                };
                let new_builder = builder.full_transform(pku2u, Some(auth_identity));
                pku2u.acquire_credentials_handle_impl(new_builder)?
            },
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.acquire_credentials_handle_impl(builder)?,
            NegotiatedProtocol::Ntlm(ntlm) => {
                let auth_identity = if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                    identity
                } else {
                    return Err(Error::new(ErrorKind::NoCredentials, "Auth identity is not provided for the Pku2u"));
                };
                let new_builder = builder.full_transform(ntlm, Some(auth_identity));
                ntlm.acquire_credentials_handle_impl(new_builder)?
            },
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
        if let Some(target_name) = &builder.target_name {
            self.check_target_name_for_ntlm_downgrade(target_name);
        }

        if let Some(Some(CredentialsBuffers::AuthIdentity(identity))) = builder.credentials_handle {
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
                    ..
                }) => {
                    warn!("Negotiate: Fall back to the NTLM");

                    let ntlm_config = kerberos
                        .config()
                        .hostname
                        .clone()
                        .map(NtlmConfig::new)
                        .unwrap_or_default();
                    self.protocol =
                        NegotiatedProtocol::Ntlm(Ntlm::with_auth_identity(self.auth_identity.clone().map(|c| c.auth_identity()).flatten(), ntlm_config));
                }
                result => return result,
            };
        }

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                let credentials_handle = self.auth_identity.as_mut().map(|c| c.auth_identity()).flatten();
                let transformed_builder = builder.full_transform(Some(&mut credentials_handle));

                pku2u.initialize_security_context_impl(&mut transformed_builder)
            },
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.initialize_security_context_impl(builder),
            NegotiatedProtocol::Ntlm(ntlm) => {
                let credentials_handle = self.auth_identity.as_mut().map(|c| c.auth_identity()).flatten();
                let transformed_builder = builder.full_transform(Some(&mut credentials_handle));

                ntlm.initialize_security_context_impl(&mut transformed_builder)
            },
        }
    }

    #[instrument(ret, fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> Result<AcceptSecurityContextResult> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                let creds_handle = if let Some(creds_handle) = builder.credentials_handle {
                    creds_handle.map(|c| c.auth_identity()).flatten()
                } else {
                    None
                };
                let new_builder = builder.full_transform(pku2u, Some(&mut creds_handle));
                pku2u.accept_security_context_impl(new_builder)
            },
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.accept_security_context_impl(builder),
            NegotiatedProtocol::Ntlm(ntlm) => {
                let creds_handle = if let Some(creds_handle) = builder.credentials_handle {
                    creds_handle.map(|c| c.auth_identity()).flatten()
                } else {
                    None
                };
                let new_builder = builder.full_transform(ntlm, Some(&mut creds_handle));
                ntlm.accept_security_context_impl(new_builder)
            },
        }
    }
}
