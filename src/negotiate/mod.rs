pub(crate) mod client;
mod config;
mod extractors;
mod generators;
pub(crate) mod server;

use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::LazyLock;

pub use config::{NegotiateConfig, ProtocolConfig};
use picky::oids;
use picky_krb::gss_api::MechType;

use crate::generator::{
    GeneratorAcceptSecurityContext, GeneratorChangePassword, GeneratorInitSecurityContext, YieldPointLocal,
};
use crate::kdc::detect_kdc_url;
use crate::kerberos::client::generators::get_client_principal_realm;
use crate::ntlm::NtlmConfig;
#[allow(unused)]
use crate::utils::is_azure_ad_domain;
use crate::{
    builders, kerberos, ntlm, pku2u, AcquireCredentialsHandleResult, AuthIdentity, CertTrustStatus, ContextNames,
    ContextSizes, CredentialUse, Credentials, CredentialsBuffers, DecryptionFlags, Error, ErrorKind, Kerberos,
    KerberosConfig, Ntlm, PackageCapabilities, PackageInfo, Pku2u, Result, SecurityBuffer, SecurityBufferRef,
    SecurityPackageType, SecurityStatus, Sspi, SspiEx, SspiImpl, PACKAGE_ID_NONE,
};

pub const PKG_NAME: &str = "Negotiate";

pub static PACKAGE_INFO: LazyLock<PackageInfo> = LazyLock::new(|| PackageInfo {
    capabilities: PackageCapabilities::empty(),
    rpc_id: PACKAGE_ID_NONE,
    max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
    name: SecurityPackageType::Negotiate,
    comment: String::from("Microsoft Package Negotiator"),
});

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

    pub fn validate_mic_token(&mut self, token: &[u8], data: &[u8]) -> Result<()> {
        match self {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.validate_mic_token(token, data),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.validate_mic_token(token, data),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.validate_mic_token(token, data),
        }
    }

    pub fn generate_mic_token(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        match self {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.generate_mic_token(data),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.generate_mic_token(data),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.generate_mic_token(data),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
enum NegotiateState {
    #[default]
    Initial,
    InProgress,
    VerifyMic,
    Ok,
}

#[derive(Clone, Debug, PartialEq)]
enum NegotiateMode {
    Client,
    Server(Vec<AuthIdentity>),
}

impl NegotiateMode {
    fn is_client(&self) -> bool {
        self == &NegotiateMode::Client
    }
}

#[derive(Clone, Debug)]
pub struct Negotiate {
    state: NegotiateState,
    protocol: NegotiatedProtocol,
    package_list: Option<String>,
    auth_identity: Option<CredentialsBuffers>,
    client_computer_name: String,
    mode: NegotiateMode,
    mech_types: picky_krb::gss_api::MechTypeList,
    mic_verified: bool,
}

#[derive(Debug)]
struct PackageListConfig {
    ntlm: bool,
    kerberos: bool,
    pku2u: bool,
}

impl Negotiate {
    pub fn new_client(config: NegotiateConfig) -> Result<Self> {
        let mode = NegotiateMode::Client;
        let mut protocol = config.protocol_config.new_instance()?;
        if let Some(filtered_protocol) =
            Self::filter_protocol(&protocol, &config.package_list, &config.client_computer_name, true)?
        {
            protocol = filtered_protocol;
        }

        Ok(Negotiate {
            state: Default::default(),
            protocol,
            package_list: config.package_list,
            auth_identity: None,
            client_computer_name: config.client_computer_name,
            mode,
            mech_types: Default::default(),
            mic_verified: false,
        })
    }

    pub fn new_server(config: NegotiateConfig, auth_data: Vec<AuthIdentity>) -> Result<Self> {
        let mode = NegotiateMode::Server(auth_data);
        let mut protocol = config.protocol_config.new_instance()?;
        if let Some(filtered_protocol) =
            Self::filter_protocol(&protocol, &config.package_list, &config.client_computer_name, false)?
        {
            protocol = filtered_protocol;
        }

        Ok(Negotiate {
            state: Default::default(),
            protocol,
            package_list: config.package_list,
            auth_identity: None,
            client_computer_name: config.client_computer_name,
            mode,
            mech_types: Default::default(),
            mic_verified: false,
        })
    }

    fn protocol_name(&self) -> &str {
        self.protocol.protocol_name()
    }

    fn set_auth_identity(&mut self) -> Result<()> {
        let ContextNames { username } = match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_names()?,
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_names()?,
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_names()?,
        };

        let NegotiateMode::Server(auth_data) = &self.mode else {
            return Err(Error::new(
                ErrorKind::InternalError,
                "set_auth_identity must be called only on server side",
            ));
        };

        let auth_data = auth_data
            .iter()
            .find(|auth_data| {
                let domains_equal = match (auth_data.username.domain_name(), username.domain_name()) {
                    (Some(auth_domain), Some(negotiated_domain)) => auth_domain.eq_ignore_ascii_case(negotiated_domain),
                    (None, None) => true,
                    _ => false,
                };

                auth_data
                    .username
                    .account_name()
                    .eq_ignore_ascii_case(username.account_name())
                    && domains_equal
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::NoCredentials,
                    "user credentials are not found on the server side",
                )
            })?
            .clone();

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.custom_set_auth_identity(auth_data)?,
            NegotiatedProtocol::Kerberos(kerberos) => {
                kerberos.custom_set_auth_identity(Credentials::AuthIdentity(auth_data))?
            }
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.custom_set_auth_identity(auth_data)?,
        }

        Ok(())
    }

    fn negotiate_protocol_by_mech_type(&mut self, mech_type: &MechType) -> Result<()> {
        let enabled_packages = Self::parse_package_list_config(&self.package_list);
        debug!(?enabled_packages, "ptri: {}", self.protocol_name());

        if mech_type == &oids::ms_krb5() || mech_type == &oids::krb5() {
            if !enabled_packages.kerberos {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "Kerberos mechanism was selected by the server but is disabled in package_list",
                ));
            }

            if self.protocol_name() != kerberos::PKG_NAME {
                let kerberos = Kerberos::new_client_from_config(KerberosConfig {
                    client_computer_name: Some(self.client_computer_name.clone()),
                    kdc_url: None,
                })?;
                self.protocol = NegotiatedProtocol::Kerberos(kerberos);
            }

            return Ok(());
        }

        if mech_type == &oids::ntlm_ssp() {
            if !enabled_packages.ntlm {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "NTLM mechanism was selected by the server but is disabled in package_list",
                ));
            }

            if self.protocol_name() != ntlm::PKG_NAME {
                self.protocol =
                    NegotiatedProtocol::Ntlm(Ntlm::with_config(NtlmConfig::new(self.client_computer_name.clone())));
            }

            return Ok(());
        }

        let s: String = (&mech_type.0).into();
        Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unsupported mech_type: {s}"),
        ))
    }

    // negotiates the authorization protocol based on the username and the domain
    // Decision rules:
    // 1) if `self.protocol` is not NTLM then we've already negotiated a suitable protocol. Nothing to do.
    // 2) if the provided domain is Azure AD domain then it'll use Pku2u
    // 3) if the provided username is FQDN and we can resolve KDC then it'll use Kerberos
    // 4) if SSPI_KDC_URL_ENV is set then it'll also use Kerberos
    // 5) in any other cases, it'll use NTLM
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip(self))]
    fn negotiate_protocol(&mut self, username: &str, domain: &str) -> Result<()> {
        let enabled_packages = Self::parse_package_list_config(&self.package_list);

        if let NegotiatedProtocol::Ntlm(_) = &self.protocol {
            #[cfg(target_os = "windows")]
            if enabled_packages.pku2u && is_azure_ad_domain(domain) {
                use super::pku2u::Pku2uConfig;

                debug!("Negotiate: try Pku2u");

                self.protocol = NegotiatedProtocol::Pku2u(Pku2u::new_client_from_config(
                    Pku2uConfig::default_client_config(self.client_computer_name.clone())?,
                )?);
            }

            if enabled_packages.kerberos {
                if let Some(host) = detect_kdc_url(&get_client_principal_realm(username, domain)) {
                    debug!("Negotiate: try Kerberos");

                    self.protocol = NegotiatedProtocol::Kerberos(Kerberos::new_client_from_config(KerberosConfig {
                        kdc_url: Some(host),
                        client_computer_name: Some(self.client_computer_name.clone()),
                    })?);
                }
            }
        }

        if let Some(filtered_protocol) = Self::filter_protocol(
            &self.protocol,
            &self.package_list,
            &self.client_computer_name,
            self.mode.is_client(),
        )? {
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
                    _ => warn!("unexpected package name: {}", &package_name),
                }
            }
        }

        PackageListConfig { ntlm, kerberos, pku2u }
    }

    fn filter_protocol(
        negotiated_protocol: &NegotiatedProtocol,
        package_list: &Option<String>,
        client_computer_name: &str,
        is_client: bool,
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
                    let ntlm_config = NtlmConfig::new(pku2u.config().client_hostname.clone());
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config)));
                }
            }
            NegotiatedProtocol::Kerberos(kerberos) => {
                if !is_kerberos {
                    let ntlm_config = kerberos
                        .config()
                        .client_computer_name
                        .clone()
                        .map(NtlmConfig::new)
                        .unwrap_or_default();
                    filtered_protocol = Some(NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config)));
                }
            }
            NegotiatedProtocol::Ntlm(_) => {
                if !is_ntlm {
                    let config = KerberosConfig {
                        client_computer_name: Some(client_computer_name.to_owned()),
                        kdc_url: None,
                    };

                    if is_client {
                        let kerberos_client = Kerberos::new_client_from_config(config)?;
                        filtered_protocol = Some(NegotiatedProtocol::Kerberos(kerberos_client));
                    } else {
                        // Aborting because we need an additional data (ServerProperties object) to create the server-side Kerberos instance.
                        error!(
                            ?package_list,
                            "NTLM protocol has been negotiated but it is disabled in package_list."
                        );

                        return Err(Error::new(
                            ErrorKind::InternalError,
                            "NTLM protocol has been negotiated but it is disabled in package_list",
                        ));
                    }
                }
            }
        }

        Ok(filtered_protocol)
    }

    pub fn negotiated_protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }

    fn is_protocol_ntlm(&self) -> bool {
        matches!(&self.protocol, NegotiatedProtocol::Ntlm(_))
    }

    fn can_downgrade_ntlm(&self) -> bool {
        let package_list = Self::parse_package_list_config(&self.package_list);
        package_list.ntlm
    }

    fn is_target_name_ip_address(address: &str) -> bool {
        let stripped_address = address.split('/').next_back().unwrap_or(address);
        stripped_address.parse::<IpAddr>().is_ok()
    }

    fn check_target_name_for_ntlm_downgrade(&mut self, target_name: &str) {
        let should_downgrade = Self::is_target_name_ip_address(target_name);
        let can_downgrade = self.can_downgrade_ntlm();

        if can_downgrade && should_downgrade && !self.is_protocol_ntlm() {
            let ntlm_config = NtlmConfig::new(self.client_computer_name.clone());
            self.protocol = NegotiatedProtocol::Ntlm(Ntlm::with_config(ntlm_config));
        }
    }
}

impl SspiEx for Negotiate {
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) -> Result<()> {
        self.auth_identity = Some(identity.clone().try_into().unwrap());

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                pku2u.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                    Error::new(
                        ErrorKind::IncompleteCredentials,
                        "Provided credentials are not password-based",
                    )
                })?)
            }
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.custom_set_auth_identity(identity),
            NegotiatedProtocol::Ntlm(ntlm) => {
                ntlm.custom_set_auth_identity(identity.auth_identity().ok_or_else(|| {
                    Error::new(
                        ErrorKind::IncompleteCredentials,
                        "Provided credentials are not password-based",
                    )
                })?)
            }
        }
    }
}

impl Sspi for Negotiate {
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip(self))]
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.complete_auth_token(token),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.complete_auth_token(token),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.complete_auth_token(token),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn encrypt_message(
        &mut self,
        flags: crate::EncryptionFlags,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
    ) -> Result<SecurityStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.encrypt_message(flags, message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.encrypt_message(flags, message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.encrypt_message(flags, message, sequence_number),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
    ) -> Result<DecryptionFlags> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.decrypt_message(message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.decrypt_message(message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.decrypt_message(message, sequence_number),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_sizes(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_sizes(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_sizes(),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_names(&mut self) -> Result<ContextNames> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_names(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_names(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_names(),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        crate::query_security_package_info(SecurityPackageType::Negotiate)
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_package_info(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_package_info(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_package_info(),
        }
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_cert_trust_status(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_cert_trust_status(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_cert_trust_status(),
        }
    }

    #[instrument(fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn query_context_session_key(&self) -> Result<crate::SessionKeys> {
        match &self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.query_context_session_key(),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.query_context_session_key(),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.query_context_session_key(),
        }
    }

    fn change_password<'a>(
        &'a mut self,
        change_password: builders::ChangePassword<'a>,
    ) -> Result<GeneratorChangePassword<'a>> {
        Ok(GeneratorChangePassword::new(move |mut yield_point| async move {
            self.change_password(&mut yield_point, change_password).await
        }))
    }

    fn make_signature(
        &mut self,
        flags: u32,
        message: &mut [SecurityBufferRef<'_>],
        sequence_number: u32,
    ) -> Result<()> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.make_signature(flags, message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.make_signature(flags, message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.make_signature(flags, message, sequence_number),
        }
    }

    fn verify_signature(&mut self, message: &mut [SecurityBufferRef<'_>], sequence_number: u32) -> Result<u32> {
        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => pku2u.verify_signature(message, sequence_number),
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.verify_signature(message, sequence_number),
            NegotiatedProtocol::Ntlm(ntlm) => ntlm.verify_signature(message, sequence_number),
        }
    }
}

impl SspiImpl for Negotiate {
    type CredentialsHandle = Option<CredentialsBuffers>;
    type AuthenticationData = Credentials;

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn acquire_credentials_handle_impl(
        &mut self,
        builder: builders::FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "The client must specify the auth data",
            ));
        }

        if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
            let account_name = identity.username.account_name();
            let domain_name = identity.username.domain_name().unwrap_or("");
            self.negotiate_protocol(account_name, domain_name)?;
        }

        self.auth_identity = builder
            .auth_data
            .cloned()
            .map(|auth_data| auth_data.try_into())
            .transpose()?;

        match &mut self.protocol {
            NegotiatedProtocol::Pku2u(pku2u) => {
                let auth_identity = if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                    identity
                } else {
                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        "Auth identity is not provided for the Pku2u",
                    ));
                };
                let new_builder = builder.full_transform(Some(auth_identity));
                new_builder.execute(pku2u)?;
            }
            NegotiatedProtocol::Kerberos(kerberos) => {
                kerberos.acquire_credentials_handle_impl(builder)?;
            }
            NegotiatedProtocol::Ntlm(ntlm) => {
                let auth_identity = if builder.credential_use == CredentialUse::Outbound {
                    if let Some(Credentials::AuthIdentity(identity)) = builder.auth_data {
                        Some(identity)
                    } else {
                        return Err(Error::new(
                            ErrorKind::NoCredentials,
                            "Auth identity is not provided for the Ntlm",
                        ));
                    }
                } else {
                    None
                };
                let new_builder = builder.full_transform(auth_identity);
                new_builder.execute(ntlm)?;
            }
        };

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    fn accept_security_context_impl<'a>(
        &'a mut self,
        builder: builders::FilledAcceptSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<GeneratorAcceptSecurityContext<'a>> {
        Ok(GeneratorAcceptSecurityContext::new(move |mut yield_point| async move {
            server::accept_security_context(self, &mut yield_point, builder).await
        }))
    }

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut builders::FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        Ok(GeneratorInitSecurityContext::new(move |mut yield_point| async move {
            client::initialize_security_context(self, &mut yield_point, builder).await
        }))
    }
}

impl<'a> Negotiate {
    #[instrument(ret, level = "debug", fields(protocol = self.protocol.protocol_name()), skip_all)]
    pub(crate) async fn change_password(
        &'a mut self,
        yield_point: &mut YieldPointLocal,
        change_password: builders::ChangePassword<'a>,
    ) -> Result<()> {
        self.negotiate_protocol(&change_password.account_name, &change_password.domain_name)?;

        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => kerberos.change_password(yield_point, change_password).await,
            _ => Err(Error::new(
                ErrorKind::UnsupportedFunction,
                "cannot change password for this protocol",
            )),
        }
    }
}
