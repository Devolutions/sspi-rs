use lazy_static::lazy_static;

use crate::internal::SspiImpl;
use crate::sspi::{Result, PACKAGE_ID_NONE};
use crate::{
    builders, AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers,
    CertTrustStatus, ContextNames, ContextSizes, DecryptionFlags, Error, ErrorKind, InitializeSecurityContextResult,
    Kerberos, KerberosConfig, Ntlm, PackageCapabilities, PackageInfo, SecurityBuffer, SecurityPackageType,
    SecurityStatus, Sspi,
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

pub struct NegotiateConfig {
    pub krb_config: Option<KerberosConfig>,
}

pub enum NegotiatedProtocol {
    Kerberos(Kerberos),
    Ntlm(Ntlm),
}

pub struct Negotiate {
    config: NegotiateConfig,
    protocol: NegotiatedProtocol,
}

impl Negotiate {
    pub fn new(config: NegotiateConfig) -> Self {
        Negotiate {
            config,
            protocol: NegotiatedProtocol::Ntlm(Ntlm::new()),
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
}

impl SspiImpl for Negotiate {
    type CredentialsHandle = Option<AuthIdentityBuffers>;

    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl(
        &mut self,
        builder: builders::FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        todo!()
    }

    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut builders::FilledInitializeSecurityContext<'a, Self::AuthenticationData,  Self::CredentialsHandle>,
    ) -> Result<InitializeSecurityContextResult> {
        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => {
                // builder.inner(Box::new(kerberos));
                let result = kerberos.initialize_security_context_impl(builder);
                match result {
                    Result::Err(Error { error_type: ErrorKind::NoCredentials, description: _ }) => {
                        self.protocol = NegotiatedProtocol::Ntlm(Ntlm::new());
                    },
                    _ => return result,
                };
            }
            _ => {},
        };

        match &mut self.protocol {
            NegotiatedProtocol::Kerberos(kerberos) => {
                kerberos.initialize_security_context_impl(builder)
            }
            NegotiatedProtocol::Ntlm(ntlm) => {
                ntlm.initialize_security_context_impl(builder)
            },
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
