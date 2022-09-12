mod generators;

use std::io::Write;
use std::str::FromStr;

use lazy_static::lazy_static;
use picky_asn1_x509::Certificate;
use picky_krb::negoex::data_types::MessageType;
use picky_krb::negoex::messages::{Exchange, Nego};
use picky_krb::negoex::{NegoexMessage, RANDOM_ARRAY_SIZE};
use rand::rngs::OsRng;
use rand::Rng;
use uuid::Uuid;

use self::generators::{generate_neg_token_init, generate_pku2u_nego_req};
use crate::builders::ChangePassword;
use crate::internal::SspiImpl;
use crate::kerberos::{EncryptionParams, MAX_SIGNATURE, SECURITY_TRAILER};
use crate::sspi::{self, PACKAGE_ID_NONE};
use crate::utils::utf16_bytes_to_utf8_string;
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, CertTrustStatus,
    ClientResponseFlags, ContextNames, ContextSizes, CredentialUse, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, PackageCapabilities, PackageInfo, Result, SecurityBuffer, SecurityBufferType,
    SecurityPackageType, SecurityStatus, Sspi,
};

pub const PKG_NAME: &str = "Pku2u";

/// Default NEGOEX authentication scheme
pub const AUTH_SCHEME: &str = "0d53335c-f9ea-4d0d-b2ec-4ae3786ec308";

lazy_static! {
    pub static ref PACKAGE_INFO: PackageInfo = PackageInfo {
        capabilities: PackageCapabilities::empty(),
        rpc_id: PACKAGE_ID_NONE,
        max_token_len: 0xbb80, // 48 000 bytes: default maximum token len in Windows
        name: SecurityPackageType::Pku2u,
        comment: String::from("Pku2u"),
    };
}

#[derive(Debug, Clone)]
pub enum Pku2uState {
    Negotiate,
    Preauthentication,
    ApExchange,
    PubKeyAuth,
    Credentials,
    Final,
}

#[derive(Debug, Clone)]
pub struct Pku2uConfig {
    p2p_certificate: Certificate,
    p2p_ca_certificate: Certificate,
}

#[derive(Debug, Clone)]
pub struct Pku2u {
    config: Pku2uConfig,
    state: Pku2uState,
    encryption_params: EncryptionParams,
    auth_identity: Option<AuthIdentityBuffers>,
    conversation_id: Uuid,
    seq_number: u32,
    realm: Option<String>,
}

impl Pku2u {
    pub fn new_client_from_config(config: Pku2uConfig) -> Result<Self> {
        Ok(Self {
            config,
            state: Pku2uState::Negotiate,
            encryption_params: EncryptionParams::default_for_client(),
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            seq_number: 0,
            realm: None,
        })
    }

    pub fn next_seq_number(&mut self) -> u32 {
        let seq_num = self.seq_number;
        self.seq_number += 1;

        seq_num
    }
}

impl Sspi for Pku2u {
    fn complete_auth_token(&mut self, _token: &mut [SecurityBuffer]) -> Result<SecurityStatus> {
        Ok(SecurityStatus::Ok)
    }

    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> Result<SecurityStatus> {
        todo!()
    }

    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], sequence_number: u32) -> Result<DecryptionFlags> {
        todo!()
    }

    fn query_context_sizes(&mut self) -> Result<ContextSizes> {
        Ok(ContextSizes {
            max_token: PACKAGE_INFO.max_token_len,
            max_signature: MAX_SIGNATURE as u32,
            block: 0,
            security_trailer: SECURITY_TRAILER as u32,
        })
    }

    fn query_context_names(&mut self) -> Result<ContextNames> {
        if let Some(ref identity_buffers) = self.auth_identity {
            let identity: AuthIdentity = identity_buffers.clone().into();
            Ok(ContextNames {
                username: identity.username,
                domain: identity.domain,
            })
        } else {
            Err(sspi::Error::new(
                sspi::ErrorKind::NoCredentials,
                String::from("Requested Names, but no credentials were provided"),
            ))
        }
    }

    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        sspi::query_security_package_info(SecurityPackageType::Pku2u)
    }

    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "Certificate trust status is not supported".to_owned(),
        ))
    }

    fn change_password(&mut self, _change_password: ChangePassword) -> Result<()> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "change_password is not supported in PKU2U".into(),
        ))
    }
}

impl SspiImpl for Pku2u {
    type CredentialsHandle = Option<AuthIdentityBuffers>;

    type AuthenticationData = AuthIdentity;

    fn acquire_credentials_handle_impl<'a>(
        &'a mut self,
        builder: crate::builders::FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> super::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        if builder.credential_use == CredentialUse::Outbound && builder.auth_data.is_none() {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                String::from("The client must specify the auth data"),
            ));
        }

        self.auth_identity = builder.auth_data.cloned().map(AuthIdentityBuffers::from);

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: self.auth_identity.clone(),
            expiry: None,
        })
    }

    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut crate::builders::FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> super::Result<InitializeSecurityContextResult> {
        let status = match self.state {
            Pku2uState::Negotiate => {
                let credentials = builder
                    .credentials_handle
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .ok_or_else(|| Error {
                        error_type: ErrorKind::NoCredentials,
                        description: "No credentials provided".to_owned(),
                    })?;

                let username = utf16_bytes_to_utf8_string(&credentials.user);

                let mut mech_token = Vec::new();

                let auth_scheme = Uuid::from_str(AUTH_SCHEME).unwrap();

                let nego = Nego::new(
                    MessageType::InitiatorNego,
                    self.conversation_id,
                    self.next_seq_number(),
                    OsRng::new()?.gen::<[u8; RANDOM_ARRAY_SIZE]>(),
                    vec![auth_scheme],
                    vec![],
                );
                nego.encode(&mut mech_token)?;

                let exchange = Exchange::new(
                    MessageType::InitiatorMetaData,
                    self.conversation_id,
                    self.next_seq_number(),
                    auth_scheme,
                    picky_asn1_der::to_vec(&generate_pku2u_nego_req(&username)?)?,
                );
                exchange.encode(&mut mech_token)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_token_init(mech_token)?)?)?;

                self.state = Pku2uState::Preauthentication;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::Preauthentication => todo!(),
            Pku2uState::ApExchange => todo!(),
            _ => {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    format!("Got wrong PKU2U state: {:?}", self.state),
                ))
            }
        };

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::empty(),
            expiry: None,
        })
    }

    fn accept_security_context_impl<'a>(
        &'a mut self,
        _builder: crate::builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> super::Result<AcceptSecurityContextResult> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "accept_security_context is not implemented in PKU2U".into(),
        ))
    }
}
