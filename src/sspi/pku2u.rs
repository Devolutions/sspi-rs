mod extractors;
mod generators;
#[macro_use]
mod macros;

use std::io::{Read, Write};
use std::str::FromStr;

use lazy_static::lazy_static;
use picky_asn1_x509::signed_data::SignedData;
use picky_asn1_x509::Certificate;
use picky_krb::constants::gss_api::{AS_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE, AP_REQ_TOKEN_ID};
use picky_krb::constants::key_usages::ACCEPTOR_SIGN;
use picky_krb::crypto::{CipherSuite, ChecksumSuite, Checksum};
use picky_krb::diffie_hellman::{generate_key, DhNonce};
use picky_krb::gss_api::WrapToken;
use picky_krb::negoex::data_types::MessageType;
use picky_krb::negoex::messages::{Exchange, Nego, Verify};
use picky_krb::negoex::{NegoexMessage, RANDOM_ARRAY_SIZE};
use picky_krb::pkinit::PaPkAsRep;
use rand::rngs::OsRng;
use rand::Rng;
use uuid::Uuid;

use self::generators::{
    generate_client_dh_parameters, generate_neg, generate_neg_token_init, generate_neg_token_targ,
    generate_pa_datas_for_as_req, generate_pku2u_nego_req, DH_NONCE_LEN, WELLKNOWN_REALM,
};
use crate::builders::ChangePassword;
use crate::internal::SspiImpl;
use crate::kerberos::client::generators::{
    generate_ap_req, generate_as_req, generate_as_req_kdc_body, generate_authenticator, ChecksumOptions,
    GenerateAsReqOptions, GenerateAuthenticatorOptions, AUTHENTICATOR_DEFAULT_CHECKSUM,
};
use crate::kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE, MAX_SIGNATURE, RRC, SECURITY_TRAILER, SERVICE_NAME};
use crate::sspi::pku2u::extractors::{
    extract_as_rep, extract_pa_pk_as_rep, extract_server_dh_public_key, extract_server_nonce,
};
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
    AsExchange,
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
pub struct DhParameters {
    // g
    base: usize,
    // p
    modulus: Vec<u8>,
    //
    q: Vec<u8>,
    // generated private key
    private_key: Vec<u8>,
    // received public key
    other_public_key: Option<Vec<u8>>,
    client_nonce: Option<[u8; DH_NONCE_LEN]>,
    server_nonce: Option<[u8; DH_NONCE_LEN]>,
}

#[derive(Debug, Clone)]
pub struct Pku2u {
    config: Pku2uConfig,
    state: Pku2uState,
    encryption_params: EncryptionParams,
    auth_identity: Option<AuthIdentityBuffers>,
    conversation_id: Uuid,
    auth_scheme: Option<Uuid>,
    seq_number: u32,
    realm: Option<String>,
    auth_nonce: u32,
    dh_parameters: DhParameters,
    // all sent and received NEGOEX messages in one vector
    // we need it for the further checksum calculation
    // https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf
    // The checksum is performed on all previous NEGOEX messages in the context negotiation.
    negoex_messages: Vec<u8>,
}

impl Pku2u {
    pub fn new_client_from_config(config: Pku2uConfig) -> Result<Self> {
        Ok(Self {
            config,
            state: Pku2uState::Negotiate,
            encryption_params: EncryptionParams::default_for_client(),
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            realm: None,
            // https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3
            // Contains the nonce in the pkAuthenticator field in the request if the DH keys are NOT reused,
            // 0 otherwise.
            auth_nonce: 0,
            // generate dh parameters at the start in order to not waste time during authorization
            dh_parameters: generate_client_dh_parameters(),
            negoex_messages: Vec::new(),
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
        _flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        _sequence_number: u32,
    ) -> Result<SecurityStatus> {
        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        let seq_number = self.next_seq_number();

        // the sub-session key is always preferred over the session key
        let key = if let Some(key) = self.encryption_params.sub_session_key.as_ref() {
            key
        } else if let Some(key) = self.encryption_params.session_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::EncryptFailure,
                "No encryption key provided".into(),
            ));
        };
        let key_usage = self.encryption_params.sspi_encrypt_key_usage;

        let mut wrap_token = WrapToken::with_seq_number(seq_number as u64);

        let mut payload = data.buffer.to_vec();
        payload.extend_from_slice(&wrap_token.header());

        let mut checksum = cipher.encrypt(key, key_usage, &payload)?;
        checksum.rotate_right(RRC.into());

        wrap_token.set_rrc(RRC);
        wrap_token.set_checksum(checksum);

        let mut raw_wrap_token = Vec::with_capacity(92);
        wrap_token.encode(&mut raw_wrap_token)?;

        match self.state {
            Pku2uState::PubKeyAuth | Pku2uState::Credentials => {
                *data.buffer.as_mut() = raw_wrap_token[SECURITY_TRAILER..].to_vec();
                let header = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
                *header.buffer.as_mut() = raw_wrap_token[0..SECURITY_TRAILER].to_vec();
            }
            _ => {
                return Err(Error {
                    error_type: ErrorKind::OutOfSequence,
                    description: "Kerberos context is not established or finished".to_owned(),
                })
            }
        };

        Ok(SecurityStatus::Ok)
    }

    fn decrypt_message(&mut self, message: &mut [SecurityBuffer], _sequence_number: u32) -> Result<DecryptionFlags> {
        let mut encrypted = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?
            .buffer
            .clone();
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

        encrypted.extend_from_slice(&data.buffer);

        let cipher = self
            .encryption_params
            .encryption_type
            .as_ref()
            .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
            .cipher();

        // the sub-session key is always preferred over the session key
        let key = if let Some(key) = self.encryption_params.sub_session_key.as_ref() {
            key
        } else if let Some(key) = self.encryption_params.session_key.as_ref() {
            key
        } else {
            return Err(Error::new(
                ErrorKind::DecryptFailure,
                "No encryption key provided".into(),
            ));
        };
        let key_usage = self.encryption_params.sspi_decrypt_key_usage;

        let mut wrap_token = WrapToken::decode(encrypted.as_slice())?;

        wrap_token.checksum.rotate_left(RRC.into());

        let mut decrypted = cipher.decrypt(key, key_usage, &wrap_token.checksum)?;
        // remove wrap token header
        decrypted.truncate(decrypted.len() - WrapToken::header_len());

        match self.state {
            Pku2uState::PubKeyAuth => {
                self.state = Pku2uState::Credentials;

                *data.buffer.as_mut() = decrypted;
                Ok(DecryptionFlags::empty())
            }
            Pku2uState::Credentials => {
                self.state = Pku2uState::Final;

                *data.buffer.as_mut() = decrypted;
                Ok(DecryptionFlags::empty())
            }
            _ => {
                *data.buffer.as_mut() = decrypted;
                Ok(DecryptionFlags::empty())
            }
        }
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
                let auth_scheme = Uuid::from_str(AUTH_SCHEME).unwrap();

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

                self.negoex_messages.extend_from_slice(&mech_token);

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_token_init(mech_token)?)?)?;

                self.state = Pku2uState::Preauthentication;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::Preauthentication => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into()))?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let buffer = input_token.buffer.as_slice();

                self.negoex_messages.extend_from_slice(buffer);

                let mut reader: Box<dyn Read> = Box::new(buffer);

                let acceptor_nego = Nego::decode(&mut reader, &input_token.buffer)?;

                check_conversation_id!(acceptor_nego.header.conversation_id.0, self.conversation_id);

                // We support only one auth scheme. So the server must choose it otherwise it's an invalid behaviour
                if let Some(auth_scheme) = acceptor_nego.auth_schemes.get(0) {
                    if auth_scheme.0 == Uuid::from_str(AUTH_SCHEME).unwrap() {
                        self.auth_scheme = Some(auth_scheme.0);
                    } else {
                        return
                        Err(Error::new(
                            ErrorKind::InvalidToken,
                            format!(
                                "The server selected unsupported auth scheme {:?}. The only one supported auth scheme: {}",
                                auth_scheme.0, AUTH_SCHEME)
                        ));
                    }
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "Server didn't send any auth scheme".into(),
                    ));
                }

                let acceptor_exchange = Exchange::decode(
                    &mut reader,
                    &input_token.buffer[(acceptor_nego.header.message_len as usize)..],
                )?;

                check_conversation_id!(acceptor_exchange.header.conversation_id.0, self.conversation_id);
                check_auth_scheme!(acceptor_exchange.auth_scheme.0, self.auth_scheme);

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
                // todo: parse response. do not extract any data. just parse and make sure it valid

                let mut mech_token = Vec::new();

                let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
                    realm: WELLKNOWN_REALM,
                    username: &username,
                    cname_type: 0x80,
                    snames: &[SERVICE_NAME, &username],
                })?;
                let pa_datas = generate_pa_datas_for_as_req(
                    &self.config.p2p_certificate,
                    &self.config.p2p_ca_certificate,
                    &kdc_req_body,
                    self.auth_nonce,
                    &self.dh_parameters,
                )?;

                let exchange = Exchange::new(
                    MessageType::InitiatorMetaData,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.auth_scheme.unwrap(),
                    picky_asn1_der::to_vec(&generate_neg(generate_as_req(&pa_datas, kdc_req_body), AS_REQ_TOKEN_ID))?,
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token)?)?)?;

                self.state = Pku2uState::AsExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::AsExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into()))?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let buffer = input_token.buffer.as_slice();

                self.negoex_messages.extend_from_slice(buffer);

                let acceptor_exchange = Exchange::decode(buffer, &input_token.buffer)?;

                check_conversation_id!(acceptor_exchange.header.conversation_id.0, self.conversation_id);
                check_auth_scheme!(acceptor_exchange.auth_scheme.0, self.auth_scheme);

                let as_rep = extract_as_rep(&acceptor_exchange.exchange)?;

                // todo: validate server's certificate

                let dh_rep_info = match extract_pa_pk_as_rep(&as_rep)? {
                    PaPkAsRep::DhInfo(dh) => dh.0,
                    PaPkAsRep::EncKeyPack(_) => {
                        return Err(Error::new(
                            ErrorKind::OperationNotSupported,
                            "encKeyPack is not supported for the PA-PK-AS-REP".into(),
                        ))
                    }
                };

                self.dh_parameters.server_nonce = Some(extract_server_nonce(&dh_rep_info)?);

                let signed_data: SignedData = picky_asn1_der::from_bytes(&dh_rep_info.dh_signed_data.0)?;

                self.dh_parameters.other_public_key = Some(extract_server_dh_public_key(&signed_data)?);

                self.encryption_params.encryption_type =
                    Some(CipherSuite::try_from(as_rep.0.enc_part.0.etype.0 .0.as_slice())?);
                self.encryption_params.session_key = Some(generate_key(
                    self.dh_parameters.other_public_key.as_ref().unwrap(),
                    &self.dh_parameters.private_key,
                    &self.dh_parameters.modulus,
                    Some(DhNonce {
                        client_nonce: self.dh_parameters.client_nonce.as_ref().unwrap(),
                        server_nonce: self.dh_parameters.server_nonce.as_ref().unwrap(),
                    }),
                    self.encryption_params
                        .encryption_type
                        .as_ref()
                        .unwrap()
                        .cipher()
                        .as_ref(),
                )?);

                let authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                    kdc_rep: &as_rep.0,
                    seq_num: Some(self.next_seq_number()),
                    sub_key: Some(OsRng::new()?.gen::<[u8; 32]>().to_vec()),
                    checksum: Some(ChecksumOptions {
                        checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                        checksum_value: AUTHENTICATOR_DEFAULT_CHECKSUM.to_vec(),
                    }),
                    channel_bindings: None,
                })?;
                let ap_req = generate_ap_req(
                    as_rep.0.ticket.0,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    &authenticator,
                    &self.encryption_params,
                    &[2, 0, 0, 0],
                )?;

                let mut mech_token = Vec::new();

                let exchange = Exchange::new(
                    MessageType::InitiatorMetaData,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.auth_scheme.unwrap(),
                    picky_asn1_der::to_vec(&generate_neg(ap_req, AP_REQ_TOKEN_ID))?,
                );
                exchange.encode(&mut mech_token)?;

                let verify = Verify::new(
                    MessageType::Verify,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.auth_scheme.unwrap(),
                    self.encryption_params.encryption_type
                        .as_ref()
                        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
                        .into(),
                    ChecksumSuite::HmacSha196Aes256.hasher().checksum(
                        self.encryption_params.session_key.as_ref().unwrap(),
                        ACCEPTOR_SIGN,
                        &self.negoex_messages,
                    )?,
                );
                verify.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token)?)?)?;

                self.state = Pku2uState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::ApExchange => {
                // todo!();

                self.state = Pku2uState::PubKeyAuth;

                SecurityStatus::ContinueNeeded
            }
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
