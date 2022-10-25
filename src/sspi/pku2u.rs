mod cert_utils;
mod config;
mod extractors;
mod generators;
#[macro_use]
mod macros;
mod validate;

use std::io::{Read, Write};
use std::str::FromStr;

pub use config::Pku2uConfig;
use lazy_static::lazy_static;
use picky_asn1_x509::signed_data::SignedData;
use picky_krb::constants::gss_api::{
    AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, AS_REP_TOKEN_ID, AS_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE,
};
use picky_krb::constants::key_usages::{ACCEPTOR_SIGN, INITIATOR_SIGN};
use picky_krb::crypto::diffie_hellman::{generate_key, DhNonce};
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use picky_krb::gss_api::{NegTokenInit, NegTokenTarg1, WrapToken};
use picky_krb::messages::{ApRep, ApReq, AsRep, AsReq};
use picky_krb::negoex::data_types::MessageType;
use picky_krb::negoex::messages::{Exchange, Nego, Verify};
use picky_krb::negoex::{NegoexMessage, RANDOM_ARRAY_SIZE};
use picky_krb::pkinit::PaPkAsRep;
use rand::rngs::OsRng;
use rand::Rng;
use uuid::Uuid;

use self::generators::{
    generate_client_dh_parameters, generate_neg, generate_neg_token_init, generate_neg_token_targ,
    generate_pa_datas_for_as_req, generate_pku2u_nego_req, generate_server_dh_parameters, DH_NONCE_LEN,
    WELLKNOWN_REALM,
};
use crate::builders::ChangePassword;
use crate::internal::SspiImpl;
use crate::kerberos::client::generators::{
    generate_ap_req, generate_as_req, generate_as_req_kdc_body, ChecksumOptions, GenerateAsReqOptions,
    GenerateAuthenticatorOptions, AUTHENTICATOR_DEFAULT_CHECKSUM,
};
use crate::kerberos::server::extractors::extract_sub_session_key_from_ap_rep;
use crate::kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE, MAX_SIGNATURE, RRC, SECURITY_TRAILER};
use crate::sspi::pku2u::cert_utils::validate_server_p2p_certificate;
use crate::sspi::pku2u::extractors::{
    compute_session_key_from_pa_pk_as_req, extract_krb_rep, extract_pa_pk_as_rep, extract_pa_pk_as_req,
    extract_server_dh_public_key, extract_server_nonce, extract_session_key_from_as_rep,
    extract_sub_session_key_from_ap_req,
};
use crate::sspi::pku2u::generators::{
    generate_ap_rep, generate_as_rep, generate_authenticator, generate_authenticator_extension,
    generate_neg_token_completed, generate_neg_token_init_s, generate_pa_datas_for_as_rep,
};
use crate::sspi::pku2u::validate::validate_signed_data;
use crate::sspi::{self, PACKAGE_ID_NONE};
use crate::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, AuthIdentity, AuthIdentityBuffers, CertTrustStatus,
    ClientResponseFlags, ContextNames, ContextSizes, CredentialUse, DecryptionFlags, EncryptionFlags, Error, ErrorKind,
    InitializeSecurityContextResult, PackageCapabilities, PackageInfo, Result, SecurityBuffer, SecurityBufferType,
    SecurityPackageType, SecurityStatus, ServerResponseFlags, Sspi, SspiEx,
};

pub const PKG_NAME: &str = "Pku2u";

pub const AZURE_AD_DOMAIN: &str = "AzureAD";

/// Default NEGOEX authentication scheme
pub const AUTH_SCHEME: &str = "0d53335c-f9ea-4d0d-b2ec-4ae3786ec308";

/// sealed = true
/// other flags = false
pub const CLIENT_WRAP_TOKEN_FLAGS: u8 = 2;
/// sealed = true
/// send by acceptor = true
/// acceptor subkey = false
pub const SERVER_WRAP_TOKEN_FLAGS: u8 = 3;

const DEFAULT_AP_REQ_OPTIONS: [u8; 4] = [0x20, 0x00, 0x00, 0x00];

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
enum Pku2uMode {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct DhParameters {
    // g
    base: Vec<u8>,
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
    mode: Pku2uMode,
    config: Pku2uConfig,
    state: Pku2uState,
    encryption_params: EncryptionParams,
    auth_identity: Option<AuthIdentityBuffers>,
    conversation_id: Uuid,
    auth_scheme: Option<Uuid>,
    seq_number: u32,
    dh_parameters: DhParameters,
    // all sent and received NEGOEX messages concatenated in one vector
    // we need it for the further checksum calculation
    // https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf
    // The checksum is performed on all previous NEGOEX messages in the context negotiation.
    negoex_messages: Vec<u8>,
    // all sent and received GSS-API messages concatenated in one vector
    // we need it for the further checksum calculation
    // https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-04#section-6
    // The checksum is performed on all previous NEGOEX messages in the context negotiation.
    gss_api_messages: Vec<u8>,
    negoex_random: [u8; RANDOM_ARRAY_SIZE],
}

impl Pku2u {
    pub fn new_server_from_config(config: Pku2uConfig) -> Result<Self> {
        let mut rng = OsRng::default();

        Ok(Self {
            mode: Pku2uMode::Server,
            config,
            state: Pku2uState::Preauthentication,
            encryption_params: EncryptionParams::default_for_server(),
            auth_identity: None,
            conversation_id: Uuid::default(),
            auth_scheme: Some(Uuid::from_str(AUTH_SCHEME).unwrap()),
            seq_number: 2,
            // https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3
            // Contains the nonce in the pkAuthenticator field in the request if the DH keys are NOT reused,
            // 0 otherwise.
            // generate dh parameters at the start in order to not waste time during authorization
            dh_parameters: generate_server_dh_parameters(&mut rng)?,
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random: rng.gen::<[u8; RANDOM_ARRAY_SIZE]>(),
        })
    }

    pub fn new_client_from_config(config: Pku2uConfig) -> Result<Self> {
        let mut rng = OsRng::default();

        Ok(Self {
            mode: Pku2uMode::Client,
            config,
            state: Pku2uState::Negotiate,
            encryption_params: EncryptionParams::default_for_client(),
            auth_identity: None,
            conversation_id: Uuid::new_v4(),
            auth_scheme: None,
            seq_number: 0,
            // https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3
            // Contains the nonce in the pkAuthenticator field in the request if the DH keys are NOT reused,
            // 0 otherwise.
            // generate dh parameters at the start in order to not waste time during authorization
            dh_parameters: generate_client_dh_parameters(&mut rng)?,
            negoex_messages: Vec::new(),
            gss_api_messages: Vec::new(),
            negoex_random: rng.gen::<[u8; RANDOM_ARRAY_SIZE]>(),
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
        sequence_number: u32,
    ) -> Result<SecurityStatus> {
        SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Token)?;
        let data = SecurityBuffer::find_buffer_mut(message, SecurityBufferType::Data)?;

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
                ErrorKind::EncryptFailure,
                "No encryption key provided".into(),
            ));
        };
        let key_usage = self.encryption_params.sspi_encrypt_key_usage;

        let mut wrap_token = WrapToken::with_seq_number(sequence_number as u64);
        wrap_token.flags = match self.mode {
            Pku2uMode::Client => CLIENT_WRAP_TOKEN_FLAGS,
            Pku2uMode::Server => SERVER_WRAP_TOKEN_FLAGS,
        };

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
            Ok(ContextNames {
                username: "s7@dataans.com".into(),
                domain: Some("AzureAD".into()),
            })
            // Err(sspi::Error::new(
            //     sspi::ErrorKind::NoCredentials,
            //     String::from("Requested Names, but no credentials were provided"),
            // ))
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

                let mut mech_token = Vec::new();

                let snames = check_if_empty!(builder.target_name, "service target name is not provided")
                    .split('/')
                    .collect();

                let nego = Nego::new(
                    MessageType::InitiatorNego,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.negoex_random.clone(),
                    vec![auth_scheme],
                    vec![],
                );
                nego.encode(&mut mech_token)?;

                let exchange = Exchange::new(
                    MessageType::InitiatorMetaData,
                    self.conversation_id,
                    self.next_seq_number(),
                    auth_scheme,
                    picky_asn1_der::to_vec(&generate_pku2u_nego_req(snames, &self.config)?)?,
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

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg".into())
                    })?
                    .0
                     .0;

                self.negoex_messages.extend_from_slice(&buffer);

                let mut reader: Box<dyn Read> = Box::new(buffer.as_slice());

                let acceptor_nego = Nego::decode(&mut reader, &buffer)?;

                check_conversation_id!(acceptor_nego.header.conversation_id.0, self.conversation_id);
                check_sequence_number!(acceptor_nego.header.sequence_num, self.next_seq_number());

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

                let acceptor_exchange_data = &buffer[(acceptor_nego.header.message_len as usize)..];
                let mut reader: Box<dyn Read> = Box::new(acceptor_exchange_data);
                let acceptor_exchange = Exchange::decode(&mut reader, acceptor_exchange_data)?;

                check_conversation_id!(acceptor_exchange.header.conversation_id.0, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme.0, self.auth_scheme);

                let mut mech_token = Vec::new();

                let snames = check_if_empty!(builder.target_name, "service target name is not provided")
                    .split('/')
                    .collect::<Vec<_>>();

                let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
                    realm: WELLKNOWN_REALM,
                    username: "AzureAD\\MS-Organization-P2P-Access [2022]\\S-1-12-1-3653211022-1339006422-2627573900-1560734919",
                    cname_type: 0x80,
                    snames: &snames,
                })?;
                let pa_datas = generate_pa_datas_for_as_req(
                    &self.config.p2p_certificate,
                    &kdc_req_body,
                    &self.dh_parameters,
                    &self.config.device_private_key,
                )?;

                let exchange_data =
                    picky_asn1_der::to_vec(&generate_neg(generate_as_req(&pa_datas, kdc_req_body), AS_REQ_TOKEN_ID))?;
                self.gss_api_messages.extend_from_slice(&exchange_data);

                let exchange = Exchange::new(
                    MessageType::ApRequest,
                    self.conversation_id,
                    self.next_seq_number(),
                    check_if_empty!(self.auth_scheme, "auth scheme is not set"),
                    exchange_data,
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let response_token = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(&response_token)?;

                self.state = Pku2uState::AsExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::AsExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into()))?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg".into())
                    })?
                    .0
                     .0;

                self.negoex_messages.extend_from_slice(&buffer);

                let acceptor_exchange = Exchange::decode(buffer.as_slice(), &buffer)?;

                check_conversation_id!(acceptor_exchange.header.conversation_id.0, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme.0, self.auth_scheme);

                self.gss_api_messages.extend_from_slice(&acceptor_exchange.exchange);

                let (as_rep, _): (AsRep, _) = extract_krb_rep(&acceptor_exchange.exchange)?;

                let dh_rep_info = match extract_pa_pk_as_rep(&as_rep)? {
                    PaPkAsRep::DhInfo(dh) => dh.0,
                    PaPkAsRep::EncKeyPack(_) => {
                        return Err(Error::new(
                            ErrorKind::OperationNotSupported,
                            "encKeyPack is not supported for the PA-PK-AS-REP".into(),
                        ))
                    }
                };

                let server_nonce = extract_server_nonce(&dh_rep_info)?;
                self.dh_parameters.server_nonce = Some(server_nonce);

                let signed_data: SignedData = picky_asn1_der::from_bytes(&dh_rep_info.dh_signed_data.0)?;

                let rsa_public_key = validate_server_p2p_certificate(&signed_data, &self.config.p2p_ca_certificate)?;
                validate_signed_data(&signed_data, &rsa_public_key)?;

                let public_key = extract_server_dh_public_key(&signed_data)?;
                self.dh_parameters.other_public_key = Some(public_key);

                self.encryption_params.encryption_type =
                    Some(CipherSuite::try_from(as_rep.0.enc_part.0.etype.0 .0.as_slice())?);
                self.encryption_params.session_key = Some(generate_key(
                    check_if_empty!(self.dh_parameters.other_public_key.as_ref(), "dh public key is not set"),
                    &self.dh_parameters.private_key,
                    &self.dh_parameters.modulus,
                    Some(DhNonce {
                        client_nonce: check_if_empty!(
                            self.dh_parameters.client_nonce.as_ref(),
                            "dh client none is not set"
                        ),
                        server_nonce: check_if_empty!(
                            self.dh_parameters.server_nonce.as_ref(),
                            "dh server nonce is not set"
                        ),
                    }),
                    check_if_empty!(
                        self.encryption_params.encryption_type.as_ref(),
                        "encryption type is not set"
                    )
                    .cipher()
                    .as_ref(),
                )?);

                self.encryption_params.session_key = Some(extract_session_key_from_as_rep(
                    &as_rep,
                    check_if_empty!(self.encryption_params.session_key.as_ref(), "session key is not set"),
                    &self.encryption_params,
                )?);

                let exchange_seq_number = self.next_seq_number();
                let verify_seq_number = self.next_seq_number();

                let authenticator_seb_key = OsRng::default().gen::<[u8; 32]>().to_vec();

                let authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                    kdc_rep: &as_rep.0,
                    seq_num: Some(exchange_seq_number),
                    sub_key: Some(authenticator_seb_key.clone()),
                    checksum: Some(ChecksumOptions {
                        checksum_type: AUTHENTICATOR_CHECKSUM_TYPE.to_vec(),
                        checksum_value: AUTHENTICATOR_DEFAULT_CHECKSUM.to_vec(),
                    }),
                    channel_bindings: None,
                    extensions: vec![generate_authenticator_extension(
                        &authenticator_seb_key,
                        &self.gss_api_messages,
                    )?],
                })?;
                let ap_req = generate_ap_req(
                    as_rep.0.ticket.0,
                    check_if_empty!(self.encryption_params.session_key.as_ref(), "session key is not set"),
                    &authenticator,
                    &self.encryption_params,
                    &DEFAULT_AP_REQ_OPTIONS,
                )?;

                let mut mech_token = Vec::new();

                let exchange = Exchange::new(
                    MessageType::ApRequest,
                    self.conversation_id,
                    exchange_seq_number,
                    check_if_empty!(self.auth_scheme, "auth_scheme is not set"),
                    picky_asn1_der::to_vec(&generate_neg(ap_req, AP_REQ_TOKEN_ID))?,
                );
                exchange.encode(&mut mech_token)?;

                exchange.encode(&mut self.negoex_messages)?;

                let verify = Verify::new(
                    MessageType::Verify,
                    self.conversation_id,
                    verify_seq_number,
                    check_if_empty!(self.auth_scheme, "auth_scheme is not set"),
                    ChecksumSuite::HmacSha196Aes256.into(),
                    ChecksumSuite::HmacSha196Aes256.hasher().checksum(
                        &authenticator_seb_key,
                        INITIATOR_SIGN,
                        &self.negoex_messages,
                    )?,
                );
                verify.encode(&mut mech_token)?;

                verify.encode(&mut self.negoex_messages)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token
                    .buffer
                    .write_all(&picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token)?)?)?;

                self.state = Pku2uState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::ApExchange => {
                let input = builder
                    .input
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into()))?;
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;

                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;

                // todo: check negResult (should be accept completed: 0)

                let buffer = neg_token_targ
                    .0
                    .response_token
                    .0
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InvalidToken, "Missing response_token in NegTokenTarg".into())
                    })?
                    .0
                     .0;

                let mut reader: Box<dyn Read> = Box::new(buffer.as_slice());
                let acceptor_exchange = Exchange::decode(&mut reader, &buffer)?;

                check_conversation_id!(acceptor_exchange.header.conversation_id.0, self.conversation_id);
                check_sequence_number!(acceptor_exchange.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_exchange.auth_scheme.0, self.auth_scheme);

                self.negoex_messages
                    .extend_from_slice(&buffer[0..(acceptor_exchange.header.message_len as usize)]);

                let acceptor_verify_data = &buffer[(acceptor_exchange.header.message_len as usize)..];
                let acceptor_verify = Verify::decode(acceptor_verify_data, acceptor_verify_data)?;

                check_conversation_id!(acceptor_verify.header.conversation_id.0, self.conversation_id);
                check_sequence_number!(acceptor_verify.header.sequence_num, self.next_seq_number());
                check_auth_scheme!(acceptor_verify.auth_scheme.0, self.auth_scheme);

                let (ap_rep, _): (ApRep, _) = extract_krb_rep(&acceptor_exchange.exchange)?;

                self.encryption_params.sub_session_key = Some(extract_sub_session_key_from_ap_rep(
                    &ap_rep,
                    check_if_empty!(self.encryption_params.session_key.as_ref(), "session key is not set"),
                    &self.encryption_params,
                )?);

                let acceptor_checksum = ChecksumSuite::try_from(acceptor_verify.checksum.checksum_type as usize)?
                    .hasher()
                    .checksum(
                        check_if_empty!(
                            self.encryption_params.sub_session_key.as_ref(),
                            "sub session key is not set"
                        ),
                        ACCEPTOR_SIGN,
                        &self.negoex_messages,
                    )?;
                if acceptor_verify.checksum.checksum_value != acceptor_checksum {
                    return Err(Error::new(
                        ErrorKind::MessageAltered,
                        "bad Verify message signature".into(),
                    ));
                }

                self.state = Pku2uState::PubKeyAuth;

                SecurityStatus::Ok
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
        builder: crate::builders::FilledAcceptSecurityContext<'a, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> super::Result<AcceptSecurityContextResult> {
        println!("accept_security_context_impl");
        let input = builder
            .input
            .ok_or_else(|| sspi::Error::new(ErrorKind::InvalidToken, "Input buffers must be specified".into()))?;

        let status = match &self.state {
            Pku2uState::Preauthentication => {
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                println!("server: nego buffer: {:?}", input_token);

                self.gss_api_messages.extend_from_slice(&input_token.buffer);

                println!("server: neg init token: {:?}", &input_token.buffer[16..]);
                let neg_token_init: NegTokenInit = picky_asn1_der::from_bytes(&input_token.buffer[16..]).unwrap();

                println!("server: neg init parsed: {:?}", neg_token_init);

                let data = neg_token_init.mech_token.0.unwrap().0 .0;

                let mut reader: Box<dyn Read> = Box::new(data.as_slice());

                self.negoex_messages.extend_from_slice(&data);

                let initiator_nego = Nego::decode(&mut reader, &data)?;

                let initiator_exchange_data = &data[(initiator_nego.header.message_len as usize)..];
                println!("server: acceptor_exchage data: {:?}", initiator_exchange_data);

                let mut reader: Box<dyn Read> = Box::new(initiator_exchange_data);

                let initiator_exchange = Exchange::decode(&mut reader, initiator_exchange_data)?;

                println!("server: acceptor_exchange: {:?}", initiator_exchange);

                self.conversation_id = initiator_nego.header.conversation_id.0;

                let mut mech_token = Vec::new();

                let auth_scheme = Uuid::from_str(AUTH_SCHEME).unwrap();

                let nego = Nego::new(
                    MessageType::AcceptorNego,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.negoex_random.clone(),
                    vec![auth_scheme],
                    vec![],
                );
                nego.encode(&mut mech_token)?;

                let exchange = Exchange::new(
                    MessageType::AcceptorMetaData,
                    self.conversation_id,
                    self.next_seq_number(),
                    auth_scheme,
                    vec![
                        48, 87, 160, 85, 48, 83, 48, 81, 128, 79, 48, 77, 49, 75, 48, 73, 6, 3, 85, 4, 3, 30, 66, 0,
                        77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0, 97, 0, 116, 0, 105,
                        0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115,
                        0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 50, 0, 93,
                    ],
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let result_token = picky_asn1_der::to_vec(&generate_neg_token_init_s(mech_token)?)?;
                self.gss_api_messages.extend_from_slice(&result_token);

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(&result_token)?;

                self.state = Pku2uState::AsExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::AsExchange => {
                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                println!("server: as exchange buffer:: {:?}", input_token);

                self.gss_api_messages.extend_from_slice(&input_token.buffer);

                let nego_token: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;

                let buffer = nego_token.0.response_token.0.unwrap().0 .0;

                self.negoex_messages.extend_from_slice(&buffer);

                let acceptor_exchange = Exchange::decode(buffer.as_slice(), &buffer)?;

                self.next_seq_number();

                let (as_req, _): (AsReq, _) = extract_krb_rep(&acceptor_exchange.exchange)?;
                println!("server: as_req parsed");
                let pa_pk_as_req = extract_pa_pk_as_req(&as_req)?;

                let mut f = std::fs::File::create("as_req_cert").unwrap();
                f.write_all(&acceptor_exchange.exchange).unwrap();

                let (session_key, dh_server_public) = compute_session_key_from_pa_pk_as_req(
                    &pa_pk_as_req,
                    self.dh_parameters.server_nonce.as_ref().unwrap(),
                )?;

                println!("dh session key: {:?}", session_key);

                self.encryption_params.session_key = Some(session_key);

                let new_key = vec![
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2,
                ];
                println!("server's session key: {:?}", new_key);

                let pa_datas = generate_pa_datas_for_as_rep(
                    &self.config.p2p_certificate,
                    self.dh_parameters.server_nonce.as_ref().unwrap(),
                    &dh_server_public,
                    &self.config.device_private_key,
                )?;
                let as_rep = generate_as_rep(
                    pa_datas,
                    self.encryption_params.session_key.as_ref().unwrap(),
                    new_key.clone(),
                )?;

                let exchange_data = picky_asn1_der::to_vec(&generate_neg(as_rep, AS_REP_TOKEN_ID))?;
                println!("exchange_data: {:?}", exchange_data);

                let mut mech_token = Vec::new();

                let exchange = Exchange::new(
                    MessageType::Challenge,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.auth_scheme.unwrap(),
                    exchange_data,
                );
                exchange.encode(&mut mech_token)?;

                self.negoex_messages.extend_from_slice(&mech_token);

                let response_token = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_token)?)?;
                self.gss_api_messages.extend_from_slice(&response_token);
                // println!("response_token: {:?}", response_token);

                self.encryption_params.session_key = Some(new_key);

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(&response_token)?;

                self.state = Pku2uState::ApExchange;

                SecurityStatus::ContinueNeeded
            }
            Pku2uState::ApExchange => {
                println!("server: ap exchange: {:?}", input);
                // println!("negoexmessages: {:?}", self.negoex_messages);
                let mut f = std::fs::File::create("negoex_messages.txt").unwrap();
                f.write_all(format!("{:?}", self.negoex_messages).as_bytes()).unwrap();

                let mut f = std::fs::File::create("gss_api_messages.txt").unwrap();
                f.write_all(format!("{:?}", self.gss_api_messages).as_bytes()).unwrap();

                // let new_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2];
                // println!("checksum: {:?}", ChecksumSuite::HmacSha196Aes256.hasher().checksum(&new_key, 41, &self.gss_api_messages));

                println!("ap_req: {:?}", input);

                let input_token = SecurityBuffer::find_buffer(input, SecurityBufferType::Token)?;
                println!("server: ap_req exchange buffer:: {:?}", input_token);

                // self.gss_api_messages.extend_from_slice(&input_token.buffer);

                let nego_token: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;

                let buffer = nego_token.0.response_token.0.unwrap().0 .0;

                let initiator_exchange = Exchange::decode(buffer.as_slice(), &buffer)?;

                self.next_seq_number();

                let initiator_verify_data = &buffer[(initiator_exchange.header.message_len as usize)..];
                println!("buffer for verify: {:?}", initiator_verify_data);

                let initiator_verify = Verify::decode(initiator_verify_data, initiator_verify_data)?;
                println!("initiator verify: {:?}", initiator_verify);

                self.negoex_messages
                    .extend_from_slice(&buffer[0..(initiator_exchange.header.message_len as usize)]);

                let (ap_req, _): (ApReq, _) = extract_krb_rep(&initiator_exchange.exchange)?;
                println!("ap_req: {:?}", ap_req);
                let sub_session_key =
                    extract_sub_session_key_from_ap_req(&ap_req, self.encryption_params.session_key.as_ref().unwrap())?;
                println!("ap_req authenticator key: {:?}", sub_session_key);
                if initiator_verify.checksum.checksum_value
                    != ChecksumSuite::HmacSha196Aes256
                        .hasher()
                        .checksum(&sub_session_key, 25, &self.negoex_messages)?
                {
                    println!("bad initiator checksum");
                } else {
                    println!("good initiator checksum");
                }

                self.negoex_messages
                    .extend_from_slice(&buffer[(initiator_exchange.header.message_len as usize)..]);

                self.next_seq_number();

                let test_sub_session_key = [
                    2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                ];
                self.encryption_params.sub_session_key = Some(test_sub_session_key.to_vec());
                println!("ap_rep enc part key: {:?}", test_sub_session_key);

                let ap_rep = generate_ap_rep(
                    self.encryption_params.session_key.as_ref().unwrap(),
                    // &sub_session_key,
                    &test_sub_session_key,
                );

                let mut mech_token = Vec::new();

                let exchange = Exchange::new(
                    MessageType::Challenge,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.auth_scheme.unwrap(),
                    picky_asn1_der::to_vec(&generate_neg(ap_rep, AP_REP_TOKEN_ID))?,
                );
                println!("exchange ap_rep: {:?}", exchange);
                exchange.encode(&mut mech_token)?;

                exchange.encode(&mut self.negoex_messages)?;

                // println!("negoex messages: {:?}", self.negoex_messages);

                let c2 = ChecksumSuite::HmacSha196Aes256.hasher().checksum(
                    &test_sub_session_key,
                    // self.encryption_params.session_key.as_ref().unwrap(),
                    23,
                    &self.negoex_messages,
                )?;

                let verify = Verify::new(
                    MessageType::Verify,
                    self.conversation_id,
                    self.next_seq_number(),
                    self.auth_scheme.unwrap(),
                    16,
                    c2,
                );
                verify.encode(&mut mech_token)?;

                verify.encode(&mut self.negoex_messages)?;

                let resp_token = picky_asn1_der::to_vec(&generate_neg_token_completed(mech_token)?)?;
                println!("resp_token: {:?}", resp_token);

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, SecurityBufferType::Token)?;
                output_token.buffer.write_all(&resp_token)?;

                self.state = Pku2uState::PubKeyAuth;

                SecurityStatus::ContinueNeeded
            }
            state => {
                println!("wow, I'm here: {:?}", state);

                SecurityStatus::CompleteNeeded
            }
        };

        Ok(AcceptSecurityContextResult {
            status,
            flags: ServerResponseFlags::empty(),
            expiry: None,
        })
    }
}

impl SspiEx for Pku2u {
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData) {
        self.auth_identity = Some(identity.into());
    }
}
