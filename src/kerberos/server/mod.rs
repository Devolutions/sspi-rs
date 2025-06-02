mod as_exchange;
mod extractors;
mod generators;

use std::io::Write;

use as_exchange::request_tgt;
use extractors::{extract_client_mic_token, extract_username, select_mech_type};
use generators::{generate_mic_token, generate_tgt_rep};
use picky::oids;
use picky_krb::constants::key_usages::INITIATOR_SIGN;
use picky_krb::data_types::{AuthenticatorInner, PrincipalName};
use picky_krb::gss_api::MechTypeList;
use rand::rngs::OsRng;
use rand::RngCore;
use time::{Duration, OffsetDateTime};

use self::extractors::{
    decode_initial_neg_init, decode_neg_ap_req, decrypt_ap_req_authenticator, decrypt_ap_req_ticket,
};
use self::generators::{generate_ap_rep, generate_final_neg_token_targ, generate_neg_token_targ};
use super::utils::validate_mic_token;
use crate::builders::FilledAcceptSecurityContext;
use crate::generator::YieldPointLocal;
use crate::kerberos::flags::ApOptions;
use crate::kerberos::DEFAULT_ENCRYPTION_TYPE;
use crate::{
    AcceptSecurityContextResult, BufferType, CredentialsBuffers, Error, ErrorKind, Kerberos, KerberosState, Result,
    SecurityBuffer, SecurityStatus, ServerRequestFlags, ServerResponseFlags, SspiImpl, Username,
};

/// Additional properties that are needed only for server-side Kerberos.
#[derive(Debug, Clone)]
pub struct ServerProperties {
    /// Supported mech types sent by the client in the first incoming message.
    /// We user them for checksum calculation during MIC token generation.
    pub mech_types: MechTypeList,
    /// Maximum allowed time difference between client and server clocks.
    /// It is recommended to set this value not greater then a few minutes.
    pub max_time_skew: Duration,
    /// Key that is used for TGS tickets decryption.
    /// It should be provided by the user during regular Kerberos auth. Or
    /// it will be established during AS exchange in the case of Kerberos U2U auth.
    pub ticket_decryption_key: Option<Vec<u8>>,
    /// Name of the Kerberos service.
    pub service_name: PrincipalName,
    /// User credentials on whose behalf the TGT ticket will be requested.
    pub user: Option<CredentialsBuffers>,
    /// Username of the authenticated client.
    ///
    /// This field should be set by the Kerberos implementation after successful log on.
    pub client: Option<Username>,
}

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
pub async fn accept_security_context(
    server: &mut Kerberos,
    yield_point: &mut YieldPointLocal,
    builder: FilledAcceptSecurityContext<'_, <Kerberos as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    let input = builder
        .input
        .as_ref()
        .ok_or_else(|| crate::Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;
    let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

    let status = match server.state {
        KerberosState::Negotiate => {
            let (tgt_req, mech_types) = decode_initial_neg_init(&input_token.buffer)?;
            let mech_type = select_mech_type(&mech_types)?;

            let server_props = server.server.as_mut().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidHandle,
                    "Kerberos server properties are not initialized",
                )
            })?;
            server_props.mech_types = mech_types;

            let tgt_rep = if let Some(tgt_req) = tgt_req {
                // If user sent us TgtReq than they want Kerberos User-to-User auth.
                // At this point, we need to request TGT token in KDC and send it back to the user.

                if !builder
                    .context_requirements
                    .contains(ServerRequestFlags::USE_SESSION_KEY)
                {
                    warn!("KRB5 U2U has been negotiated (requested by the client) but the USE_SESSION_KEY flag is not set.");
                }

                server.krb5_user_to_user = true;

                let credentials = builder
                    .credentials_handle
                    .map(|credentials_handle| (*credentials_handle).clone())
                    .unwrap();
                let credentials = credentials.or_else(|| server_props.user.clone());
                let credentials = credentials.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorKind::WrongCredentialHandle,
                        "failed to request TGT ticket: no credentials provided",
                    )
                })?;

                Some(generate_tgt_rep(
                    request_tgt(server, credentials, &tgt_req, yield_point).await?,
                ))
            } else {
                None
            };

            let encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_type, tgt_rep)?)?;

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer.write_all(&encoded_neg_token_targ)?;

            server.state = KerberosState::Preauthentication;

            SecurityStatus::ContinueNeeded
        }
        KerberosState::Preauthentication => {
            let ap_req = decode_neg_ap_req(&input_token.buffer)?;

            let server_data = server.server.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidHandle,
                    "Kerberos server properties are not initialized",
                )
            })?;

            let ticket_service_name = &ap_req.0.ticket.0 .0.sname.0;
            if *ticket_service_name != server_data.service_name {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!(
                        "invalid ticket service name ({:?}): Kerberos server is configured for {:?}",
                        ticket_service_name, server_data.service_name
                    ),
                ));
            }

            let ticket_decryption_key = server_data
                .ticket_decryption_key
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "ticket decryption key is not set"))?;

            let ticket_enc_part = decrypt_ap_req_ticket(ticket_decryption_key, &ap_req)?;
            server.encryption_params.session_key = Some(ticket_enc_part.key.0.key_value.0 .0.clone());
            let session_key = server
                .encryption_params
                .session_key
                .as_ref()
                .expect("session key should be set");

            let AuthenticatorInner {
                authenticator_vno: _,
                crealm,
                cname,
                cksum: _,
                cusec,
                ctime,
                subkey: _,
                seq_number: _,
                authorization_data: _,
            } = decrypt_ap_req_authenticator(session_key, &ap_req)?.0;

            // [3.2.3.  Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
            // The name and realm of the client from the ticket are compared against the same fields in the authenticator.
            if ticket_enc_part.crealm.0 != crealm.0 || ticket_enc_part.cname != cname.0 {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "the name and realm of the client in ticket and authenticator do not match",
                ));
            }

            let now = OffsetDateTime::now_utc();
            let client_time = OffsetDateTime::try_from(ctime.0 .0.clone())
                .map_err(|err| Error::new(ErrorKind::InvalidToken, format!("clint time is not valid: {:?}", err)))?;
            let max_time_skew = server_data.max_time_skew;

            if (now - client_time).abs() > max_time_skew {
                return Err(Error::new(
                    ErrorKind::TimeSkew,
                    "invalid authenticator ctime: time skew is too big",
                ));
            }

            // TODO: authenticators cache.

            let ticket_start_time = OffsetDateTime::try_from(
                ticket_enc_part
                    .starttime
                    .0
                    .map(|start_time| start_time.0)
                    // [5.3.  Tickets](https://www.rfc-editor.org/rfc/rfc4120#section-5.3)
                    // If the starttime field is absent from the ticket, then the authtime field SHOULD be used in its place to determine
                    // the life of the ticket.
                    .unwrap_or_else(|| ticket_enc_part.auth_time.0)
                    .0,
            )
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("ticket end time is not valid: {:?}", err),
                )
            })?;
            if ticket_start_time > now + max_time_skew {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "ticket not yet valid: ticket start time is greater than current time + max time skew",
                ));
            }

            let ticket_end_time = OffsetDateTime::try_from(ticket_enc_part.endtime.0 .0).map_err(|err| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("ticket end time is not valid: {:?}", err),
                )
            })?;
            if now > ticket_end_time + max_time_skew {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "ticket is expired: current time is greater than ticket end time + max time skew",
                ));
            }

            debug!("ApReq Ticket and Authenticator are valid!");

            let server_data = server.server.as_mut().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidHandle,
                    "Kerberos server properties are not initialized",
                )
            })?;
            server_data.client = Some(Username::new_upn(
                &extract_username(&cname.0)?,
                &crealm.0 .0.to_string().to_ascii_lowercase(),
            )?);

            let ap_options_bytes = ap_req.0.ap_options.0 .0.as_bytes();
            // [5.5.1.  KRB_AP_REQ Definition](https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1)
            // The `ap-options` field has 32 bits or 4 bytes long. But it is encoded as BitStringAsn1, so the first byte
            // indicates the number of bits used. Thus, the overall number of expected bytes is 1 + 4 = 5.
            if ap_options_bytes.len() != 1 + 4 {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!(
                        "invalid ApReq ap-options: invalid data length: expected 5 bytes but got {}",
                        ap_options_bytes.len()
                    ),
                ));
            }
            let ap_options =
                ApOptions::from_bits(u32::from_be_bytes(ap_options_bytes[1..].try_into().map_err(|err| {
                    Error::new(ErrorKind::InvalidToken, format!("invalid ApReq ap-options: {:?}", err))
                })?))
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "invalid ApReq ap-options"))?;

            // [3.2.4.  Generation of a KRB_AP_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
            // ...the server need not explicitly reply to the KRB_AP_REQ. However, if mutual authentication is being performed,
            // the KRB_AP_REQ message will have MUTUAL-REQUIRED set in its ap-options field, and a KRB_AP_REP message
            // is required in response.
            if ap_options.contains(ApOptions::MUTUAL_REQUIRED) {
                let key_size = server
                    .encryption_params
                    .encryption_type
                    .as_ref()
                    .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
                    .cipher()
                    .key_size();
                let mut sub_session_key = vec![0; key_size];
                OsRng.fill_bytes(&mut sub_session_key);
                server.encryption_params.sub_session_key = Some(sub_session_key);

                // [3.2.4.  Generation of a KRB_AP_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
                // A subkey MAY be included if the server desires to negotiate a different subkey.
                // The KRB_AP_REP message is encrypted in the session key extracted from the ticket.
                let ap_rep = generate_ap_rep(
                    session_key,
                    ctime.0,
                    cusec.0,
                    (server.seq_number + 1).to_be_bytes().to_vec(),
                    &server.encryption_params,
                )?;

                let mic = generate_mic_token(
                    u64::from(server.seq_number + 1),
                    picky_asn1_der::to_vec(
                        &server
                            .server
                            .as_ref()
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorKind::InvalidHandle,
                                    "Kerberos server properties are not initialized",
                                )
                            })?
                            .mech_types,
                    )?,
                    server
                        .encryption_params
                        .sub_session_key
                        .as_ref()
                        .expect("sub-session key should present"),
                )?;

                let mech_id = if server.krb5_user_to_user {
                    oids::krb5_user_to_user()
                } else {
                    oids::krb5()
                };

                let encoded_neg_ap_rep = picky_asn1_der::to_vec(&generate_final_neg_token_targ(mech_id, ap_rep, mic)?)?;

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer.write_all(&encoded_neg_ap_rep)?;
            }

            server.state = KerberosState::ApExchange;

            SecurityStatus::ContinueNeeded
        }
        KerberosState::ApExchange => {
            let client_mic = extract_client_mic_token(&input_token.buffer)?;
            validate_mic_token(&client_mic, INITIATOR_SIGN, &server.encryption_params)?;

            server.state = KerberosState::PubKeyAuth;

            SecurityStatus::Ok
        }
        _ => {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("got wrong Kerberos state: {:?}", server.state),
            ))
        }
    };

    Ok(AcceptSecurityContextResult {
        status,
        flags: ServerResponseFlags::empty(),
        expiry: None,
    })
}
