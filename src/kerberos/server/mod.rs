mod extractors;
mod generators;

use std::io::Write;

use picky::oids;
use picky_krb::data_types::AuthenticatorInner;
use time::{Duration, OffsetDateTime};

use self::extractors::{decode_neg_ap_req, decrypt_ap_req_authenticator, decrypt_ap_req_ticket, extract_tgt_req};
use self::generators::{generate_ap_rep, generate_final_neg_token_targ, generate_neg_token_targ};
use crate::builders::FilledAcceptSecurityContext;
use crate::kerberos::flags::ApOptions;
use crate::{
    AcceptSecurityContextResult, BufferType, Error, ErrorKind, Kerberos, KerberosState, Result, SecurityBuffer,
    SecurityStatus, ServerResponseFlags, SspiImpl,
};

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
pub fn accept_security_context_impl(
    server: &mut Kerberos,
    builder: FilledAcceptSecurityContext<'_, <Kerberos as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    let input = builder
        .input
        .as_ref()
        .ok_or_else(|| crate::Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;
    let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

    let status = match server.state {
        KerberosState::Negotiate => {
            let tgt_req = extract_tgt_req(&input_token.buffer)?;
            let tgt_rep = todo!();

            // TODO: negotiate krb oid and krb u2u.

            let encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_neg_token_targ(tgt_rep)?)?;

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer.write_all(&encoded_neg_token_targ)?;

            server.state = KerberosState::Preauthentication;

            SecurityStatus::ContinueNeeded
        }
        KerberosState::Preauthentication => {
            let ap_req = decode_neg_ap_req(&input_token.buffer)?;

            // TODO: check ap_req service name.

            let ticket_enc_part = decrypt_ap_req_ticket(todo!(), &ap_req)?;
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
            // TODO: make allowed time skew configurable
            let max_time_skew = Duration::minutes(3);

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

            info!("ApReq Ticket and Authenticator are valid!");

            let ap_options_bytes = ap_req.0.ap_options.0 .0.as_bytes();
            let ap_options =
                ApOptions::from_bits(u32::from_be_bytes(ap_options_bytes.try_into().map_err(|err| {
                    Error::new(ErrorKind::InvalidToken, format!("invalid ApReq ap-options: {:?}", err))
                })?))
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "invalid ApReq ap-options"))?;

            // [3.2.4.  Generation of a KRB_AP_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
            // ...the server need not explicitly reply to the KRB_AP_REQ. However, if mutual authentication is being performed,
            // the KRB_AP_REQ message will have MUTUAL-REQUIRED set in its ap-options field, and a KRB_AP_REP message
            // is required in response.
            if ap_options.contains(ApOptions::MUTUAL_REQUIRED) {
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
        KerberosState::ApExchange => SecurityStatus::Ok,
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
