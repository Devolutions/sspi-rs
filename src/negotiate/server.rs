use std::mem;

use picky_krb::constants::gss_api::{ACCEPT_COMPLETE, ACCEPT_INCOMPLETE};
use picky_krb::gss_api::{NegTokenTarg, NegTokenTarg1};

use crate::builders::FilledAcceptSecurityContext;
use crate::generator::YieldPointLocal;
use crate::negotiate::NegotiateState;
use crate::negotiate::extractors::{decode_initial_neg_init, negotiate_mech_type};
use crate::negotiate::generators::{generate_final_neg_token_targ, generate_neg_token_targ, generate_neg_token_targ_1};
use crate::{
    AcceptSecurityContextResult, BufferType, Error, ErrorKind, Negotiate, Result, SecurityBuffer, SecurityStatus,
    ServerResponseFlags, SspiImpl,
};

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
#[instrument(ret, fields(protocol = negotiate.protocol_name()), skip_all)]
pub(crate) async fn accept_security_context(
    negotiate: &mut Negotiate,
    yield_point: &mut YieldPointLocal,
    mut builder: FilledAcceptSecurityContext<'_, <Negotiate as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    let input = builder
        .input
        .as_mut()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;

    let input_token = SecurityBuffer::find_buffer_mut(input, BufferType::Token)?;

    let status = match negotiate.state {
        NegotiateState::Initial => {
            let (mech_token, mech_types) = decode_initial_neg_init(&input_token.buffer)?;
            let (mech_type, mech_index) = negotiate_mech_type(&mech_types, negotiate)?;
            negotiate.mech_types = picky_asn1_der::to_vec(&mech_types)?;

            let encoded_neg_token_targ = if mech_index != 0 {
                // The selected mech type is not the most preferred one by client, so MIC token exchange is required according to RFC 4178.
                //
                // [RFC 4178 5. Processing of mechListMIC](https://www.rfc-editor.org/rfc/rfc4178.html#section-5):
                // > if the accepted mechanism is the most preferred mechanism of both the initiator and the acceptor,
                // > then the MIC token exchange is OPTIONAL.
                // > In all other cases, MIC tokens MUST be exchanged after the mechanism context is fully established.
                // > ...Note that the MIC token exchange is required if a mechanism other than
                // > the initiator's first choice is chosen.
                negotiate.mic_needed = true;
                negotiate.mic_verified = false;

                // The selected mech type is not the most preferred one by client, so we cannot use the token sent by the client.
                picky_asn1_der::to_vec(&generate_neg_token_targ(mech_type, None)?)?
            } else {
                // The selected mech type is the most preferred one by client, so we can use the token sent by the client.
                let response_token = if let Some(mut mech_token) = mech_token {
                    input_token.buffer = mem::take(&mut mech_token);

                    negotiate
                        .protocol
                        .accept_security_context(yield_point, &mut builder)
                        .await?;

                    let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

                    Some(mem::take(&mut output_token.buffer))
                } else {
                    None
                };

                picky_asn1_der::to_vec(&generate_neg_token_targ(mech_type, response_token)?)?
            };

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer = encoded_neg_token_targ;

            negotiate.state = NegotiateState::InProgress;

            SecurityStatus::ContinueNeeded
        }
        NegotiateState::InProgress => {
            let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
            let NegTokenTarg {
                neg_result: _,
                supported_mech: _,
                response_token,
                mech_list_mic,
            } = neg_token_targ.0;

            let input_token = SecurityBuffer::find_buffer_mut(input, BufferType::Token)?;
            let token = response_token.0.map(|token| token.0.0);
            if let Some(token) = token {
                input_token.buffer = token;
            } else {
                input_token.buffer.clear();
            }

            let mut result = negotiate
                .protocol
                .accept_security_context(yield_point, &mut builder)
                .await?;

            if result.status == SecurityStatus::Ok || result.status == SecurityStatus::CompleteNeeded {
                negotiate.state = NegotiateState::VerifyMic;
                result.status = SecurityStatus::ContinueNeeded;

                let mech_list_mic = mech_list_mic.0.map(|token| token.0.0);
                let neg_result = if mech_list_mic.is_some() || !negotiate.mic_needed {
                    negotiate.set_auth_identity()?;

                    negotiate.verify_mic_token(mech_list_mic.as_deref())?;

                    ACCEPT_COMPLETE.to_vec()
                } else {
                    ACCEPT_INCOMPLETE.to_vec()
                };

                prepare_final_neg_token(neg_result, negotiate, &mut builder)?;
            } else {
                // Wrap in a NegToken.
                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

                let spnego_token =
                    picky_asn1_der::to_vec(&generate_neg_token_targ_1(Some(mem::take(&mut output_token.buffer))))?;

                output_token.buffer = spnego_token;
            }

            result.status
        }
        NegotiateState::VerifyMic => {
            if !negotiate.mic_verified && negotiate.mic_needed {
                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let NegTokenTarg {
                    neg_result: _,
                    supported_mech: _,
                    response_token: _,
                    mech_list_mic,
                } = neg_token_targ.0;

                let mech_list_mic = mech_list_mic.0.map(|token| token.0.0);
                if mech_list_mic.is_some() {
                    negotiate.set_auth_identity()?;
                    negotiate.verify_mic_token(mech_list_mic.as_deref())?;
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidToken,
                        "mech_list_mic is not present in SPNEGO message",
                    ));
                }
            }

            SecurityStatus::Ok
        }
        _ => {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "initialize_security_context called after negotiation completed",
            ));
        }
    };

    Ok(AcceptSecurityContextResult {
        status,
        flags: ServerResponseFlags::empty(),
        expiry: None,
    })
}

fn prepare_final_neg_token(
    neg_result: Vec<u8>,
    negotiate: &mut Negotiate,
    builder: &mut FilledAcceptSecurityContext<'_, <Negotiate as SspiImpl>::CredentialsHandle>,
) -> Result<()> {
    let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

    let response_token = if !output_token.buffer.is_empty() {
        Some(mem::take(&mut output_token.buffer))
    } else {
        None
    };

    let mic = if negotiate.mic_needed {
        Some(
            negotiate
                .protocol
                .generate_mic_token(&negotiate.mech_types, crate::private::Sealed)?,
        )
    } else {
        None
    };

    let neg_token_targ = generate_final_neg_token_targ(neg_result, response_token, mic);

    let encoded_final_neg_token_targ = picky_asn1_der::to_vec(&neg_token_targ)?;

    output_token.buffer = encoded_final_neg_token_targ;

    Ok(())
}
