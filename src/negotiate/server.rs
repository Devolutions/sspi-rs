use std::mem;

use picky_krb::constants::gss_api::{ACCEPT_COMPLETE, ACCEPT_INCOMPLETE};
use picky_krb::gss_api::{NegTokenTarg, NegTokenTarg1};

use crate::builders::FilledAcceptSecurityContext;
use crate::generator::YieldPointLocal;
use crate::negotiate::extractors::{decode_initial_neg_init, select_mech_type};
use crate::negotiate::generators::{generate_final_neg_token_targ, generate_neg_token_targ, generate_neg_token_targ_1};
use crate::negotiate::NegotiateState;
use crate::{
    AcceptSecurityContextResult, BufferType, EmptyAcceptSecurityContext, Error, ErrorKind, Negotiate,
    NegotiatedProtocol, Result, SecurityBuffer, SecurityStatus, ServerResponseFlags, SspiImpl,
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

    let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

    let status = match negotiate.state {
        NegotiateState::Initial => {
            let (tgt_req, mech_types) = decode_initial_neg_init(&input_token.buffer)?;
            let mech_type = select_mech_type(&mech_types)?;
            negotiate.mech_types = mech_types;

            let mut encoded_neg_token_targ = picky_asn1_der::to_vec(&generate_neg_token_targ(mech_type, None)?)?;

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer = mem::take(&mut encoded_neg_token_targ);

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
            let token = response_token.0.map(|token| token.0 .0);
            if let Some(token) = token {
                input_token.buffer = token;
            } else {
                input_token.buffer.clear();
            }

            let mut output_tokens = builder.output.to_vec();
            let mut input_tokens = input.to_vec();

            let mut result = match &mut negotiate.protocol {
                NegotiatedProtocol::Pku2u(pku2u) => {
                    let mut creds_handle = builder
                        .credentials_handle
                        .as_ref()
                        .and_then(|creds| (*creds).clone())
                        .and_then(|creds_handle| creds_handle.auth_identity());
                    let new_builder: FilledAcceptSecurityContext<'_, Option<crate::AuthIdentityBuffers>> =
                        EmptyAcceptSecurityContext::new()
                            .with_context_requirements(builder.context_requirements)
                            .with_target_data_representation(builder.target_data_representation)
                            .with_input(&mut input_tokens)
                            .with_output(&mut output_tokens)
                            .with_credentials_handle(&mut creds_handle);
                    pku2u.accept_security_context_impl(yield_point, new_builder).await?
                }
                NegotiatedProtocol::Kerberos(kerberos) => {
                    let mut creds_handle = builder.credentials_handle.as_ref().and_then(|creds| (*creds).clone());
                    let new_builder = EmptyAcceptSecurityContext::new()
                        .with_context_requirements(builder.context_requirements)
                        .with_target_data_representation(builder.target_data_representation)
                        .with_input(&mut input_tokens)
                        .with_output(&mut output_tokens)
                        .with_credentials_handle(&mut creds_handle);
                    kerberos.accept_security_context_impl(yield_point, new_builder).await?
                }
                NegotiatedProtocol::Ntlm(ntlm) => {
                    let mut creds_handle = builder
                        .credentials_handle
                        .as_ref()
                        .and_then(|creds| (*creds).clone())
                        .and_then(|creds_handle| creds_handle.auth_identity());
                    let new_builder = EmptyAcceptSecurityContext::new()
                        .with_credentials_handle(&mut creds_handle)
                        .with_context_requirements(builder.context_requirements)
                        .with_target_data_representation(builder.target_data_representation)
                        .with_input(&mut input_tokens)
                        .with_output(&mut output_tokens);
                    ntlm.accept_security_context_impl(new_builder)?
                }
            };

            let output_token = SecurityBuffer::find_buffer_mut(&mut output_tokens, BufferType::Token)?;
            let ot = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            ot.buffer = output_token.buffer.clone();

            if result.status == SecurityStatus::Ok || result.status == SecurityStatus::CompleteNeeded {
                negotiate.state = NegotiateState::VerifyMic;
                result.status = SecurityStatus::ContinueNeeded;

                let mech_list_mic = mech_list_mic.0.map(|token| token.0 .0);
                let neg_result = if let Some(mech_list_mic) = mech_list_mic {
                    let mech_types = picky_asn1_der::to_vec(&negotiate.mech_types)?;

                    negotiate.set_auth_identity()?;
                    negotiate.protocol.validate_mic_token(&mech_list_mic, &mech_types)?;

                    negotiate.mic_verified = true;

                    ACCEPT_COMPLETE.to_vec()
                } else {
                    ACCEPT_INCOMPLETE.to_vec()
                };

                prepare_final_neg_token(neg_result, negotiate, &mut builder)?;

                trace!(?builder.output, "outbuilderdata");
            } else {
                // Wrap in a NegToken.
                let ot = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;

                let spnego_token = picky_asn1_der::to_vec(&generate_neg_token_targ_1(Some(mem::take(&mut ot.buffer))))?;

                ot.buffer = spnego_token;
            }

            result.status
        }
        NegotiateState::VerifyMic => {
            if !negotiate.mic_verified {
                let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&input_token.buffer)?;
                let NegTokenTarg {
                    neg_result: _,
                    supported_mech: _,
                    response_token: _,
                    mech_list_mic,
                } = neg_token_targ.0;

                let mech_list_mic = mech_list_mic.0.map(|token| token.0 .0);
                if let Some(mech_list_mic) = mech_list_mic {
                    let mech_types = picky_asn1_der::to_vec(&negotiate.mech_types)?;

                    negotiate.set_auth_identity()?;
                    negotiate.protocol.validate_mic_token(&mech_list_mic, &mech_types)?;

                    negotiate.mic_verified = true;
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
            ))
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

    let mech_types = picky_asn1_der::to_vec(&negotiate.mech_types)?;
    let neg_token_targ = generate_final_neg_token_targ(
        neg_result,
        response_token,
        negotiate.protocol.generate_mic_token(&mech_types)?,
    );

    let encoded_final_neg_token_targ = picky_asn1_der::to_vec(&neg_token_targ)?;

    output_token.buffer = encoded_final_neg_token_targ;

    Ok(())
}
