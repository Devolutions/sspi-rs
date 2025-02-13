use thiserror::Error;

use crate::epm::{build_tcpip_tower, EptMap, EPM};
use crate::gkdi::ISD_KEY;
use crate::rpc::bind::{BindAck, BindTimeFeatureNegotiationBitmask, ContextElement, ContextResultCode};
use crate::rpc::request::Response;
use crate::rpc::verification::{Command, CommandFlags, CommandPContext, VerificationTrailer};
use crate::rpc::{bind_time_feature_negotiation, NDR, NDR64};
use crate::Result;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("BindAcknowledge doesn't contain desired context element")]
    MissingDesiredContext,
}

pub type ClientResult<T> = std::result::Result<T, ClientError>;

fn get_epm_contexts() -> Vec<ContextElement> {
    vec![ContextElement {
        context_id: 0,
        abstract_syntax: EPM,
        transfer_syntaxes: vec![NDR64],
    }]
}

fn get_isd_key_key_context() -> Vec<ContextElement> {
    vec![
        ContextElement {
            context_id: 0,
            abstract_syntax: ISD_KEY,
            transfer_syntaxes: vec![NDR64],
        },
        ContextElement {
            context_id: 1,
            abstract_syntax: ISD_KEY,
            transfer_syntaxes: vec![bind_time_feature_negotiation(BindTimeFeatureNegotiationBitmask::None)],
        },
    ]
}

fn get_ept_map_isd_key() -> EptMap {
    EptMap {
        obj: None,
        tower: build_tcpip_tower(ISD_KEY, NDR, 135, 0),
        entry_handle: None,
        max_towers: 4,
    }
}

fn get_verification_trailer() -> VerificationTrailer {
    VerificationTrailer {
        commands: vec![Command::Pcontext(CommandPContext {
            flags: CommandFlags::SecVtCommandEnd,
            interface_id: ISD_KEY,
            transfer_syntax: NDR64,
        })],
    }
}

fn process_bind_result(
    requested_contexts: &[ContextElement],
    bind_ack: BindAck,
    desired_context: u16,
) -> Result<()> {
    bind_ack
        .results
        .iter()
        .enumerate()
        .filter_map(|(index, result)| {
            if result.result == ContextResultCode::Acceptance {
                requested_contexts.get(index).map(|ctx| ctx.context_id)
            } else {
                None
            }
        })
        .find(|context_id| *context_id == desired_context)
        .ok_or(ClientError::MissingDesiredContext)?;

    Ok(())
}
