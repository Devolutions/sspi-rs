use thiserror::Error;

use crate::rpc::bind::{BindAck, ContextElement, ContextResultCode};
use crate::rpc::request::{Response};
use crate::Result;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("BindAcknowledge doesn't contain desired context element")]
    MissingDesiredContext,
}

pub type ClientResult<T> = std::result::Result<T, ClientError>;

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
