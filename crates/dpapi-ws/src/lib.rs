#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(clippy::large_futures)]

#[macro_use]
extern crate tracing;

mod gateway;

use std::env;
use std::io::Result;
use std::pin::Pin;

use url::Url;
use uuid::Uuid;

use crate::gateway::GatewayClient;

/// Authenticates to the proxy, obtains the needed session token, and returns
/// WS connection URL with the session token included in.
///
/// Paramers:
/// * `gatway_url` - proxy (Devolutions Gateway) address.
/// * `destination` - target RPC server address.
pub fn get_session_token(gateway_url: Url, destination: Url) -> Pin<Box<dyn Future<Output = Result<String>>>> {
    let webapp_token = env::var("DG_WEB_APP_TOKEN").unwrap();

    Box::pin(async move {
        Ok(GatewayClient::new(gateway_url)?
            .request_session_token(destination.as_str(), &webapp_token, Uuid::new_v4())
            .await?)
    })
}
