use std::net::SocketAddr;

use dpapi::client::{WS_SCHEME, WSS_SCHEME, WebAppAuth};
use dpapi::{Error, Result};
use url::Url;
use uuid::Uuid;

use crate::webapp_http_client::GatewayWebAppHttpClient;

mod webapp_http_client;

pub async fn prepare_ws_request_for_gateway_webapp(
    ws_request: &Url,
    web_app_auth: &WebAppAuth,
    destination: &SocketAddr,
) -> Result<Url> {
    let is_secure = match ws_request.scheme() {
        WSS_SCHEME => true,
        WS_SCHEME => false,
        _ => {
            return Err(Error::InvalidUrl {
                url: ws_request.to_string(),
                description: format!("invalid URL scheme for WebSocket: {}", ws_request.scheme()),
            });
        }
    };

    let host = ws_request.host_str().ok_or(Error::InvalidUrl {
        url: ws_request.to_string(),
        description: "host has to be specified".to_owned(),
    })?;

    let port = ws_request.port().ok_or(Error::InvalidUrl {
        url: ws_request.to_string(),
        description: "port has to be specified".to_owned(),
    })?;

    let http_client = GatewayWebAppHttpClient::new(host, port, is_secure);

    let session_id = Uuid::new_v4();

    let web_app_token = http_client.request_web_app_token(web_app_auth).await?;
    let session_token = http_client
        .request_session_token(&destination.to_string(), &web_app_token, session_id)
        .await?;

    let mut ws_request_owned = ws_request.clone();

    ws_request_owned
        .path_segments_mut()
        .map_err(|_| Error::InvalidUrl {
            url: ws_request.to_string(),
            description: "URL is `cannot-be-a-base`".to_owned(),
        })?
        .push(session_id.to_string().as_str());

    ws_request_owned
        .query_pairs_mut()
        .append_pair("token", session_token.as_str());

    Ok(ws_request_owned)
}
