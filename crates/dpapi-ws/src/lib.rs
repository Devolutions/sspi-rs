#![warn(clippy::large_futures)]

#[macro_use]
extern crate tracing;

mod webapp_http_client;

use std::io::{Error, ErrorKind};

use dpapi_transport::WebAppAuth;
use url::Url;
use uuid::Uuid;

use crate::webapp_http_client::GatewayWebAppHttpClient;

#[instrument(level = "trace", err)]
pub async fn prepare_ws_connection_url(
    gateway_url: Url,
    web_app_auth: &WebAppAuth,
    destination: &Url,
) -> Result<Url, Error> {
    let http_client = GatewayWebAppHttpClient::new(gateway_url.clone())?;

    let session_id = Uuid::new_v4();

    let web_app_token = http_client.request_web_app_token(web_app_auth).await?;

    info!("Web-app token has been asquired!");

    let session_token = http_client
        .request_session_token(destination.as_str(), &web_app_token, session_id)
        .await?;

    info!("Session token has been asquired!");

    let mut connection_url = gateway_url;

    if let Ok(mut segments) = connection_url.path_segments_mut() {
        segments.extend(&["jet", "fwd", "tcp", session_id.to_string().as_str()]);
    } else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("provided URL ({:?}) is `cannot-be-a-base`", connection_url),
        ));
    }

    connection_url
        .query_pairs_mut()
        .append_pair("token", session_token.as_str());

    Ok(connection_url)
}
