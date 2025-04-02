use dpapi::{Error, Result, WebAppAuth};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use url::Url;
use uuid::Uuid;

/// [AppTokenContentType](https://github.com/Devolutions/devolutions-gateway/blob/6e74bcc4256e5b6c67f798d3835b5277cc245633/devolutions-gateway/src/api/webapp.rs#L40-L42)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum AppTokenContentType {
    WebApp,
}

/// [AppTokenSignRequest](https://github.com/Devolutions/devolutions-gateway/blob/6e74bcc4256e5b6c67f798d3835b5277cc245633/devolutions-gateway/src/api/webapp.rs#L46-L56)
#[derive(Debug, Serialize, Deserialize)]
struct AppTokenSignRequest {
    /// The content type for the web app token.
    content_type: AppTokenContentType,
    /// The username used to request the app token.
    subject: String,
    /// The validity duration in seconds for the app token.
    ///
    /// This value cannot exceed the configured maximum lifetime.
    /// If no value is provided, the configured maximum lifetime will be granted.
    lifetime: Option<u64>,
}

/// [ApplicationProtocol](https://github.com/Devolutions/devolutions-gateway/blob/6e74bcc4256e5b6c67f798d3835b5277cc245633/devolutions-gateway/src/token.rs#L136-L139)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
enum ApplicationProtocol {
    Unknown(SmolStr),
}

/// [SessionTokenContentType](https://github.com/Devolutions/devolutions-gateway/blob/6e74bcc4256e5b6c67f798d3835b5277cc245633/devolutions-gateway/src/api/webapp.rs#L225-L257)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(tag = "content_type")]
enum SessionTokenContentType {
    Association {
        /// Protocol for the session (e.g.: "rdp")
        protocol: ApplicationProtocol,
        /// Destination host
        destination: String,
        /// Unique ID for this session
        session_id: Uuid,
    },
}

/// [SessionTokenSignRequest](https://github.com/Devolutions/devolutions-gateway/blob/6e74bcc4256e5b6c67f798d3835b5277cc245633/devolutions-gateway/src/api/webapp.rs#L260-L268)
#[derive(Debug, Serialize, Deserialize)]
struct SessionTokenSignRequest {
    /// The content type for the session token
    #[serde(flatten)]
    content_type: SessionTokenContentType,
    /// The validity duration in seconds for the session token
    ///
    /// This value cannot exceed 2 hours.
    lifetime: u64,
}

/// An HTTP Client that is used to request authentication tokens from a Devolutions Gateway WebApp.
pub struct GatewayWebAppHttpClient {
    client: Client,
    gateway_url: Url,
}

impl GatewayWebAppHttpClient {
    const WEB_APP_TOKEN_LIFETIME: u64 = 60 * 60 * 8;
    const SESSION_TOKEN_LIFETIME: u64 = 60 * 60;

    pub fn new(gateway_url: Url) -> Self {
        Self {
            client: Client::new(),
            gateway_url,
        }
    }

    /// Requests a web token from a Devolutions Gateway WebApp.
    pub async fn request_web_app_token(&self, web_app_auth: &WebAppAuth) -> Result<String> {
        let url = self.gateway_url.clone().join("jet/webapp/app-token")?;

        let mut request_builder = self.client.post(url);

        if let WebAppAuth::Custom { username, password } = web_app_auth {
            request_builder = request_builder.basic_auth(username, Some(password));
        }

        let username = if let WebAppAuth::Custom { username, .. } = web_app_auth {
            username.to_owned()
        } else {
            "DPAPI client".to_owned()
        };

        let token = request_builder
            .json(&AppTokenSignRequest {
                content_type: AppTokenContentType::WebApp,
                subject: username,
                lifetime: Some(Self::WEB_APP_TOKEN_LIFETIME),
            })
            .send()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::HttpRequest(e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))?;

        Ok(token)
    }

    /// Requests a session token from a Devolutions Gateway WebApp.
    pub async fn request_session_token(
        &self,
        destination: &str,
        web_app_token: &str,
        session_id: Uuid,
    ) -> Result<String> {
        let mut url = self.gateway_url.clone().join("jet/webapp/session-token")?;
        url.query_pairs_mut().append_pair("token", web_app_token);

        let token = self
            .client
            .post(url)
            .json(&SessionTokenSignRequest {
                content_type: SessionTokenContentType::Association {
                    protocol: ApplicationProtocol::Unknown(SmolStr::new_inline("DPAPI")),
                    destination: destination.to_owned(),
                    session_id,
                },
                lifetime: Self::SESSION_TOKEN_LIFETIME,
            })
            .send()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::HttpRequest(e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::HttpRequest(e.to_string()))?;

        Ok(token)
    }
}
