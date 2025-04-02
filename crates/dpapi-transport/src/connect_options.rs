use thiserror::Error;
use url::Url;

pub const DEFAULT_RPC_PORT: u16 = 135;

const WSS_SCHEME: &str = "wss";
const WS_SCHEME: &str = "ws";
const TCP_SCHEME: &str = "tcp";

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid URL: {0}")]
    InvalidUrl(&'static str),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum WebAppAuth {
    Custom { username: String, password: String },
    None,
}

/// RPC server connection options.
#[derive(Debug, PartialEq)]
pub enum ConnectionOptions {
    /// Regular TCP connection.
    Tcp(Url),
    /// Tunneled connection via Devolutions Gateway using a WebSocket.
    WebSocketTunnel {
        websocket_url: Url,
        web_app_auth: WebAppAuth,
        destination: Url,
    },
}

impl ConnectionOptions {
    pub fn new(destination: &str, proxy: Option<Url>) -> Result<Self> {
        let mut destination = Url::parse(&if destination.contains("://") {
            destination.to_owned()
        } else {
            format!("tcp://{destination}")
        })?;

        if destination.scheme().is_empty() {
            destination.set_scheme(TCP_SCHEME).expect("TCP_SCHEME value is valid");
        }
        if destination.port().is_none() {
            destination
                .set_port(Some(DEFAULT_RPC_PORT))
                .expect("URL isn't `cannot-be-a-base`, so it should not fail");
        }

        if let Some(mut proxy) = proxy {
            match (proxy.scheme(), destination.scheme()) {
                (WS_SCHEME | WSS_SCHEME, TCP_SCHEME) => (),
                _ => {
                    return Err(Error::InvalidUrl(
                        "WS proxy or target server URL scheme is invalid or unsupported",
                    ));
                }
            }

            let web_app_auth = match proxy.username() {
                "" => WebAppAuth::None,
                username => {
                    let username = username.to_owned();
                    let password = proxy.password().unwrap_or_default().to_owned();

                    proxy
                        .set_username("")
                        .expect("URL isn't `cannot-be-a-base`, so it should not fail");
                    proxy
                        .set_password(None)
                        .expect("URL isn't `cannot-be-a-base`, so it should not fail");

                    WebAppAuth::Custom { username, password }
                }
            };

            Ok(ConnectionOptions::WebSocketTunnel {
                websocket_url: proxy,
                web_app_auth,
                destination,
            })
        } else {
            if destination.scheme() != TCP_SCHEME {
                return Err(Error::InvalidUrl(
                    "WS proxy or target server URL scheme is invalid or unsupported",
                ));
            }

            Ok(ConnectionOptions::Tcp(destination))
        }
    }

    /// Sets the new port for the destination RPC server.
    pub fn set_destination_port(&mut self, new_port: u16) {
        match self {
            Self::Tcp(addr) => addr.set_port(Some(new_port)),
            Self::WebSocketTunnel {
                destination: tcp_addr, ..
            } => tcp_addr.set_port(Some(new_port)),
        }
        .expect("URL isn't `cannot-be-a-base`, so it should not fail");
    }
}
