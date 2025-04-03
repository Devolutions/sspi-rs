use thiserror::Error;
use url::Url;

/// Default port for RPC communication.
pub const DEFAULT_RPC_PORT: u16 = 135;

const WSS_SCHEME: &str = "wss";
const WS_SCHEME: &str = "ws";
const TCP_SCHEME: &str = "tcp";

/// An error returned
#[derive(Debug, Error)]
pub enum Error {
    /// The RPC server (destination) or proxy URL is invalid.
    #[error("invalid URL: {0}")]
    InvalidUrl(&'static str),

    /// Failed to parse URL.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
}

pub type Result<T> = core::result::Result<T, Error>;

/// Authentication data.
#[derive(Debug, PartialEq)]
pub enum WebAppAuth {
    /// Password based authentication.
    Custom {
        /// Name of the user for proxy authentication.
        username: String,
        /// User's password.
        password: String,
    },

    /// No authentication data is needed.
    None,
}

/// Target server connection options.
#[derive(Debug, PartialEq)]
pub enum ConnectionOptions {
    /// Regular TCP connection. Contains target RPC server address.
    Tcp(Url),

    /// Tunneled connection via Devolutions Gateway using a WebSocket.
    WsTunnel {
        /// Devolutions Gateway address.
        websocket_url: Url,

        /// Authentication data.
        web_app_auth: WebAppAuth,

        /// Target RPC server address.
        destination: Url,
    },
}

impl ConnectionOptions {
    /// Constructs a new [ConnectionOptions] object.
    ///
    /// Parameters:
    /// * `destination` - target RPC server URL.
    /// * `proxy` - optional Devilution Gateway URl.
    ///
    /// Returns an error if the provided URLs are not valid.
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

            Ok(ConnectionOptions::WsTunnel {
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
            Self::WsTunnel {
                destination: tcp_addr, ..
            } => tcp_addr.set_port(Some(new_port)),
        }
        .expect("URL isn't `cannot-be-a-base`, so it should not fail");
    }
}
