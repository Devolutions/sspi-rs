use std::future::Future;
use std::pin::Pin;

use thiserror::Error;
use url::Url;
use uuid::Uuid;

/// Type that represents a function for obtaining the sesion token.
///
/// We need it because we don't know the destination address in advance.
///
/// Parameters:
/// * `Uuid` is the session id.
/// * `Url` is the destination of the proxied connection.
pub type GetSessionTokenFn = dyn Fn(Uuid, Url) -> Pin<Box<dyn Future<Output = std::io::Result<String>>>>;

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

/// Target server connection options.
pub enum ConnectOptions {
    /// Regular TCP connection. Contains target RPC server address.
    Tcp(Url),

    /// Tunneled connection via Devolutions Gateway using a WebSocket.
    WsTunnel {
        /// Devolutions Gateway address.
        proxy: Url,
        /// Target RPC server address.
        destination: Url,
        /// Callback for obtaining proxy session token.
        get_session_token: Box<GetSessionTokenFn>,
    },
}

/// Proxy connection options.
pub struct ProxyOptions {
    /// Devolutions Gateway address.
    pub proxy: Url,
    /// Callback for obtaining proxy session token.
    pub get_session_token: Box<GetSessionTokenFn>,
}

impl ConnectOptions {
    /// Constructs a new [ConnectOptions] object.
    ///
    /// Parameters:
    /// * `destination` - target RPC server URL.
    /// * `proxy_options` - proxying options.
    ///
    /// Returns an error if the provided URLs are not valid.
    pub fn new(destination: &str, proxy_options: Option<ProxyOptions>) -> Result<Self> {
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

        if let Some(ProxyOptions {
            proxy,
            get_session_token,
        }) = proxy_options
        {
            match (proxy.scheme(), destination.scheme()) {
                (WS_SCHEME | WSS_SCHEME, TCP_SCHEME) => (),
                _ => {
                    return Err(Error::InvalidUrl(
                        "WS proxy or target server URL scheme is invalid or unsupported",
                    ));
                }
            }

            Ok(ConnectOptions::WsTunnel {
                proxy,
                destination,
                get_session_token,
            })
        } else {
            if destination.scheme() != TCP_SCHEME {
                return Err(Error::InvalidUrl(
                    "WS proxy or target server URL scheme is invalid or unsupported",
                ));
            }

            Ok(ConnectOptions::Tcp(destination))
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
