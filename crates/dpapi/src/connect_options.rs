use std::net::{SocketAddr, ToSocketAddrs};

use sspi::Secret;
use url::Url;

use crate::Result;

const DEFAULT_RPC_PORT: u16 = 135;

const WSS_SCHEME: &str = "wss";
const WS_SCHEME: &str = "ws";
const TCP_SCHEME: &str = "tcp";

#[derive(Debug, PartialEq)]
pub enum WebAppAuth {
    Custom { username: String, password: Secret<String> },
    None,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionUrlParseError {
    #[error("invalid URL: {0}")]
    InvalidUrl(&'static str),
}

/// RPC server connection options.
#[derive(Debug, PartialEq)]
pub enum ConnectionOptions {
    /// Regular TCP connection.
    Tcp(SocketAddr),
    /// Tunneled connection via Devolutions Gateway using a WebSocket.
    WebSocketTunnel {
        websocket_url: Url,
        web_app_auth: WebAppAuth,
        destination: SocketAddr,
    },
}

impl ConnectionOptions {
    pub fn parse(mut destination: Url, proxy: Option<Url>) -> Result<Self> {
        if destination.scheme().is_empty() {
            destination.set_scheme(TCP_SCHEME).expect("TCP_SCHEME value is valid");
        }

        if let Some(mut proxy) = proxy {
            match (proxy.scheme(), destination.scheme()) {
                (WS_SCHEME | WSS_SCHEME, TCP_SCHEME) => (),
                _ => {
                    return Err(ConnectionUrlParseError::InvalidUrl(
                        "WS proxy or target server URL scheme is invalid or unsupported",
                    )
                    .into())
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

                    WebAppAuth::Custom {
                        username,
                        password: password.into(),
                    }
                }
            };

            Ok(ConnectionOptions::WebSocketTunnel {
                websocket_url: proxy,
                web_app_auth,
                destination: url_to_socket_addr(destination)?,
            })
        } else {
            if destination.scheme() != TCP_SCHEME {
                return Err(ConnectionUrlParseError::InvalidUrl(
                    "WS proxy or target server URL scheme is invalid or unsupported",
                )
                .into());
            }

            Ok(ConnectionOptions::Tcp(url_to_socket_addr(destination)?))
        }
    }

    /// Sets the new port for the destination RPC server.
    pub fn set_destination_port(&mut self, new_port: u16) {
        match self {
            Self::Tcp(addr) => addr.set_port(new_port),
            Self::WebSocketTunnel {
                destination: tcp_addr, ..
            } => tcp_addr.set_port(new_port),
        }
    }
}

fn url_to_socket_addr(url: Url) -> Result<SocketAddr> {
    let tcp_host = url.host_str().ok_or(ConnectionUrlParseError::InvalidUrl(
        "destination URL does not contain a host",
    ))?;
    (tcp_host, url.port().unwrap_or(DEFAULT_RPC_PORT))
        .to_socket_addrs()?
        .next()
        .ok_or(ConnectionUrlParseError::InvalidUrl("cannot resolve the address of the TCP server").into())
}
