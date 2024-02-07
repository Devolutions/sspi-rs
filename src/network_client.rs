use std::fmt::Debug;

use crate::generator::NetworkRequest;
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Http,
    Https,
}

impl NetworkProtocol {
    pub const ALL: &'static [Self] = &[Self::Tcp, Self::Udp, Self::Http, Self::Https];

    pub(crate) fn from_url_scheme(scheme: &str) -> Option<Self> {
        match scheme {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }
}

pub trait NetworkClient: Send + Sync {
    /// Send request to the server and return the response. URL scheme is guaranteed to be
    /// the same as specified by `protocol` argument. `sspi-rs` will call this method only if
    /// `NetworkClient::is_protocol_supported` returned true prior to the call, so unsupported
    /// `protocol` values could be marked as `unreachable!`.
    fn send(&self, request: &NetworkRequest) -> Result<Vec<u8>>;
}

#[cfg(feature = "network_client")]
pub mod reqwest_network_client {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket};

    use byteorder::{BigEndian, ReadBytesExt};
    use reqwest::blocking::Client;
    use url::Url;

    use super::{NetworkClient, NetworkProtocol};
    use crate::generator::NetworkRequest;
    use crate::{Error, ErrorKind, Result};

    #[derive(Debug, Clone, Default)]
    pub struct ReqwestNetworkClient;

    impl ReqwestNetworkClient {
        fn send_tcp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));
            let mut stream = TcpStream::connect(addr)
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e)))?;

            stream
                .write(data)
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e)))?;

            let len = stream
                .read_u32::<BigEndian>()
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e)))?;

            let mut buf = vec![0; len as usize + 4];
            buf[0..4].copy_from_slice(&(len.to_be_bytes()));

            stream
                .read_exact(&mut buf[4..])
                .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e)))?;

            Ok(buf)
        }

        fn send_udp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            let port =
                portpicker::pick_unused_port().ok_or_else(|| Error::new(ErrorKind::InternalError, "No free ports"))?;
            let udp_socket = UdpSocket::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), port))?;

            let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));
            udp_socket.send_to(data, addr)?;

            // 48 000 bytes: default maximum token len in Windows
            let mut buf = vec![0; 0xbb80];

            let n = udp_socket.recv(&mut buf)?;

            let mut reply_buf = Vec::with_capacity(n + 4);
            reply_buf.extend_from_slice(&(n as u32).to_be_bytes());
            reply_buf.extend_from_slice(&buf[0..n]);

            Ok(reply_buf)
        }

        fn send_http(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            let client = Client::new();

            let response = client
                .post(url.clone())
                .body(data.to_vec())
                .send()
                .map_err(|err| match err {
                    err if err.to_string().to_lowercase().contains("certificate") => Error::new(
                        ErrorKind::CertificateUnknown,
                        format!("Invalid certificate data: {:?}", err),
                    ),
                    _ => Error::new(
                        ErrorKind::NoAuthenticatingAuthority,
                        format!("Unable to send the data to the KDC Proxy: {:?}", err),
                    ),
                })?
                .error_for_status()
                .map_err(|err| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("KDC Proxy: {err}")))?;

            let body = response.bytes().map_err(|err| {
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("Unable to read the response data from the KDC Proxy: {:?}", err),
                )
            })?;

            // The type bytes::Bytes has a special From implementation for Vec<u8>.
            let body = Vec::from(body);

            Ok(body)
        }
    }

    impl NetworkClient for ReqwestNetworkClient {
        fn send(&self, request: &NetworkRequest) -> Result<Vec<u8>> {
            match request.protocol {
                NetworkProtocol::Tcp => self.send_tcp(&request.url, &request.data),
                NetworkProtocol::Udp => self.send_udp(&request.url, &request.data),
                NetworkProtocol::Http | NetworkProtocol::Https => self.send_http(&request.url, &request.data),
            }
        }
    }
}
