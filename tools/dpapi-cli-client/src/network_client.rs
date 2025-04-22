use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;

use dpapi::sspi::{network_client::AsyncNetworkClient, Error, ErrorKind, NetworkProtocol, NetworkRequest, Result};
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use url::Url;

#[derive(Debug)]
pub struct ReqwestNetworkClient {
    client: Option<Client>,
}

impl AsyncNetworkClient for ReqwestNetworkClient {
    fn send<'a>(&'a mut self, request: &'a NetworkRequest) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>> {
        Box::pin(async move {
            match &request.protocol {
                NetworkProtocol::Tcp => self.send_tcp(&request.url, &request.data).await,
                NetworkProtocol::Udp => self.send_udp(&request.url, &request.data).await,
                NetworkProtocol::Http | NetworkProtocol::Https => self.send_http(&request.url, &request.data).await,
            }
        })
    }
}

impl ReqwestNetworkClient {
    pub fn new() -> Self {
        Self { client: None }
    }
}

impl ReqwestNetworkClient {
    async fn send_tcp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
        let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));

        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, e))?;

        stream
            .write(data)
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, e))?;

        let len = stream
            .read_u32()
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, e))?;

        let mut buf = vec![0; len as usize + 4];
        buf[0..4].copy_from_slice(&(len.to_be_bytes()));

        stream
            .read_exact(&mut buf[4..])
            .await
            .map_err(|e| Error::new(ErrorKind::NoAuthenticatingAuthority, e))?;

        Ok(buf)
    }

    async fn send_udp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
        let udp_socket = UdpSocket::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;

        let addr = format!("{}:{}", url.host_str().unwrap_or_default(), url.port().unwrap_or(88));

        udp_socket.send_to(data, addr).await?;

        // 48 000 bytes: default maximum token len in Windows
        let mut buf = vec![0; 0xbb80];

        let n = udp_socket.recv(&mut buf).await?;

        let mut reply_buf = Vec::with_capacity(n + 4);
        reply_buf.extend_from_slice(&(n as u32).to_be_bytes());
        reply_buf.extend_from_slice(&buf[0..n]);

        Ok(reply_buf)
    }

    async fn send_http(&mut self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
        let client = self.client.get_or_insert_with(Client::new);

        let response = client
            .post(url.clone())
            .body(data.to_vec())
            .send()
            .await
            .map_err(|err| match err {
                err if err.to_string().to_lowercase().contains("certificate") => Error::new(
                    ErrorKind::CertificateUnknown,
                    format!("invalid certificate data: {:?}", err),
                ),
                _ => Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("unable to send the data to the KDC Proxy: {:?}", err),
                ),
            })?
            .error_for_status()
            .map_err(|err| Error::new(ErrorKind::NoAuthenticatingAuthority, format!("KDC Proxy: {err}")))?;

        let body = response.bytes().await.map_err(|err| {
            Error::new(
                ErrorKind::NoAuthenticatingAuthority,
                format!("unable to read the response data from the KDC Proxy: {:?}", err),
            )
        })?;

        // The type bytes::Bytes has a special From implementation for Vec<u8>.
        let body = Vec::from(body);

        Ok(body)
    }
}