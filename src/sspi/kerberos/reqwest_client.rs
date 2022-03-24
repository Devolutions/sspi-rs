use std::{
    io::{Read, Write},
    net::TcpStream,
};

use byteorder::{BigEndian, ReadBytesExt};

use super::{NetworkClient, NetworkClientError};

pub struct ReqwestNetworkClient {}

impl ReqwestNetworkClient {
    pub fn new() -> Self {
        Self {}
    }
}

impl NetworkClient for ReqwestNetworkClient {
    fn send(&self, url: url::Url, data: &[u8]) -> Result<Vec<u8>, NetworkClientError> {
        match url.scheme() {
            "tcp" => {
                let mut stream = TcpStream::connect(&format!(
                    "{}:{}",
                    url.clone().host_str().unwrap_or_default(),
                    url.port().unwrap_or(88)
                ))?;

                stream.write(data)?;

                let len = stream.read_u32::<BigEndian>()?;

                let mut buf = vec![0; len as usize + 4];
                buf[0..4].copy_from_slice(&(len.to_be_bytes()));

                stream.read_exact(&mut buf[4..])?;

                Ok(buf)
            }
            scheme => Err(NetworkClientError::UrlError(format!(
                "scheme is not supported: {}",
                scheme
            ))),
        }
    }

    fn send_http(&self, url: url::Url, data: &[u8]) -> Result<Vec<u8>, NetworkClientError> {
        todo!()
    }
}
