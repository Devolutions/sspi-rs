use std::{
    io::{Read, Write},
    net::TcpStream,
};

use byteorder::{BigEndian, ReadBytesExt};
use url::Url;

use super::NetworkClient;
use crate::sspi::{Error, ErrorKind, Result};

pub struct ReqwestNetworkClient {}

impl ReqwestNetworkClient {
    pub fn new() -> Self {
        Self {}
    }
}

impl NetworkClient for ReqwestNetworkClient {
    fn send(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
        match url.scheme() {
            "tcp" => {
                let mut stream = TcpStream::connect(&format!(
                    "{}:{}",
                    url.clone().host_str().unwrap_or_default(),
                    url.port().unwrap_or(88)
                ))?;

                stream.write(data).map_err(|e| Error {
                    error_type: ErrorKind::InternalError,
                    description: format!("{:?}", e),
                })?;

                let len = stream.read_u32::<BigEndian>().map_err(|e| Error {
                    error_type: ErrorKind::InternalError,
                    description: format!("{:?}", e),
                })?;

                let mut buf = vec![0; len as usize + 4];
                buf[0..4].copy_from_slice(&(len.to_be_bytes()));

                stream.read_exact(&mut buf[4..]).map_err(|e| Error {
                    error_type: ErrorKind::InternalError,
                    description: format!("{:?}", e),
                })?;

                Ok(buf)
            }
            scheme => Err(Error {
                error_type: ErrorKind::InternalError,
                description: format!(
                    "Invalid protocol for KDC server: {:?}. Expected only tcp/udp",
                    scheme
                ),
            }),
        }
    }

    fn send_http(&self, _url: &Url, _data: &[u8]) -> Result<Vec<u8>> {
        todo!()
    }
}
