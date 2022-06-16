use std::fmt::Debug;

use url::Url;

use crate::sspi::Result;

pub trait NetworkClient: Debug {
    fn send(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>>;
    fn send_http(&self, url: &Url, data: &[u8], domain: Option<String>) -> Result<Vec<u8>>;
    fn clone(&self) -> Box<dyn NetworkClient>;
}

#[cfg(feature = "network_client")]
pub mod reqwest_network_client {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket};

    use byteorder::{BigEndian, ReadBytesExt};
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, OctetStringAsn1, Optional};
    use picky_krb::data_types::KerberosStringAsn1;
    use picky_krb::messages::KdcProxyMessage;
    use reqwest::blocking::Client;
    use url::Url;

    use super::NetworkClient;
    use crate::{Error, ErrorKind, Result};

    #[derive(Debug, Clone)]
    pub struct ReqwestNetworkClient;

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
                "udp" => {
                    let port = portpicker::pick_unused_port().ok_or_else(|| Error {
                        error_type: ErrorKind::InternalError,
                        description: "No free ports".into(),
                    })?;
                    let udp_socket = UdpSocket::bind((IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))?;

                    if data.len() < 4 {
                        return Err(Error::new(
                            ErrorKind::InternalError,
                            format!("kerb message has invalid length. expected >= 4 but got {}", data.len()),
                        ));
                    }
                    // first 4 bytes contains message length. we don't need it for UDP
                    udp_socket.send_to(&data[4..], url.as_str())?;

                    // 48 000 bytes: default maximum token len in Windows
                    let mut buff = vec![0; 0xbb80];

                    let n = udp_socket.recv(&mut buff)?;

                    let mut reply_buf = Vec::with_capacity(n + 4);
                    reply_buf.extend_from_slice(&(n as u32).to_be_bytes());
                    reply_buf.extend_from_slice(&buff[0..n]);

                    Ok(reply_buf)
                }
                scheme => Err(Error {
                    error_type: ErrorKind::InternalError,
                    description: format!("Invalid protocol for KDC server: {:?}. Expected only tcp/udp", scheme),
                }),
            }
        }

        fn send_http(&self, url: &Url, data: &[u8], domain: Option<String>) -> Result<Vec<u8>> {
            let client = Client::new();

            let domain = if let Some(domain) = domain {
                Some(ExplicitContextTag1::from(KerberosStringAsn1::from(
                    IA5String::from_string(domain)?,
                )))
            } else {
                None
            };

            let kdc_proxy_message = KdcProxyMessage {
                kerb_message: ExplicitContextTag0::from(OctetStringAsn1::from(data.to_vec())),
                target_domain: Optional::from(domain),
                dclocator_hint: Optional::from(None),
            };

            let result_bytes = client
                .post(url.clone())
                .body(picky_asn1_der::to_vec(&kdc_proxy_message)?)
                .send()
                .map_err(|err| Error {
                    error_type: ErrorKind::InternalError,
                    description: format!("Unable to send the data to the KDC Proxy: {:?}", err),
                })?
                .bytes()
                .map_err(|err| Error {
                    error_type: ErrorKind::InternalError,
                    description: format!("Unable to read the response data from the KDC Proxy: {:?}", err),
                })?
                .to_vec();

            let kdc_proxy_message: KdcProxyMessage = picky_asn1_der::from_bytes(&result_bytes)?;

            Ok(kdc_proxy_message.kerb_message.0 .0)
        }

        fn clone(&self) -> Box<dyn NetworkClient> {
            Box::new(Clone::clone(self))
        }
    }

    impl Default for ReqwestNetworkClient {
        fn default() -> Self {
            Self::new()
        }
    }
}
