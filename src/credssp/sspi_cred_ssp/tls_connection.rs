use std::io::{Read, Write};

use picky_asn1_x509::Certificate;
use rustls::{Connection, ProtocolVersion};

use crate::{
    ConnectionCipher, ConnectionHash, ConnectionInfo, ConnectionKeyExchange, ConnectionProtocol, Error, ErrorKind,
    Result, StreamSizes,
};

// type + version + length
pub const TLS_PACKET_HEADER_LEN: usize = 1 /* ContentType */ + 2 /* ProtocolVersion */ + 2 /* length: uint16 */;
// [Block Size and Padding](https://www.rfc-editor.org/rfc/rfc3826#section-3.1.1.3)
// The block size of the AES cipher is 128 bits
const AES_BLOCK_SIZE: usize = 16;

// [Processing Events and Sequencing Rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
// The CredSSP server does not request the client's X.509 certificate (thus far, the client is anonymous).
// Also, the CredSSP Protocol does not require the client to have a commonly trusted certification authority root with the CredSSP server.
//
// This configuration just accepts any certificate
pub mod danger {
    use std::time::SystemTime;

    use rustls::client::{ServerCertVerified, ServerCertVerifier};
    use rustls::{Certificate, Error, ServerName};

    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[derive(Debug)]
pub enum TlsConnection {
    Rustls(Connection),
    // Schannel
}

impl TlsConnection {
    pub fn encrypt_tls(&mut self, plain_data: &[u8]) -> Result<Vec<u8>> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let mut writer = tls_connection.writer();
                let _bytes_written = writer.write(plain_data)?;

                let mut tls_buffer = Vec::new();
                let _bytes_written = tls_connection.write_tls(&mut tls_buffer)?;

                Ok(tls_buffer)
            }
        }
    }

    pub fn decrypt_tls(&mut self, mut payload: &[u8]) -> Result<Vec<u8>> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let mut plain_data = Vec::with_capacity(payload.len());

                while payload.len() != 0 {
                    let _tls_bytes_read = tls_connection.read_tls(&mut payload)?;

                    let tls_state = tls_connection
                        .process_new_packets()
                        .map_err(|err| Error::new(ErrorKind::DecryptFailure, err.to_string()))?;

                    let mut reader = tls_connection.reader();
                    let mut decrypted = vec![0; tls_state.plaintext_bytes_to_read()];
                    let _plain_data_len = reader.read(&mut decrypted)?;

                    plain_data.extend_from_slice(&decrypted);
                }
                Ok(plain_data)
            }
        }
    }

    pub fn peer_certificates(&self) -> Result<Vec<&[u8]>> {
        match self {
            TlsConnection::Rustls(tls_connection) => tls_connection
                .peer_certificates()
                .map(|certificates| certificates.iter().map(|cert| cert.as_ref()).collect())
                .ok_or_else(|| Error::new(ErrorKind::CertificateUnknown, "The server certificate is not present")),
        }
    }

    pub fn process_tls_packets(&mut self, mut input_token: &[u8]) -> Result<(usize, Vec<u8>)> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                if !input_token.is_empty() {
                    let _bytes_read = tls_connection.read_tls(&mut input_token)?;
                }

                let _io_status = tls_connection
                    .process_new_packets()
                    .map_err(|err| Error::new(ErrorKind::EncryptFailure, err.to_string()))?;

                let mut tls_buffer = Vec::new();
                let bytes_written = tls_connection.write_tls(&mut tls_buffer)?;

                Ok((bytes_written, tls_buffer))
            }
        }
    }

    pub fn stream_sizes(&self) -> Result<StreamSizes> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let connection_cipher = tls_connection
                    .negotiated_cipher_suite()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "Connection cipher is not negotiated"))?;

                let bulk_cipher = match connection_cipher {
                    rustls::SupportedCipherSuite::Tls12(cipher_suite) => &cipher_suite.common.bulk,
                    rustls::SupportedCipherSuite::Tls13(cipher_suite) => &cipher_suite.common.bulk,
                };
                let block_size = match bulk_cipher {
                    rustls::BulkAlgorithm::Aes128Gcm => AES_BLOCK_SIZE,
                    rustls::BulkAlgorithm::Aes256Gcm => AES_BLOCK_SIZE,
                    // ChaCha20 is a stream cipher
                    rustls::BulkAlgorithm::Chacha20Poly1305 => 0,
                };

                Ok(StreamSizes {
                    header: TLS_PACKET_HEADER_LEN as u32,
                    // trailer = tls mac + padding
                    // this value is taken from the win schannel
                    trailer: 0x2c,
                    // this value is taken from the win schannel
                    max_message: 0x4000,
                    // MSDN: message must contain four buffers
                    // https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
                    buffers: 4,
                    block_size: block_size as u32,
                })
            }
        }
    }

    pub fn connection_info(&self) -> Result<ConnectionInfo> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let protocol_version = tls_connection.protocol_version().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidParameter,
                        "Can not acquire connection protocol version",
                    )
                })?;

                let protocol = match tls_connection {
                    Connection::Client(_) => match protocol_version {
                        ProtocolVersion::SSLv2 => ConnectionProtocol::SpProtSsl2Client,
                        ProtocolVersion::TLSv1_0 => ConnectionProtocol::SpProtTls1Client,
                        ProtocolVersion::TLSv1_1 => ConnectionProtocol::SpProtTls1_1Client,
                        ProtocolVersion::TLSv1_2 => ConnectionProtocol::SpProtTls1_2Client,
                        ProtocolVersion::TLSv1_3 => ConnectionProtocol::SpProtTls1_3Client,
                        version => {
                            return Err(Error::new(
                                ErrorKind::InternalError,
                                format!("Unsupported connection protocol was used: {:?}", version),
                            ));
                        }
                    },
                    Connection::Server(_) => match protocol_version {
                        ProtocolVersion::SSLv2 => ConnectionProtocol::SpProtSsl2Server,
                        ProtocolVersion::TLSv1_0 => ConnectionProtocol::SpProtTls1Server,
                        ProtocolVersion::TLSv1_1 => ConnectionProtocol::SpProtTls1_1Server,
                        ProtocolVersion::TLSv1_2 => ConnectionProtocol::SpProtTls1_2Server,
                        ProtocolVersion::TLSv1_3 => ConnectionProtocol::SpProtTls1_3Server,
                        version => {
                            return Err(Error::new(
                                ErrorKind::InternalError,
                                format!("Unsupported connection protocol was used: {:?}", version),
                            ));
                        }
                    },
                };

                let connection_cipher = tls_connection
                    .negotiated_cipher_suite()
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "Connection cipher is not negotiated"))?;

                let bulk_cipher = match connection_cipher {
                    rustls::SupportedCipherSuite::Tls12(cipher_suite) => &cipher_suite.common.bulk,
                    rustls::SupportedCipherSuite::Tls13(cipher_suite) => &cipher_suite.common.bulk,
                };
                let (cipher, cipher_strength) = match bulk_cipher {
                    rustls::BulkAlgorithm::Aes128Gcm => (ConnectionCipher::CalgAes128, 128),
                    rustls::BulkAlgorithm::Aes256Gcm => (ConnectionCipher::CalgAes256, 256),
                    rustls::BulkAlgorithm::Chacha20Poly1305 => {
                        return Err(Error::new(
                            ErrorKind::UnsupportedFunction,
                            "alg_id for CHACHA20_POLY1305 does not exist",
                        ))
                    }
                };

                let hash_algo = connection_cipher.hash_algorithm();

                Ok(ConnectionInfo {
                    protocol,
                    cipher,
                    cipher_strength,
                    hash: ConnectionHash::CalgSha,
                    hash_strength: hash_algo.output_len() as u32,
                    key_exchange: ConnectionKeyExchange::CalgRsaKeyx,
                    exchange_strength: (self.raw_peer_public_key()?.len() * 8) as u32,
                })
            }
        }
    }

    pub fn raw_peer_public_key(&self) -> Result<Vec<u8>> {
        let certificates = self.peer_certificates()?;
        let peer_certificate = certificates
            .get(0)
            .ok_or_else(|| Error::new(ErrorKind::CertificateUnknown, "Can not acquire server certificate"))?;

        let peer_certificate: Certificate = picky_asn1_der::from_bytes(peer_certificate)?;

        let raw_public_key = match peer_certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
        {
            picky_asn1_x509::PublicKey::Rsa(rsa_pk) => picky_asn1_der::to_vec(&rsa_pk.0)?,
            picky_asn1_x509::PublicKey::Ec(ec) => picky_asn1_der::to_vec(&ec)?,
            picky_asn1_x509::PublicKey::Ed(ed) => picky_asn1_der::to_vec(&ed)?,
        };

        Ok(raw_public_key)
    }
}
