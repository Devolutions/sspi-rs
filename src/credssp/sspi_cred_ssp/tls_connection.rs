use std::io::{Read, Write};

use picky_asn1_x509::Certificate;
use rustls::{Connection, ProtocolVersion};

use crate::{
    ConnectionCipher, ConnectionHash, ConnectionInfo, ConnectionKeyExchange, ConnectionProtocol, Error, ErrorKind,
    Result, StreamSizes,
};

// type + version + length
pub const TLS_PACKET_HEADER_LEN: usize = 1 /* ContentType */ + 2 /* ProtocolVersion */ + 2 /* length: uint16 */;

// The Secure Sockets Layer (SSL) Protocol Version 3.0
// https://datatracker.ietf.org/doc/html/rfc6101#page-14
//
// ...Sequence numbers are of type uint64 and may not exceed 2^64-1.
const TLS_PACKET_SEQUENCE_NUMBER_LEN: usize = std::mem::size_of::<u64>();

// The Secure Sockets Layer (SSL) Protocol Version 3.0
// https://datatracker.ietf.org/doc/html/rfc6101#appendix-A.1
//
// application_data(23)
const TLS_APPLICATION_CONTENT_TYPE: u8 = 0x17;

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
            Ok(ServerCertVerified::assertion())
        }
    }
}

/// Represents parsed part of the TLS traffic.
///
/// The input buffer can contain part of the TLS message, one TLS packet, or even more than one TLS packet.
/// To decrypt the incoming buffer sometimes we need to split it into parts. If it contains more then one TLS packet,
/// we should decrypt only first of them. This behavior corresponds to the SChannel behavior.
#[derive(Debug)]
struct TlsTrafficParts<'data> {
    /// TLS packet header with a sequence number.
    header: &'data mut [u8],
    /// Decrypted part of the TLS packet.
    ///
    /// *Pay attention*: the TLS packet sequence number must be in the [header] buffer.
    application_data: &'data mut [u8],
    /// Unprocessed TLS packets.
    extra: &'data mut [u8],
}

impl<'a> From<&'a mut [u8]> for TlsTrafficParts<'a> {
    fn from(value: &'a mut [u8]) -> Self {
        Self {
            header: &mut [],
            application_data: value,
            extra: &mut [],
        }
    }
}

/// Represents buffers after the decryption.
///
/// We can not return just decrypted data because we also need a TLS header and unprocessed data buffers.
/// More info: https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
///
/// After the decryption, the original SChannel produces four buffers (the order is important):
/// * SECBUFFER_STREAM_HEADER. It contains TLS packet header with a sequence number.
/// * SECBUFFER_DATA. It contains a decrypted data.
/// * SECBUFFER_STREAM_TRAILER. It contains the TLS packet HMAC with all unprocessed data.
/// * SECBUFFER_EXTRA. It contains the rest of the unprocessed TLS traffic. Usually, the start of this buffer
///   points to the start of the next TLS packet in the input buffer.
#[derive(Debug)]
pub struct DecryptionResultBuffers<'data> {
    /// TLS packet header with the sequence number.
    pub header: &'data mut [u8],
    /// Decrypted data.
    pub decrypted: &'data mut [u8],
    /// Unprocessed TLS packets.
    pub extra: &'data mut [u8],
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

    // This function extracts the application data (encrypted part) of the TLS packet.
    // If the input buffer contains more than one TLS packet, then the application data of
    // the first one will be returned.
    // If the input buffer contains less than one TLS packet (only a part of it), then
    // the whole input buffer will be returned.
    fn find_tls_data_to_decrypt<'data>(connection: &Connection, payload: &'data mut [u8]) -> Result<&'data mut [u8]> {
        if payload.len() < TLS_PACKET_HEADER_LEN + TLS_PACKET_SEQUENCE_NUMBER_LEN {
            return Ok(payload);
        }

        let mut tls_packet_start = vec![TLS_APPLICATION_CONTENT_TYPE];
        let tls_version = connection
            .protocol_version()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Can not query negotiated TLS version"))?
            .get_u16()
            .to_be_bytes();
        tls_packet_start.extend_from_slice(&tls_version);

        // safe: payload length is checked above.
        if payload[0..3] != tls_packet_start {
            return Ok(payload);
        }

        // safe: payload length is checked above.
        let encrypted_application_data_len = usize::from(u16::from_be_bytes(payload[3..5].try_into().unwrap()));

        if payload.len() < TLS_PACKET_HEADER_LEN + encrypted_application_data_len {
            return Ok(payload);
        }

        let tls_packet_len = TLS_PACKET_HEADER_LEN + encrypted_application_data_len;

        // safe: payload length is checked above.
        Ok(&mut payload[0..tls_packet_len])
    }

    // This function splits the incoming TLS traffic into three parts (if possible):
    // * header.
    // * application_data.
    // * extra.
    // See the [TlsTrafficParts] documentation for a more detailed explanation of those buffers.
    fn split_tls_traffic<'a>(connection: &Connection, payload: &'a mut [u8]) -> Result<TlsTrafficParts<'a>> {
        const TLS_PACKET_PREFIX_LEN: usize = TLS_PACKET_HEADER_LEN + TLS_PACKET_SEQUENCE_NUMBER_LEN;
        if payload.len() < TLS_PACKET_PREFIX_LEN {
            return Ok(payload.into());
        }

        let mut tls_packet_start = vec![TLS_APPLICATION_CONTENT_TYPE];
        let tls_version = connection
            .protocol_version()
            .ok_or_else(|| Error::new(ErrorKind::InternalError, "Can not query negotiated TLS version"))?
            .get_u16()
            .to_be_bytes();
        tls_packet_start.extend_from_slice(&tls_version);

        // safe: payload length is checked above.
        if payload[0..3] != tls_packet_start {
            return Ok(payload.into());
        }

        // safe: payload length is checked above.
        let encrypted_application_data_len = usize::from(u16::from_be_bytes(payload[3..5].try_into().unwrap()));

        if payload.len() < TLS_PACKET_PREFIX_LEN + encrypted_application_data_len {
            let (header, application_data) = payload.split_at_mut(TLS_PACKET_PREFIX_LEN);
            return Ok(TlsTrafficParts {
                header,
                application_data,
                extra: &mut [],
            });
        }

        // safe: payload length is checked above.
        let (header, rest) = payload.split_at_mut(TLS_PACKET_PREFIX_LEN);
        // `encrypted_application_data_len` is a len of the encrypted data with the sequence number.
        // But here we need the encrypted data WITHOUT a sequence number, so we extract TLS_PACKET_SEQUENCE_NUMBER_LEN
        // from the overall data length.
        let (application_data, extra) =
            rest.split_at_mut(encrypted_application_data_len - TLS_PACKET_SEQUENCE_NUMBER_LEN);

        Ok(TlsTrafficParts {
            header,
            application_data,
            extra,
        })
    }

    /// Decrypt a part of the incoming TLS traffic.
    ///
    /// If the input buffer contains more than one TLS message,then only the first one will be decrypted.
    pub fn decrypt_tls<'a>(&mut self, payload: &'a mut [u8]) -> Result<DecryptionResultBuffers<'a>> {
        match self {
            TlsConnection::Rustls(tls_connection) => {
                let tls_data_to_decrypt = TlsConnection::find_tls_data_to_decrypt(tls_connection, payload)?;
                let mut tls_packet: &[u8] = tls_data_to_decrypt;

                let mut plain_data = Vec::with_capacity(tls_packet.len());

                while !tls_packet.is_empty() {
                    let _ = tls_connection.read_tls(&mut tls_packet)?;

                    let tls_state = tls_connection
                        .process_new_packets()
                        .map_err(|err| Error::new(ErrorKind::DecryptFailure, err.to_string()))?;

                    let decrypted_data_len = plain_data.len();
                    plain_data.resize(decrypted_data_len + tls_state.plaintext_bytes_to_read(), 0);

                    let mut reader = tls_connection.reader();
                    let _plain_data_len = reader.read(&mut plain_data[decrypted_data_len..])?;
                }

                let TlsTrafficParts {
                    header,
                    application_data,
                    extra,
                } = TlsConnection::split_tls_traffic(tls_connection, payload)?;

                if application_data.len() < plain_data.len() {
                    return Err(Error::new(
                        ErrorKind::DecryptFailure,
                        "Decrypted data can not be larger then encrypted one.",
                    ));
                }

                let decrypted = &mut application_data[0..plain_data.len()];
                decrypted.copy_from_slice(&plain_data);

                Ok(DecryptionResultBuffers {
                    header,
                    decrypted,
                    extra,
                })
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
                    hash_strength: hash_algo.output_len().try_into()?,
                    key_exchange: ConnectionKeyExchange::CalgRsaKeyx,
                    exchange_strength: (self.raw_peer_public_key()?.len() * 8).try_into()?,
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
