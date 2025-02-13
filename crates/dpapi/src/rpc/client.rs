use std::net::{TcpStream, ToSocketAddrs};

use uuid::{uuid, Uuid};

use crate::rpc::auth::AuthProvider;
use crate::rpc::bind::{
    AlterContext, Bind, BindAck, BindTimeFeatureNegotiationBitmask, ContextElement, ContextResultCode, SyntaxId,
};
use crate::rpc::pdu::*;
use crate::rpc::request::Request;
use crate::rpc::verification::VerificationTrailer;
use crate::rpc::{write_padding, Decode, EncodeExt};
use crate::DpapiResult;

pub const NDR64: SyntaxId = SyntaxId {
    uuid: uuid!("71710533-beba-4937-8319-b5dbef9ccc36"),
    version: 1,
    version_minor: 0,
};
pub const NDR: SyntaxId = SyntaxId {
    uuid: uuid!("8a885d04-1ceb-11c9-9fe8-08002b104860"),
    version: 2,
    version_minor: 0,
};

pub fn bind_time_feature_negotiation(flags: BindTimeFeatureNegotiationBitmask) -> SyntaxId {
    SyntaxId {
        uuid: Uuid::from_fields(0x6cb71c2c, 0x9812, 0x4540, &flags.as_u64().to_be_bytes()),
        version: 1,
        version_minor: 0,
    }
}

/// Represents structural offsets in RPC PDU.
///
/// This structure is used to split the encoded RPC PDU into separate parts before encryption or decryption.
#[derive(Debug, Copy, Clone)]
struct EncryptionOffsets {
    /// RPC PDU header length.
    pub pdu_header_len: usize,
    /// Indicated how many bytes precede RPC PDU security trailer.
    pub security_trailer_offset: usize,
}

impl EncryptionOffsets {
    /// RPC PDU header length + RPC Request header data length.
    const REQUEST_PDU_HEADER_LEN: usize = 24;
}

/// General RPC client.
///
/// All RPC communication is done using this RPC client. It can connect to RPC server,
/// authenticate, and send RPC requests.
pub struct RpcClient {
    stream: TcpStream,
    sign_header: bool,
    auth: AuthProvider,
}

impl RpcClient {
    /// Connects to the RPC server.
    ///
    /// Returns a new RPC client that is ready to send/receive data.
    pub fn connect<A: ToSocketAddrs>(addr: A, auth: AuthProvider) -> DpapiResult<Self> {
        Ok(Self {
            stream: TcpStream::connect(addr)?,
            sign_header: false,
            auth,
        })
    }

    fn create_pdu_header(
        &self,
        packet_type: PacketType,
        packet_flags: PacketFlags,
        auth_len: u16,
        call_id: u32,
    ) -> PduHeader {
        PduHeader {
            version: 5,
            version_minor: 0,
            packet_type,
            packet_flags: packet_flags | PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
            data_rep: DataRepr::default(),
            // We will set `frag_len` later after building the PDU.
            frag_len: 0,
            auth_len,
            call_id,
        }
    }

    fn create_bind_pdu(
        &mut self,
        contexts: Vec<ContextElement>,
        security_trailer: Option<SecurityTrailer>,
    ) -> DpapiResult<Pdu> {
        let (auth_len, packet_flags) = if let Some(security_trailer) = security_trailer.as_ref() {
            self.sign_header = true;

            (security_trailer.auth_value.len(), PacketFlags::PfcSupportHeaderSign)
        } else {
            (0, PacketFlags::None)
        };

        Ok(Pdu {
            header: self.create_pdu_header(
                PacketType::Bind,
                packet_flags,
                auth_len.try_into()?,
                1, /* call id */
            ),
            data: PduData::Bind(Bind {
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                assoc_group: 0,
                contexts,
            }),
            security_trailer,
        })
    }

    fn create_alter_context_pdu(
        &self,
        contexts: Vec<ContextElement>,
        sec_trailer: SecurityTrailer,
    ) -> DpapiResult<Pdu> {
        let packet_flags = if self.sign_header {
            PacketFlags::PfcSupportHeaderSign
        } else {
            PacketFlags::None
        };

        Ok(Pdu {
            header: self.create_pdu_header(
                PacketType::AlterContext,
                packet_flags,
                sec_trailer.auth_value.len().try_into()?,
                1, /* call id */
            ),
            data: PduData::AlterContext(AlterContext(Bind {
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                assoc_group: 0,
                contexts,
            })),
            security_trailer: Some(sec_trailer),
        })
    }

    #[instrument(level = "trace", ret, skip(self))]
    fn create_request(
        &mut self,
        context_id: u16,
        opnum: u16,
        mut stub_data: Vec<u8>,
        verification_trailer: Option<VerificationTrailer>,
        authenticate: bool,
    ) -> DpapiResult<(Pdu, Option<EncryptionOffsets>)> {
        if let Some(verification_trailer) = verification_trailer.as_ref() {
            write_padding::<4>(stub_data.len(), &mut stub_data)?;
            let encoded_verification_trailer = verification_trailer.encode_to_vec()?;
            stub_data.extend_from_slice(&encoded_verification_trailer);
        }

        let (security_trailer, auth_len, encrypt_offsets) = if authenticate {
            // If the security trailer is present it must be aligned to the
            // next 16 byte boundary after the stub data. This padding is
            // included as part of the stub data to be encrypted.
            let padding_len = write_padding::<16>(stub_data.len(), &mut stub_data)?;
            let security_trailer = self.auth.get_empty_trailer(padding_len.try_into()?)?;
            let auth_len = security_trailer.auth_value.len();

            (
                Some(security_trailer),
                auth_len,
                Some(EncryptionOffsets {
                    pdu_header_len: EncryptionOffsets::REQUEST_PDU_HEADER_LEN,
                    security_trailer_offset: EncryptionOffsets::REQUEST_PDU_HEADER_LEN + stub_data.len(),
                }),
            )
        } else {
            (None, 0, None)
        };

        Ok((
            Pdu {
                header: self.create_pdu_header(
                    PacketType::Request,
                    PacketFlags::None,
                    auth_len.try_into()?,
                    1, /* call id */
                ),
                data: PduData::Request(Request {
                    alloc_hint: stub_data.len().try_into()?,
                    context_id,
                    opnum,
                    obj: None,
                    stub_data,
                }),
                security_trailer,
            },
            encrypt_offsets,
        ))
    }

    #[instrument(level = "trace", ret, skip(self))]
    fn prepare_pdu(&mut self, pdu: Pdu, encrypt_offsets: Option<EncryptionOffsets>) -> DpapiResult<Vec<u8>> {
        let mut pdu_encoded = pdu.encode_to_vec()?;
        let frag_len = u16::try_from(pdu_encoded.len())?;
        // Set `frag_len` in the PDU header.
        pdu_encoded[8..10].copy_from_slice(&frag_len.to_le_bytes());

        if let Some(encrypt_offsets) = encrypt_offsets {
            let EncryptionOffsets {
                pdu_header_len,
                security_trailer_offset,
            } = encrypt_offsets;

            let header = &pdu_encoded[0..pdu_header_len];
            let body = &pdu_encoded[pdu_header_len..security_trailer_offset];
            let sec_trailer =
                &pdu_encoded[security_trailer_offset..security_trailer_offset + SecurityTrailer::HEADER_LEN];

            Ok(self.auth.wrap(header, body, sec_trailer, self.sign_header)?)
        } else {
            Ok(pdu_encoded)
        }
    }

    fn process_bind_ack(&self, ack: &BindAck, contexts: &[ContextElement]) -> Vec<ContextElement> {
        contexts
            .iter()
            .enumerate()
            .filter_map(|(index, context)| {
                if let Some(result) = ack.results.get(index) {
                    if result.result == ContextResultCode::Acceptance {
                        Some(context.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    #[instrument(level = "trace", ret, skip(self))]
    fn process_response(
        &mut self,
        response: &mut [u8],
        pdu_header: &PduHeader,
        encrypt_offsets: Option<EncryptionOffsets>,
    ) -> DpapiResult<Pdu> {
        if pdu_header.auth_len > 0 && encrypt_offsets.is_some() {
            // Decrypt the security trailer.
            let EncryptionOffsets {
                pdu_header_len,
                security_trailer_offset: _,
            } = encrypt_offsets.unwrap();

            let sec_trailer_offset =
                usize::from(pdu_header.frag_len) - (usize::from(pdu_header.auth_len) - SecurityTrailer::HEADER_LEN);
            let header = &response[0..pdu_header_len];
            let body = &response[pdu_header_len..sec_trailer_offset];
            let sec_trailer = &response[sec_trailer_offset..sec_trailer_offset + SecurityTrailer::HEADER_LEN];
            let signature = &response[sec_trailer_offset + SecurityTrailer::HEADER_LEN..];

            let decrypted_stub_data = self
                .auth
                .unwrap(header, body, sec_trailer, signature, self.sign_header)?;

            response[pdu_header_len..sec_trailer_offset].copy_from_slice(&decrypted_stub_data);
        }

        let pdu = Pdu::decode(response as &[u8])?;

        Ok(pdu)
    }

    #[instrument(level = "trace", ret, skip(self))]
    fn send_pdu(&mut self, pdu: Pdu, encrypt_offsets: Option<EncryptionOffsets>) -> DpapiResult<Pdu> {
        let pdu_encoded = self.prepare_pdu(pdu, encrypt_offsets)?;

        super::write_buf(&pdu_encoded, &mut self.stream)?;

        // Read PDU header
        let mut pdu_buf = super::read_vec(PduHeader::LENGTH, &mut self.stream)?;
        let pdu_header = PduHeader::decode(pdu_buf.as_slice())?;

        pdu_buf.resize(usize::from(pdu_header.frag_len), 0);
        super::read_buf(&mut self.stream, &mut pdu_buf[PduHeader::LENGTH..])?;

        let pdu = self.process_response(&mut pdu_buf, &pdu_header, encrypt_offsets)?;

        pdu.data.check_error()?;

        Ok(pdu)
    }

    /// Sends the RPC request.
    #[instrument(level = "trace", ret, skip(self))]
    pub fn request(
        &mut self,
        context_id: u16,
        opnum: u16,
        stub_data: Vec<u8>,
        verification_trailer: Option<VerificationTrailer>,
        authenticate: bool,
    ) -> DpapiResult<Pdu> {
        let (pdu, encrypt_offsets) =
            self.create_request(context_id, opnum, stub_data, verification_trailer, authenticate)?;

        self.send_pdu(pdu, encrypt_offsets)
    }

    /// Performs the RPC bind/bind_ack exchange.
    ///
    /// If the `authenticate` is set to `true`, then the bind/bind_ack exchange will continue
    /// until authentication is finished.
    #[instrument(level = "trace", ret, skip(self))]
    pub fn bind(&mut self, contexts: &[ContextElement], authenticate: bool) -> DpapiResult<BindAck> {
        let bind = if authenticate {
            // The first `initialize_security_context` call is Negotiation in our Kerberos implementation.
            // We don't need its result in RPC authentication.
            let _security_trailer = self.auth.initialize_security_context(Vec::new())?;

            let security_trailer = self.auth.initialize_security_context(Vec::new())?;

            self.create_bind_pdu(contexts.to_vec(), Some(security_trailer))?
        } else {
            self.create_bind_pdu(contexts.to_vec(), None)?
        };

        let pdu_resp = self.send_pdu(bind, None)?;

        let Pdu {
            header,
            data,
            security_trailer,
        } = pdu_resp;
        let bind_ack = data.bind_ack()?;

        if !authenticate {
            return Ok(bind_ack);
        }

        self.sign_header = header.packet_flags.contains(PacketFlags::PfcSupportHeaderSign);

        let final_contexts = self.process_bind_ack(&bind_ack, contexts);
        let mut in_token = security_trailer.map(|security_trailer| security_trailer.auth_value);

        while !self.auth.is_finished() {
            let security_trailer = self.auth.initialize_security_context(in_token.unwrap_or_default())?;

            if security_trailer.auth_value.is_empty() || self.auth.is_finished() {
                break;
            }

            let alter_context = self.create_alter_context_pdu(final_contexts.clone(), security_trailer)?;
            let alter_context_resp = self.send_pdu(alter_context, None)?;

            in_token = alter_context_resp
                .security_trailer
                .map(|security_trailer| security_trailer.auth_value);
        }

        Ok(bind_ack)
    }
}
