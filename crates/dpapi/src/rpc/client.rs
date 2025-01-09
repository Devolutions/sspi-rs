use std::net::{TcpStream, ToSocketAddrs};

use crate::rpc::auth::AuthProvider;
use crate::rpc::bind::{AlterContext, Bind, BindAck, ContextElement, ContextResultCode};
use crate::rpc::pdu::*;
use crate::rpc::request::Request;
use crate::rpc::verification::VerificationTrailer;
use crate::rpc::{write_padding, Decode, Encode, EncodeExt};
use crate::DpapiResult;

pub struct RpcClient {
    stream: TcpStream,
    sign_header: bool,
    auth: AuthProvider,
}

impl RpcClient {
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
            frag_len: 0, // We need to set it later after building the PDU
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

    fn create_request(
        &self,
        context_id: u16,
        opnum: u16,
        mut stub_data: Vec<u8>,
        verification_trailer: Option<VerificationTrailer>,
    ) -> DpapiResult<(Pdu, (usize, usize))> {
        if let Some(verification_trailer) = verification_trailer.as_ref() {
            write_padding::<4>(stub_data.len(), &mut stub_data)?;
            stub_data.extend_from_slice(&verification_trailer.encode_to_vec()?);
        }

        // If the security trailer is present it must be aligned to the
        // next 16 byte boundary after the stub data. This padding is
        // included as part of the stub data to be encrypted.
        let padding_len = write_padding::<16>(stub_data.len(), &mut stub_data)?;
        let security_trailer = self.auth.get_empty_trailer(padding_len.try_into()?);
        let auth_len = security_trailer.auth_value.len();
        let encrypt_offsets = (24, 24 + stub_data.len());

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
                security_trailer: Some(security_trailer),
            },
            encrypt_offsets,
        ))
    }

    fn prepare_pdu(&self, pdu: Pdu, encrypt_offsets: (usize, usize)) -> DpapiResult<Vec<u8>> {
        let mut pdu_encoded = pdu.encode_to_vec()?;
        let frag_len = u16::try_from(pdu_encoded.len())?;
        // Set `frag_len` in the PDU header.
        pdu_encoded[8..10].copy_from_slice(&frag_len.to_le_bytes());

        let header = &pdu_encoded[0..encrypt_offsets.0];
        let body = &pdu_encoded[encrypt_offsets.0..encrypt_offsets.1];
        let sec_trailer = &pdu_encoded[encrypt_offsets.1..encrypt_offsets.1 + 8];

        let pdu_encoded = self.auth.wrap(header, body, sec_trailer, self.sign_header)?;

        Ok(pdu_encoded)
    }

    fn process_bind_ack(&self, ack: &BindAck, contexts: &[ContextElement]) -> Vec<ContextElement> {
        // TODO: other operations were moved out of this function:
        // because here we don't have an access to the PDU header and sec_trailer.
        contexts
            .into_iter()
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

    fn process_response(
        &self,
        response: &mut [u8],
        pdu_header: &PduHeader,
        encrypt_offsets: (usize, usize),
    ) -> DpapiResult<Pdu> {
        if pdu_header.auth_len > 0 {
            // Decrypt the security trailer.

            let sec_trailer_offset = usize::from(pdu_header.frag_len - (pdu_header.auth_len + 8));
            let header = &response[0..encrypt_offsets.0];
            let body = &response[encrypt_offsets.0..sec_trailer_offset];
            let sec_trailer = &response[sec_trailer_offset..sec_trailer_offset + 8];
            let signature = &response[sec_trailer_offset + 8..];

            let decrypted_stub_data = self
                .auth
                .unwrap(header, body, sec_trailer, signature, self.sign_header)?;

            response[encrypt_offsets.0..sec_trailer_offset].copy_from_slice(&decrypted_stub_data);
        }

        let pdu = Pdu::decode(response as &[u8])?;

        // TODO: check pdu type (can be done outside this function).

        Ok(pdu)
    }
}
