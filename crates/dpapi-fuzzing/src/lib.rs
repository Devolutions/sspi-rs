pub mod generator;

use dpapi_core::{DecodeOwned, DecodeWithContextOwned, Encode, ReadCursor, WriteBuf};
use dpapi_pdu::gkdi::{EcdhKey, FfcdhKey, FfcdhParameters, GetKey, GroupKeyEnvelope, KdfParameters, KeyIdentifier};
use dpapi_pdu::rpc::{
    AlterContext, AlterContextResponse, Bind, BindAck, BindNak, Command, ContextElement, ContextResult, EptMap,
    EptMapResult, Fault, Floor, PacketFlags, Pdu, PduHeader, Request, Response, SecurityTrailer, SyntaxId,
    VerificationTrailer,
};

use crate::generator::AnyStruct;

pub fn round_trip(any: AnyStruct) {
    let mut buf = WriteBuf::new();

    if let Ok(name) = any.encode(&mut buf) {
        let round_tripped_struct =
            AnyStruct::decode(name, &mut ReadCursor::new(buf.filled())).expect("decode should not fail");
        pretty_assertions::assert_eq!(any, round_tripped_struct);
    }
}

pub fn structure_decoding(data: &[u8]) {
    // bind
    decode::<SyntaxId>(data);
    decode::<ContextElement>(data);
    decode::<ContextResult>(data);
    decode::<Bind>(data);
    decode::<BindAck>(data);
    decode::<BindNak>(data);
    decode::<AlterContext>(data);
    decode::<AlterContextResponse>(data);

    // epm
    decode::<Floor>(data);
    decode::<EptMap>(data);
    decode::<EptMapResult>(data);

    // pdu
    decode::<PduHeader>(data);
    decode::<SecurityTrailer>(data);
    decode::<Fault>(data);
    decode::<Pdu>(data);

    // request
    decode::<Response>(data);

    // verification
    decode::<Command>(data);
    decode::<VerificationTrailer>(data);

    // gkdi
    decode::<GetKey>(data);
    decode::<KdfParameters>(data);
    decode::<FfcdhParameters>(data);
    decode::<FfcdhKey>(data);
    decode::<EcdhKey>(data);
    decode::<KeyIdentifier>(data);
    decode::<GroupKeyEnvelope>(data);

    decode_with_context::<PacketFlags, Request>(
        data,
        PacketFlags::PfcSupportHeaderSign | PacketFlags::PfcLastFrag | PacketFlags::PfcFirstFrag,
    );
    decode_with_context::<PacketFlags, Request>(
        data,
        PacketFlags::PfcSupportHeaderSign
            | PacketFlags::PfcLastFrag
            | PacketFlags::PfcFirstFrag
            | PacketFlags::PfcObjectUuid,
    );
}

fn decode<S>(data: &[u8])
where
    S: DecodeOwned + Encode,
{
    let mut reader = ReadCursor::new(data);

    let decoded = S::decode_owned(&mut reader);
    let bytes_read = reader.pos();

    if let Ok(decoded) = decoded {
        assert_eq!(decoded.size(), bytes_read);
    }
}

fn decode_with_context<'ctx, C, S>(data: &[u8], ctx: C)
where
    S: DecodeWithContextOwned<Context<'ctx> = C> + Encode,
{
    let mut reader = ReadCursor::new(data);

    let decoded = S::decode_with_context_owned(&mut reader, ctx);
    let bytes_read = reader.pos();

    if let Ok(decoded) = decoded {
        assert_eq!(decoded.size(), bytes_read);
    }
}
