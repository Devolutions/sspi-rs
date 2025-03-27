pub mod generator;

use dpapi_core::{DecodeOwned, Encode, ReadCursor, WriteBuf};
use dpapi_pdu::gkdi::{EcdhKey, FfcdhKey, FfcdhParameters, GetKey, GroupKeyEnvelope};
use dpapi_pdu::rpc::Pdu;

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
    decode::<GetKey>(data);
    // KdfParameters has very few number of valid payloads, as its only field cannot have an arbitrary value.
    // decode::<KdfParameters>(data);
    decode::<FfcdhParameters>(data);
    decode::<FfcdhKey>(data);
    decode::<EcdhKey>(data);
    decode::<GroupKeyEnvelope>(data);
    decode::<Pdu>(data);
}

fn decode<S>(data: &[u8])
where
    S: DecodeOwned + Encode,
{
    let mut reader = ReadCursor::new(data);

    let decoded = S::decode_owned(&mut reader);
    let bytes_read = reader.pos() as usize;

    match decoded {
        Ok(decoded) => {
            assert_eq!(decoded.size(), bytes_read);
        }
        Err(_) => (),
    }
}
