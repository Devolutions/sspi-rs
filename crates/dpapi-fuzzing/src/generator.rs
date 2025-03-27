use dpapi_core::{DecodeOwned, DecodeResult, EncodeResult, ReadCursor, StaticName, WriteBuf, encode_buf};
use dpapi_pdu::gkdi::{EcdhKey, FfcdhKey, FfcdhParameters, GetKey, GroupKeyEnvelope, KdfParameters};
use dpapi_pdu::rpc::Pdu;

macro_rules! wrapper {
    (pub enum $name:ident ; structs $( $msg_ty:ident, )+ ) => {
        #[derive(Debug, PartialEq, arbitrary::Arbitrary)]
        pub enum $name {
            $( $msg_ty($msg_ty), )+
        }

        impl $name {
            pub fn encode(&self, dst: &mut WriteBuf) -> EncodeResult<&'static str> {
                match self {
                    $(
                        $name::$msg_ty(msg) => {
                            encode_buf(msg, dst)?;

                            Ok($msg_ty::NAME)
                        },
                    )+
                }
            }

            pub fn decode(name: &str, src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
                match name {
                    $(
                        $msg_ty::NAME => $msg_ty::decode_owned(src).map(Self::$msg_ty),
                    )+
                    _ => panic!("unexpected case"),
                }
            }
        }
    };
}

wrapper! {
    pub enum AnyStruct;
    structs
        GetKey,
        KdfParameters,
        FfcdhParameters,
        FfcdhKey,
        EcdhKey,
        GroupKeyEnvelope,
        Pdu,
}
