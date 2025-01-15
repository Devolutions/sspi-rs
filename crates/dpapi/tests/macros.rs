#[allow(unused_macros)]
macro_rules! test_encoding_decoding {
    ($name:ident, $type:ty, $expected:expr, $data:expr) => {
        paste::paste! {
            #[test]
            fn [<$name:lower _encoding_decoding>]() {
                use dpapi::rpc::{EncodeExt, Decode};

                let data = $data;

                let parsed = $type::decode(data.as_ref()).unwrap();
                let encoded = parsed.encode_to_vec().unwrap();

                assert_eq!($expected, parsed);
                assert_eq!(data.as_ref(), &encoded);
            }
        }
    };
}
