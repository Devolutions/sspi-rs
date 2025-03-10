macro_rules! test_encoding_decoding {
    ($name:ident, $type:ty, $expected:expr, $data:expr) => {
        paste::paste! {
            #[test]
            fn [<$name:lower _encoding_decoding>]() {
                use dpapi_core::{Encode, Decode};

                let data = $data;

                let parsed = $type::decode(data.as_slice()).unwrap();
                let encoded = parsed.encode_vec().unwrap();

                assert_eq!($expected, parsed);
                assert_eq!(data[..], encoded[..]);
            }
        }
    };
}
