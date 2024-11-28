macro_rules! test_encoding_decoding {
    ($name:ident, $expected:expr, $data:expr) => {
        paste::paste! {
            #[test]
            fn [<$name _encoding_decoding>]() {
                use crate::rpc::{Encode, Decode};

                let data = $data;

                let parsed = $name::decode(data.as_ref()).unwrap();
                let encoded = parsed.encode_to_vec().unwrap();

                assert_eq!($expected, parsed);
                assert_eq!(data.as_ref(), &encoded);
            }
        }
    };
}
