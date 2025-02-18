macro_rules! kout {
    ($name:ident, $size:ident) => {
        pub struct $name;

        impl digest_pre::crypto_common::KeySizeUser for $name {
            type KeySize = digest_pre::consts::$size;
        }
    };
}

kout!(Kout32, U32);
kout!(Kout64, U64);
