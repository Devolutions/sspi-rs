macro_rules! kout {
    ($name:ident, $size:ident) => {
        pub struct $name;

        impl digest::crypto_common::KeySizeUser for $name {
            type KeySize = digest::consts::$size;
        }
    };
}

kout!(Kout32, U32);
kout!(Kout64, U64);
