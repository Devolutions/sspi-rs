#![doc = include_str!("../README.md")]
#![allow(dead_code)]

pub mod blob;
mod client;
pub mod crypto;
pub mod error;
pub mod gkdi;
pub mod rpc;
pub(crate) mod sid;
pub(crate) mod str;

pub use error::{Error, DpapiResult};

#[cfg(test)]
mod tests {
    use super::*;

    pub fn init_tracing() {
        use std::io;

        use tracing_subscriber::prelude::*;
        use tracing_subscriber::EnvFilter;

        const DEFAULT_LOG_LEVEL: &str = "trace";

        let logging_filter: EnvFilter = EnvFilter::builder()
            .with_default_directive(DEFAULT_LOG_LEVEL.parse().expect("Default log level constant is bad."))
            .with_env_var("DPAPI_LOG_LEVEL")
            .from_env_lossy();

        let stdout_layer = tracing_subscriber::fmt::layer().pretty().with_writer(io::stdout);

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(logging_filter)
            .init();
    }

    #[test]
    fn decode_ap_rep() {
        use byteorder::{LittleEndian, ReadBytesExt};
        use picky_asn1::wrapper::ObjectIdentifierAsn1;
        use picky_krb::messages::ApRep;

        let data = &[
            96, 129, 153, 6, 9, 42, 134, 72, 134, 247, 18, 1, 2, 2, 2, 0, 111, 129, 137, 48, 129, 134, 160, 3, 2, 1, 5,
            161, 3, 2, 1, 15, 162, 122, 48, 120, 160, 3, 2, 1, 18, 162, 113, 4, 111, 170, 33, 208, 106, 225, 73, 38,
            73, 249, 131, 165, 226, 174, 96, 227, 228, 103, 164, 109, 214, 15, 21, 102, 71, 171, 103, 35, 16, 84, 96,
            110, 52, 180, 218, 117, 233, 245, 224, 208, 82, 226, 82, 232, 15, 76, 0, 94, 121, 149, 165, 96, 190, 24,
            168, 132, 178, 92, 80, 189, 178, 29, 52, 53, 77, 83, 250, 12, 75, 23, 53, 71, 101, 108, 70, 100, 243, 88,
            211, 34, 26, 79, 36, 18, 144, 59, 106, 160, 171, 155, 207, 235, 120, 27, 243, 88, 39, 74, 104, 88, 244,
            152, 145, 198, 82, 221, 50, 152, 214, 240, 4, 68,
        ];

        let mut reader = &data[3..];
        let id: ObjectIdentifierAsn1 = picky_asn1_der::from_reader(&mut reader).unwrap();
        let krb_id = reader.read_u16::<LittleEndian>().unwrap();
        let ap_rep: ApRep = picky_asn1_der::from_reader(reader).unwrap();

        println!("{:?} {:?} {:?}", id, krb_id, ap_rep);
    }

    #[test]
    fn run() {
        init_tracing();

        let username = "t2@tbt.com";
        let password = "qqqQQQ111!!!".to_owned();

        let secret = "TheBestTvarynka";
        println!("secret: {secret}");

        let blob = n_crypt_protect_secret(
            secret.as_bytes(),
            "S-1-5-21-1485435871-894665558-560847465-1104".into(),
            None,
            "192.168.1.104",
            username,
            password.clone().into(),
        )
        .unwrap();

        println!("ENCRYPTED!!!!");

        let plaintext = n_crypt_unprotect_secret(&blob, "192.158.1.104", username, password.clone().into()).unwrap();

        println!("DECRYPTED!!!!");

        assert_eq!(secret.as_bytes(), plaintext.as_slice());
    }
}
