mod credssp;
mod kerberos;
mod ntlm;

use sspi::credssp::SspiContext;
use sspi::{EncryptionFlags, SecurityBufferRef, Sspi};

fn test_encryption(client: &mut SspiContext, server: &mut SspiContext) {
    let plain_message = b"Devolutions/sspi-rs";

    let mut token = [0; 1024];
    let mut data = plain_message.to_vec();

    let mut message = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];

    client
        .encrypt_message(EncryptionFlags::empty(), &mut message, 0)
        .unwrap();
    server.decrypt_message(&mut message, 0).unwrap();

    assert_eq!(plain_message, message[1].data());
}
