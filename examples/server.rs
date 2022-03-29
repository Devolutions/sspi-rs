// Based on the SSPI server example from MSDN: https://docs.microsoft.com/en-us/windows/win32/secauthn/using-sspi-with-a-windows-sockets-server

// This example works with the client example using SSPI.
// It demonstrates how to connect with a client, establish a secure communication session, and send the client an encrypted message.

use std::{
    io,
    net::{TcpListener, TcpStream},
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

#[cfg(windows)]
use sspi::winapi::Ntlm;
#[cfg(not(windows))]
use sspi::Ntlm;

use sspi::{
    AuthIdentity, CredentialUse, DataRepresentation, EncryptionFlags, SecurityBuffer,
    SecurityBufferType, SecurityStatus, ServerRequestFlags, Sspi,
};

const IP: &str = "127.0.0.1:8080";

fn main() -> Result<(), io::Error> {
    let listener = TcpListener::bind(IP).expect("Unable to start the server");

    println!("Started the server.");

    let (mut stream, _client_addr) = listener.accept()?;

    let mut ntlm = Ntlm::new();

    let identity = AuthIdentity {
        username: whoami::username(),
        password: String::from("password"),
        domain: Some(whoami::hostname()),
    };

    do_authentication(&mut ntlm, &identity, &mut stream)
        .expect("Failed to authenticate connection");
    println!("Authenticated!");

    println!("Sending the encrypted message...");

    let msg = "This is your server speaking!".to_string();

    // By agreement, the server encrypts and sets the size of the
    // trailer block to be just what it needed. decrypt_message
    // needs the size of the trailer block.
    //
    // By agreement, the server places the trailer at the beginning
    // of the message, and the data comes after the trailer.
    let mut msg_buffer = vec![
        SecurityBuffer::new(
            vec![0u8; ntlm.query_context_sizes()?.security_trailer as usize],
            SecurityBufferType::Token,
        ),
        SecurityBuffer::new(Vec::from(msg.as_bytes()), SecurityBufferType::Data),
    ];

    println!("Unencrypted message: [{}]", msg);
    println!("Encrypting...");

    let _result = ntlm.encrypt_message(EncryptionFlags::empty(), &mut msg_buffer, 0)?;

    println!("Encrypted message: {:?}", msg_buffer[1].buffer);

    println!("Sending the trailer...");
    write_message(&mut stream, &msg_buffer[0].buffer)?;

    println!("Sending the data...");
    write_message(&mut stream, &msg_buffer[1].buffer)?;

    println!("Communication successfully finished.");

    Ok(())
}

fn do_authentication(
    ntlm: &mut Ntlm,
    identity: &AuthIdentity,
    mut stream: &mut TcpStream,
) -> Result<(), sspi::Error> {
    let mut acq_cred_result = ntlm
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Inbound)
        .with_auth_data(identity)
        .execute()?;

    let mut input_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];
    let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

    loop {
        read_message(&mut stream, &mut input_buffer[0].buffer)?;

        let result = ntlm
            .accept_security_context()
            .with_credentials_handle(&mut acq_cred_result.credentials_handle)
            .with_context_requirements(ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input_buffer)
            .with_output(&mut output_buffer)
            .execute()?;

        if [
            SecurityStatus::CompleteAndContinue,
            SecurityStatus::CompleteNeeded,
        ]
        .contains(&result.status)
        {
            println!("Completing the token...");
            ntlm.complete_auth_token(&mut output_buffer)?;
        }

        write_message(&mut stream, &output_buffer[0].buffer)?;

        output_buffer[0].buffer.clear();
        input_buffer[0].buffer.clear();

        if ![
            SecurityStatus::CompleteAndContinue,
            SecurityStatus::ContinueNeeded,
        ]
        .contains(&result.status)
        {
            break;
        }
    }

    Ok(())
}

// By agreement, the message length is read from the first 2 bytes of the message in little-endian order.
pub fn read_message<T: io::Read, A: io::Write>(
    stream: &mut T,
    output_buffer: &mut A,
) -> Result<(), io::Error> {
    let msg_len = stream.read_u16::<LittleEndian>()?;

    let mut buff = vec![0u8; msg_len as usize];
    stream.read_exact(&mut buff)?;

    output_buffer.write_all(&buff)?;

    println!("Received the buffer [{} bytes]: {:?}", buff.len(), buff);

    Ok(())
}

// By agreement, the message length is written in the first 2 bytes of the message in little-endian order.
pub fn write_message<T: io::Write>(stream: &mut T, input_buffer: &[u8]) -> Result<(), io::Error> {
    if !input_buffer.is_empty() {
        println!(
            "Sending the buffer [{} bytes]: {:?}",
            input_buffer.len(),
            input_buffer
        );

        stream.write_u16::<LittleEndian>(input_buffer.len() as u16)?;
        stream.write_all(input_buffer)?;
    }

    Ok(())
}

#[test]
fn buffer_read_correctly() {
    let mut msg = vec![0x3, 0x0];
    msg.append(&mut b"abc".to_vec());

    let mut buffer = Vec::new();

    read_message(&mut msg.as_slice(), &mut buffer).unwrap();

    assert_eq!(buffer, b"abc".to_vec());
}

#[test]
fn buffer_written_correctly() {
    let mut msg = vec![9, 8, 7];
    let mut stream = Vec::new();

    write_message(&mut stream, &mut msg).unwrap();

    assert_eq!(stream, vec![3, 0, 9, 8, 7]);
}
