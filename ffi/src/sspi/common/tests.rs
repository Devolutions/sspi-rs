use std::ptr::null_mut;
use std::slice::from_raw_parts;

use sspi::credssp::SspiContext;
use sspi::{EncryptionFlags, Kerberos, SecurityBufferRef, Sspi};

use crate::sspi::sec_buffer::{SecBuffer, SecBufferDesc};
use crate::sspi::sec_handle::{SecHandle, SecurityPackageId, SspiHandle};
use crate::utils::into_raw_ptr;

const SECBUFFER_DATA: u32 = 1;
const SECBUFFER_TOKEN: u32 = 2;
const SECBUFFER_STREAM: u32 = 10;

fn kerberos_sec_handle(kerberos: Kerberos) -> SecHandle {
    SecHandle {
        dw_lower: SecurityPackageId::Kerberos.into(),
        dw_upper: {
            let sspi_context = SspiHandle::new(SspiContext::Kerberos(kerberos));
            into_raw_ptr(sspi_context)
                .expose_provenance()
                .try_into()
                .expect("ptr address must fit into c_ulonglong")
        },
    }
}

fn sec_buffer(buffer_type: u32, data: &mut [u8]) -> SecBuffer {
    SecBuffer {
        cb_buffer: data.len().try_into().unwrap(),
        buffer_type,
        pv_buffer: data.as_mut_ptr().cast(),
    }
}

fn sec_buffer_desc(buffers: &mut [SecBuffer]) -> SecBufferDesc {
    SecBufferDesc {
        ul_version: 0,
        c_buffers: buffers.len().try_into().unwrap(),
        p_buffers: buffers.as_mut_ptr(),
    }
}

/// Copies the bytes referenced by the buffer.
fn buffer_bytes(buffer: &SecBuffer) -> Vec<u8> {
    unsafe { from_raw_parts(buffer.pv_buffer.cast::<u8>(), buffer.cb_buffer.try_into().unwrap()) }.to_vec()
}

#[test]
fn kerberos_stream_buffer_decryption() {
    // This test simulates decryption when the `SECBUFFER_STREAM` buffer is used.
    // The expected behavior is the same as for the original Windows SSPI.
    //
    // MSDN code example: https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi
    let plain_message = b"some plain message";

    let kerberos_client = sspi::kerberos::test_data::fake_client();
    let mut kerberos_server = sspi::kerberos::test_data::fake_server();

    let mut token = [0; 1024];
    let mut data = plain_message.to_vec();
    let mut message = vec![
        SecurityBufferRef::token_buf(token.as_mut_slice()),
        SecurityBufferRef::data_buf(data.as_mut_slice()),
    ];

    kerberos_server
        .encrypt_message(EncryptionFlags::empty(), &mut message)
        .unwrap();

    let mut kerberos_client_context = kerberos_sec_handle(kerberos_client);

    let mut stream_buffer_data = message[0].data().to_vec();
    stream_buffer_data.extend_from_slice(message[1].data());
    let stream_buffer_data_len = stream_buffer_data.len().try_into().unwrap();
    let mut buffers = [
        sec_buffer(SECBUFFER_STREAM, &mut stream_buffer_data),
        SecBuffer {
            cb_buffer: 0,
            buffer_type: SECBUFFER_DATA,
            pv_buffer: null_mut(),
        },
    ];
    let mut message = sec_buffer_desc(&mut buffers);

    let status = unsafe { super::DecryptMessage(&mut kerberos_client_context, &mut message, 0, null_mut()) };
    assert_eq!(status, 0);

    let status = unsafe { super::DeleteSecurityContext(&mut kerberos_client_context) };
    assert_eq!(status, 0);

    // Check SECBUFFER_STREAM
    assert_eq!(buffers[0].buffer_type, SECBUFFER_STREAM);
    assert_eq!(buffers[0].cb_buffer, stream_buffer_data_len);

    // Check SECBUFFER_DATA
    assert_eq!(buffers[1].buffer_type, SECBUFFER_DATA);
    assert_eq!(buffers[1].cb_buffer, u32::try_from(plain_message.len()).unwrap());
    // Check that the decrypted data is the same as the initial message
    assert_eq!(buffer_bytes(&buffers[1]), plain_message);
}

/// Run it under [Miri](https://github.com/rust-lang/miri): `cargo +nightly miri test`.
#[test]
fn kerberos_encryption_decryption() {
    let plain_message = b"some plain message";

    let kerberos_client = sspi::kerberos::test_data::fake_client();
    let kerberos_server = sspi::kerberos::test_data::fake_server();

    let mut kerberos_server_context = kerberos_sec_handle(kerberos_server);

    let mut token = [0_u8; 1024];
    let mut data = plain_message.to_vec();
    let mut buffers = [
        sec_buffer(SECBUFFER_TOKEN, &mut token),
        sec_buffer(SECBUFFER_DATA, &mut data),
    ];
    let mut message = sec_buffer_desc(&mut buffers);

    let status = unsafe { super::EncryptMessage(&mut kerberos_server_context, 0, &mut message, 0) };
    assert_eq!(status, 0);

    let status = unsafe { super::DeleteSecurityContext(&mut kerberos_server_context) };
    assert_eq!(status, 0);

    let mut kerberos_client_context = kerberos_sec_handle(kerberos_client);

    let mut token = buffer_bytes(&buffers[0]);
    let mut data = buffer_bytes(&buffers[1]);
    let mut buffers = [
        sec_buffer(SECBUFFER_TOKEN, &mut token),
        sec_buffer(SECBUFFER_DATA, &mut data),
    ];
    let mut message = sec_buffer_desc(&mut buffers);

    let status = unsafe { super::DecryptMessage(&mut kerberos_client_context, &mut message, 0, null_mut()) };
    assert_eq!(status, 0);

    let status = unsafe { super::DeleteSecurityContext(&mut kerberos_client_context) };
    assert_eq!(status, 0);

    // Check that the decrypted data is the same as the initial message
    assert_eq!(buffer_bytes(&buffers[1]), plain_message);
}
