use byteorder::{LittleEndian, ReadBytesExt};
use picky_krb::crypto::CipherSuite;
use rand::rngs::OsRng;
use rand::Rng;

use crate::kerberos::EncryptionParams;
use crate::{DecryptBuffer, Error, ErrorKind, Result, SecurityBufferType};

pub fn string_to_utf16(value: impl AsRef<str>) -> Vec<u8> {
    value
        .as_ref()
        .encode_utf16()
        .flat_map(|i| i.to_le_bytes().to_vec())
        .collect::<Vec<u8>>()
}

pub fn bytes_to_utf16_string(mut value: &[u8]) -> String {
    let mut value_u16 = vec![0x00; value.len() / 2];
    value
        .read_u16_into::<LittleEndian>(value_u16.as_mut())
        .expect("read_u16_into cannot fail at this point");

    String::from_utf16_lossy(value_u16.as_ref())
}

#[cfg_attr(not(target_os = "windows"), allow(unused))]
pub fn is_azure_ad_domain(domain: &str) -> bool {
    domain == crate::pku2u::AZURE_AD_DOMAIN
}

pub fn utf16_bytes_to_utf8_string(data: &[u8]) -> String {
    debug_assert_eq!(data.len() % 2, 0);
    String::from_utf16_lossy(
        &data
            .chunks(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect::<Vec<u16>>(),
    )
}

pub fn generate_random_symmetric_key(cipher: &CipherSuite, rnd: &mut OsRng) -> Vec<u8> {
    let key_size = cipher.cipher().key_size();
    let mut key = Vec::with_capacity(key_size);

    for _ in 0..key_size {
        key.push(rnd.gen());
    }

    key
}

pub fn map_keb_error_code_to_sspi_error(krb_error_code: u32) -> (ErrorKind, String) {
    use picky_krb::constants::error_codes::*;

    match krb_error_code {
        KDC_ERR_NONE => (ErrorKind::Unknown, "No error".into()),
        KDC_ERR_NAME_EXP => (
            ErrorKind::InvalidParameter,
            "Client's entry in database has expired".into(),
        ),
        KDC_ERR_SERVICE_EXP => (
            ErrorKind::InvalidParameter,
            "Server's entry in database has expired".into(),
        ),
        KDC_ERR_BAD_PVNO => (
            ErrorKind::KdcInvalidRequest,
            "Requested protocol version number not supported".into(),
        ),
        KDC_ERR_C_OLD_MAST_KVNO => (
            ErrorKind::EncryptFailure,
            "Client's key encrypted in old master key".into(),
        ),
        KDC_ERR_S_OLD_MAST_KVNO => (
            ErrorKind::EncryptFailure,
            "Server's key encrypted in old master key".into(),
        ),
        KDC_ERR_C_PRINCIPAL_UNKNOWN => (
            ErrorKind::UnknownCredentials,
            "Client not found in Kerberos database".into(),
        ),
        KDC_ERR_S_PRINCIPAL_UNKNOWN => (
            ErrorKind::UnknownCredentials,
            "Server not found in Kerberos database".into(),
        ),
        KDC_ERR_PRINCIPAL_NOT_UNIQUE => (
            ErrorKind::TooManyPrincipals,
            "Multiple principal entries database".into(),
        ),
        KDC_ERR_NULL_KEY => (ErrorKind::EncryptFailure, "The client or server has a null key".into()),
        KDC_ERR_CANNOT_POSTDATE => (
            ErrorKind::KdcInvalidRequest,
            "Ticket not eligible for postdating".into(),
        ),
        KDC_ERR_NEVER_VALID => (
            ErrorKind::KdcInvalidRequest,
            "Requested starttime is later than end time".into(),
        ),
        KDC_ERR_POLICY => (ErrorKind::KdcInvalidRequest, "KDC policy rejects request".into()),
        KDC_ERR_BADOPTION => (
            ErrorKind::KdcInvalidRequest,
            "KDC cannot accommodate request option".into(),
        ),
        KDC_ERR_ETYPE_NOSUPP => (
            ErrorKind::OperationNotSupported,
            "KDC has no support for encryption type".into(),
        ),
        KDC_ERR_SUMTYPE_NOSUPP => (
            ErrorKind::KdcInvalidRequest,
            "KDC has no support for checksum type".into(),
        ),
        KDC_ERR_PADATA_TYPE_NOSUPP => (
            ErrorKind::KdcInvalidRequest,
            "KDC has no support for padata type".into(),
        ),
        KDC_ERR_TRTYPE_NOSUPP => (
            ErrorKind::KdcInvalidRequest,
            "KDC has no support for transited type".into(),
        ),
        KDC_ERR_CLIENT_REVOKED => (
            ErrorKind::UnknownCredentials,
            "Clients credentials have been revoked".into(),
        ),
        KDC_ERR_SERVICE_REVOKED => (
            ErrorKind::UnknownCredentials,
            "Credentials for server have been revoked".into(),
        ),
        KDC_ERR_TGT_REVOKED => (ErrorKind::UnknownCredentials, "TGT has been revoked".into()),
        KDC_ERR_CLIENT_NOTYET => (
            ErrorKind::UnknownCredentials,
            "Client not yet valid; try again later".into(),
        ),
        KDC_ERR_SERVICE_NOTYET => (
            ErrorKind::UnknownCredentials,
            "Server not yet valid; try again later".into(),
        ),
        KDC_ERR_KEY_EXPIRED => (
            ErrorKind::InvalidParameter,
            "Password has expired; change password to reset".into(),
        ),
        KDC_ERR_PREAUTH_FAILED => (
            ErrorKind::KdcInvalidRequest,
            "Pre-authentication information was invalid".into(),
        ),
        KDC_ERR_PREAUTH_REQUIRED => (
            ErrorKind::KdcInvalidRequest,
            "Additional preauthentication required".into(),
        ),
        KDC_ERR_SERVER_NOMATCH => (
            ErrorKind::KdcInvalidRequest,
            "Requested server and ticket don't match".into(),
        ),
        KDC_ERR_MUST_USE_USER2USER => (
            ErrorKind::KdcInvalidRequest,
            "Server principal valid for user2user only".into(),
        ),
        KDC_ERR_PATH_NOT_ACCEPTED => (ErrorKind::KdcInvalidRequest, "KDC Policy rejects transited path".into()),
        KDC_ERR_SVC_UNAVAILABLE => (ErrorKind::KdcInvalidRequest, "A service is not available".into()),
        KRB_AP_ERR_BAD_INTEGRITY => (
            ErrorKind::MessageAltered,
            "Integrity check on decrypted field failed".into(),
        ),
        KRB_AP_ERR_TKT_EXPIRED => (ErrorKind::ContextExpired, "Ticket expired".into()),
        KRB_AP_ERR_TKT_NYV => (ErrorKind::InvalidToken, "Ticket not yet valid".into()),
        KRB_AP_ERR_REPEAT => (ErrorKind::KdcInvalidRequest, "Request is a replay".into()),
        KRB_AP_ERR_NOT_US => (ErrorKind::InvalidToken, "The ticket isn't for us".into()),
        KRB_AP_ERR_BADMATCH => (
            ErrorKind::KdcInvalidRequest,
            "Ticket and authenticator don't match".into(),
        ),
        KRB_AP_ERR_SKEW => (ErrorKind::TimeSkew, "Clock skew too great".into()),
        KRB_AP_ERR_BADADDR => (ErrorKind::InvalidParameter, "Incorrect net address".into()),
        KRB_AP_ERR_BADVERSION => (ErrorKind::KdcInvalidRequest, "Protocol version mismatch".into()),
        KRB_AP_ERR_MSG_TYPE => (ErrorKind::InvalidToken, "Invalid msg type".into()),
        KRB_AP_ERR_MODIFIED => (ErrorKind::MessageAltered, "Message stream modified".into()),
        KRB_AP_ERR_BADORDER => (ErrorKind::OutOfSequence, "Message out of order".into()),
        KRB_AP_ERR_BADKEYVER => (
            ErrorKind::KdcInvalidRequest,
            "Specified version of key is not available".into(),
        ),
        KRB_AP_ERR_NOKEY => (ErrorKind::NoKerbKey, "Service key not available".into()),
        KRB_AP_ERR_MUT_FAIL => (ErrorKind::MutualAuthFailed, "Mutual authentication failed".into()),
        KRB_AP_ERR_BADDIRECTION => (ErrorKind::OutOfSequence, "Incorrect message direction".into()),
        KRB_AP_ERR_METHOD => (
            ErrorKind::InvalidToken,
            "Alternative authentication method required".into(),
        ),
        KRB_AP_ERR_BADSEQ => (ErrorKind::OutOfSequence, "Incorrect sequence number in message".into()),
        KRB_AP_ERR_INAPP_CKSUM => (
            ErrorKind::InvalidToken,
            "Inappropriate type of checksum in message".into(),
        ),
        KRB_AP_PATH_NOT_ACCEPTED => (ErrorKind::KdcInvalidRequest, "Policy rejects transited path".into()),
        KRB_ERR_RESPONSE_TOO_BIG => (
            ErrorKind::InvalidParameter,
            "Response too big for UDP; retry with TC".into(),
        ),
        KRB_ERR_GENERIC => (ErrorKind::InternalError, "Generic error (description in e-text)".into()),
        KRB_ERR_FIELD_TOOLONG => (
            ErrorKind::KdcInvalidRequest,
            "Field is too long for this implementation".into(),
        ),
        KDC_ERROR_CLIENT_NOT_TRUSTED => (ErrorKind::InvalidParameter, "Client is not trusted".into()),
        KDC_ERROR_KDC_NOT_TRUSTED => (ErrorKind::InvalidParameter, "KDC is not trusted".into()),
        KDC_ERROR_INVALID_SIG => (ErrorKind::MessageAltered, "Invalid signature".into()),
        KDC_ERR_KEY_TOO_WEAK => (ErrorKind::EncryptFailure, "Key is too weak".into()),
        KDC_ERR_CERTIFICATE_MISMATCH => (ErrorKind::InvalidParameter, "Certificated mismatch".into()),
        KRB_AP_ERR_NO_TGT => (
            ErrorKind::NoTgtReply,
            "No TGT available to validate USER-TO-USER".into(),
        ),
        KDC_ERR_WRONG_REALM => (ErrorKind::InvalidParameter, "Wrong Realm".into()),
        KRB_AP_ERR_USER_TO_USER_REQUIRED => (ErrorKind::KdcInvalidRequest, "Ticket must be for USER-TO-USER".into()),
        KDC_ERR_CANT_VERIFY_CERTIFICATE => (
            ErrorKind::KdcInvalidRequest,
            "KDC can not verify the certificate".into(),
        ),
        KDC_ERR_INVALID_CERTIFICATE => (ErrorKind::InvalidParameter, "Invalid certificate".into()),
        KDC_ERR_REVOKED_CERTIFICATE => (ErrorKind::KdcCertRevoked, "Revoked certificate".into()),
        KDC_ERR_REVOCATION_STATUS_UNKNOWN => (ErrorKind::InternalError, "Revoked status unknown".into()),
        KDC_ERR_REVOCATION_STATUS_UNAVAILABLE => (ErrorKind::InternalError, "Revoked status unavailable".into()),
        KDC_ERR_CLIENT_NAME_MISMATCH => (ErrorKind::InvalidParameter, "Client name mismatch".into()),
        KDC_ERR_KDC_NAME_MISMATCH => (ErrorKind::InvalidParameter, "KDC name mismatch".into()),
        code => (ErrorKind::Unknown, format!("Unknown Kerberos error: {}", code)),
    }
}

pub fn get_encryption_key(enc_params: &EncryptionParams) -> Result<&[u8]> {
    // the sub-session key is always preferred over the session key
    if let Some(key) = enc_params.sub_session_key.as_ref() {
        debug!("Encryption using sub-session key");

        Ok(key)
    } else if let Some(key) = enc_params.session_key.as_ref() {
        warn!("Encryption using session key (not sub-session key)");

        Ok(key)
    } else {
        error!("No encryption keys in the krb context. Maybe security context is not established and encrypt_message was called too early");

        Err(Error::new(ErrorKind::EncryptFailure, "No encryption key provided"))
    }
}

struct DataBuffer {
    data: *mut u8,
    size: usize,
}

/// Copies a decrypted data into the [SecurityBufferType::Data] or [SecurityBufferType::Stream].
///
/// If the provided buffers do not contain the [SecurityBufferType::Data] buffer, then it will try
/// to write the data in the [SecurityBufferType::Stream]. Otherwise, the error will be returned.
/// If the inner buffer is not large enough, then this function will return an error.
pub fn save_decrypted_data<'a>(
    decrypted: &'a mut [u8],
    buffers: &'a mut [DecryptBuffer],
) -> Result<()> {
    let buffer = DecryptBuffer::find_buffer_mut(buffers, SecurityBufferType::Stream);

    if let Ok(stream_buffer) = buffer {
        if stream_buffer.data().len() != decrypted.len() {
            return Err(Error::new(
                ErrorKind::EncryptFailure,
                format!(
                    "Decrypted data length ({}) does not match the stream buffer length ({})",
                    decrypted.len(),
                    stream_buffer.data().len()
                ),
            ));
        }
        let mut inner_stream_buffer = stream_buffer.take_data();
        inner_stream_buffer = &mut inner_stream_buffer[..decrypted.len()];
        inner_stream_buffer.copy_from_slice(&decrypted[..]);
        stream_buffer.set_data(inner_stream_buffer)?;
    };
    // let stream_buffer_inner = buffer
    //     .as_ref()
    //     .map(|b| {
    //         let ptr = b.data().as_ptr();
    //         let len = b.data().len();
    //         DataBuffer {
    //             data: ptr as *mut u8,
    //             size: len,
    //         }
    //     })
    //     .ok();

    // let buffer = DecryptBuffer::find_buffer_mut(buffers, SecurityBufferType::Data);
    // if let Ok(data_buffer) = buffer {
    //     if let Some(stream_buffer) = stream_buffer_inner {
    //         let DataBuffer {
    //             data: stream_inner_ptr,
    //             size: stream_inner_size,
    //         } = stream_buffer;

    //         unsafe {
    //             let data_start_ptr = stream_inner_ptr.add(header_len);
    //             let data_slice = std::slice::from_raw_parts_mut(data_start_ptr, stream_inner_size - header_len);
    //             data_buffer.set_data(data_slice)?;
    //         }
    //     };
    // };

    Ok(())
}

/// Extracts data to decrypt from the incoming buffers.
///
/// Data to decrypt is `Token` + `Stream`/`Data` buffers concatenated together.
pub fn extract_encrypted_data(buffers: &[DecryptBuffer]) -> Result<Vec<u8>> {
    let mut encrypted = DecryptBuffer::buf_data(buffers, SecurityBufferType::Token)
        .unwrap_or_default()
        .to_vec();

    encrypted.extend_from_slice(
        if let Ok(buffer) = DecryptBuffer::buf_data(buffers, SecurityBufferType::Stream) {
            buffer
        } else {
            DecryptBuffer::buf_data(buffers, SecurityBufferType::Data)?
        },
    );

    Ok(encrypted)
}
