use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;

use picky_asn1::wrapper::Utf8StringAsn1;
use picky_asn1_x509::{oids, Certificate, ExtensionView, GeneralName};
use sha1::{Digest, Sha1};
use winapi::ctypes::c_void;
use winapi::um::ncrypt::HCRYPTKEY;
use winapi::um::wincrypt::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore, CryptAcquireContextW,
    CryptDestroyKey, CryptGetKeyParam, CryptGetProvParam, CryptGetUserKey, CryptReleaseContext, AT_KEYEXCHANGE,
    CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_FIRST,
    CRYPT_NEXT, CRYPT_SILENT, HCRYPTPROV, KP_CERTIFICATE, PP_ENUMCONTAINERS, PP_SMARTCARD_READER, PROV_RSA_FULL,
};

// UTF-16 encoded "Microsoft Base Smart Card Crypto Provider\0"
const CSP_NAME_W: &[u8] = &[
    77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0, 111, 0, 102, 0, 116, 0, 32, 0, 66, 0, 97, 0, 115, 0, 101, 0, 32, 0,
    83, 0, 109, 0, 97, 0, 114, 0, 116, 0, 32, 0, 67, 0, 97, 0, 114, 0, 100, 0, 32, 0, 67, 0, 114, 0, 121, 0, 112, 0,
    116, 0, 111, 0, 32, 0, 80, 0, 114, 0, 111, 0, 118, 0, 105, 0, 100, 0, 101, 0, 114, 0, 0, 0,
];
const CSP_NAME: &str = "Microsoft Base Smart Card Crypto Provider";

use crate::{Error, ErrorKind, Result};

#[instrument(level = "trace", ret)]
unsafe fn find_raw_cert_by_thumbprint(thumbprint: &[u8], cert_store: *mut c_void) -> Result<Vec<u8>> {
    let mut certificate = CertEnumCertificatesInStore(cert_store, null_mut());

    while !certificate.is_null() {
        let cert_der = from_raw_parts((*certificate).pbCertEncoded, (*certificate).cbCertEncoded as usize);

        let mut sha1 = Sha1::new();
        sha1.update(cert_der);
        let cert_thumbprint = sha1.finalize().to_vec();

        if cert_thumbprint == thumbprint {
            CertFreeCertificateContext(certificate);

            return Ok(cert_der.to_vec());
        }

        let next_certificate = CertEnumCertificatesInStore(cert_store, certificate);

        certificate = next_certificate;
    }

    Err(Error::new(
        ErrorKind::InternalError,
        "Cannot find appropriate device certificate",
    ))
}

unsafe fn open_user_cert_store() -> Result<*mut c_void> {
    // "My\0" encoded as a wide string.
    // More info: https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore#remarks
    let my: [u16; 3] = [77, 121, 0];
    let cert_store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
        my.as_ptr() as *const _,
    );

    if cert_store.is_null() {
        return Err(Error::new(
            ErrorKind::InternalError,
            "Cannot initialize certificate store: permission denied",
        ));
    }

    Ok(cert_store)
}

#[instrument(level = "trace", ret)]
pub unsafe fn extract_raw_certificate_by_thumbprint(thumbprint: &[u8]) -> Result<Vec<u8>> {
    let cert_store = open_user_cert_store()?;
    let cert = find_raw_cert_by_thumbprint(thumbprint, cert_store)?;

    CertCloseStore(cert_store, 0);

    Ok(cert)
}

#[instrument(level = "trace", ret)]
pub unsafe fn extract_certificate_by_thumbprint(thumbprint: &[u8]) -> Result<(Vec<u8>, Certificate)> {
    let raw_cert = extract_raw_certificate_by_thumbprint(thumbprint)?;

    Ok((raw_cert.to_vec(), picky_asn1_der::from_bytes(&raw_cert)?))
}

#[instrument(level = "trace", ret)]
unsafe fn acquire_key_container_context(key_container_name: &str) -> Result<HCRYPTPROV> {
    let container_name = key_container_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    let mut crypt_context_handle = HCRYPTPROV::default();

    if CryptAcquireContextW(
        &mut crypt_context_handle,
        container_name.as_ptr() as *const _,
        CSP_NAME_W.as_ptr() as *const _,
        PROV_RSA_FULL,
        CRYPT_SILENT,
    ) == 0
    {
        return Err(Error::new(
            ErrorKind::InternalError,
            "Cannot acquire crypt context handle.",
        ));
    }

    Ok(crypt_context_handle)
}

#[instrument(level = "trace", ret)]
unsafe fn get_reader_name(crypt_context_handle: HCRYPTPROV) -> Result<String> {
    let mut reader_buff_len = 0;
    if CryptGetProvParam(
        crypt_context_handle,
        PP_SMARTCARD_READER,
        null_mut(),
        &mut reader_buff_len,
        0,
    ) == 0
    {
        return Err(Error::new(ErrorKind::InternalError, "Cannot get reader name."));
    }

    let mut reader_buff = vec![0; reader_buff_len as usize];
    if CryptGetProvParam(
        crypt_context_handle,
        PP_SMARTCARD_READER,
        reader_buff.as_mut_ptr(),
        &mut reader_buff_len,
        0,
    ) == 0
    {
        return Err(Error::new(ErrorKind::InternalError, "Cannot get reader name."));
    }

    // remove null byte
    reader_buff.pop();

    String::from_utf8(reader_buff)
        .map_err(|_| Error::new(ErrorKind::InternalError, "reader name is not valid UTF-8 text"))
}

#[instrument(level = "trace", ret)]
pub unsafe fn get_key_container_certificate(crypt_context_handle: HCRYPTPROV) -> Result<Certificate> {
    let mut key = HCRYPTKEY::default();

    if CryptGetUserKey(crypt_context_handle, AT_KEYEXCHANGE, &mut key) == 0 {
        return Err(Error::new(ErrorKind::InternalError, "Cannot acquire key handle."));
    }

    let mut cert_data_len = 0;
    if CryptGetKeyParam(key, KP_CERTIFICATE, null_mut(), &mut cert_data_len, 0) == 0 {
        CryptDestroyKey(key);
        return Err(Error::new(ErrorKind::InternalError, "Cannot get certificate data len."));
    }

    let mut cert_data = vec![0; cert_data_len as usize];
    if CryptGetKeyParam(key, KP_CERTIFICATE, cert_data.as_mut_ptr(), &mut cert_data_len, 0) == 0 {
        CryptDestroyKey(key);
        return Err(Error::new(ErrorKind::InternalError, "Cannot get certificate data."));
    }

    CryptDestroyKey(key);

    Ok(picky_asn1_der::from_bytes(&cert_data)?)
}

#[derive(Debug)]
pub struct SmartCardInfo {
    pub key_container_name: String,
    pub reader_name: String,
    pub csp_name: String,
    pub certificate: Certificate,
    pub private_key_file_index: u8,
}

// This function gathers the smart card information like reader name, key container name,
// and so on using the provided certificate serial number.
// It iterates over existing key containers and tries to find a suitable reader name and key container.
// The similar approach is implemented in the FreeRDP for the smart card information gathering:
// https://github.com/FreeRDP/FreeRDP/blob/56324906a2d5b2538675e2f10b9f1ffe4a27de79/libfreerdp/core/smartcardlogon.c#L616
#[instrument(level = "trace", ret)]
pub unsafe fn finalize_smart_card_info(cert_serial_number: &[u8]) -> Result<SmartCardInfo> {
    let mut crypt_context_handle = HCRYPTPROV::default();
    if CryptAcquireContextW(
        &mut crypt_context_handle,
        null(),
        CSP_NAME_W.as_ptr() as *const _,
        PROV_RSA_FULL,
        CRYPT_SILENT,
    ) == 0
    {
        return Err(Error::new(
            ErrorKind::InternalError,
            "Cannot acquire crypt context handle.",
        ));
    }

    let mut key_container_name_len = 0;
    let mut is_first = true;
    let mut index = 1;
    loop {
        if CryptGetProvParam(
            crypt_context_handle,
            PP_ENUMCONTAINERS,
            null_mut(),
            &mut key_container_name_len,
            if is_first { CRYPT_FIRST } else { CRYPT_NEXT },
        ) == 0
        {
            break;
        }

        let mut key_container_name = vec![0; key_container_name_len as usize];

        if CryptGetProvParam(
            crypt_context_handle,
            PP_ENUMCONTAINERS,
            key_container_name.as_mut_ptr(),
            &mut key_container_name_len,
            if is_first { CRYPT_FIRST } else { CRYPT_NEXT },
        ) == 0
        {
            break;
        }
        let mut key_container_name = String::from_utf8(key_container_name).unwrap();
        // remove null char
        key_container_name.pop();

        let context = if let Ok(context) = acquire_key_container_context(&key_container_name) {
            context
        } else {
            index += 1;
            continue;
        };

        if let Ok(certificate) = get_key_container_certificate(context) {
            if certificate.tbs_certificate.serial_number.0 == cert_serial_number {
                let reader_name = get_reader_name(crypt_context_handle);

                CryptReleaseContext(crypt_context_handle, 0);

                let reader_name = match reader_name {
                    Ok(reader_name) => reader_name,
                    Err(err) => {
                        error!(?err);
                        continue;
                    }
                };

                return Ok(SmartCardInfo {
                    key_container_name,
                    reader_name,
                    certificate,
                    csp_name: CSP_NAME.to_owned(),
                    private_key_file_index: index,
                });
            }
        }

        CryptReleaseContext(crypt_context_handle, 0);

        index += 1;
        is_first = false;
    }

    Err(Error::new(ErrorKind::InternalError, "Cannot get smart card info"))
}

// This function tries to extract the user principal name from the smart card certificate by searching in the Subject Alternative Name.
#[instrument(level = "trace", ret)]
pub fn extract_user_name_from_certificate(certificate: &Certificate) -> Result<String> {
    let subject_alt_name_ext = &certificate
        .tbs_certificate
        .extensions
        .0
         .0
        .iter()
        .find(|extension| extension.extn_id().0 == oids::subject_alternative_name())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::IncompleteCredentials,
                "Subject alternative name certificate extension is not present",
            )
        })?
        .extn_value();

    let alternate_name = match subject_alt_name_ext {
        ExtensionView::SubjectAltName(alternate_name) => alternate_name,
        // safe: checked above
        _ => unreachable!("ExtensionView must be SubjectAltName"),
    };
    let other_name = match alternate_name.0.get(0).unwrap() {
        GeneralName::OtherName(other_name) => other_name,
        _ => {
            return Err(Error::new(
                ErrorKind::IncompleteCredentials,
                "Subject alternate name has unsupported value type",
            ))
        }
    };

    if other_name.type_id.0 != oids::user_principal_name() {
        return Err(Error::new(
            ErrorKind::IncompleteCredentials,
            "Subject alternate name must be UPN",
        ));
    }

    let data: Utf8StringAsn1 = picky_asn1_der::from_bytes(&other_name.value.0 .0)?;
    Ok(data.to_string())
}

#[cfg(test)]
mod tests {
    use picky::x509::Cert;
    use picky_asn1_x509::Certificate;

    use super::extract_user_name_from_certificate;

    #[test]
    fn username_extraction() {
        let certificate: Certificate = Cert::from_pem_str(include_str!("../test_assets/pw11.cer"))
            .unwrap()
            .into();

        assert_eq!(
            "pw11@example.com",
            extract_user_name_from_certificate(&certificate).unwrap()
        );
    }
}
