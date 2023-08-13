use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;

use picky_asn1_x509::Certificate;
use sha1::{Digest, Sha1};
use winapi::ctypes::c_void;
use winapi::um::ncrypt::HCRYPTKEY;
use winapi::um::wincrypt::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore, CryptAcquireContextW,
    CryptGetKeyParam, CryptGetProvParam, CryptGetUserKey, AT_KEYEXCHANGE, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_FIRST, CRYPT_NEXT, CRYPT_SILENT,
    HCRYPTPROV, KP_CERTIFICATE, PP_ENUMCONTAINERS, PP_SMARTCARD_READER, PROV_RSA_FULL,
};

use crate::{Result, Error, ErrorKind};

unsafe fn find_cert_by_thumbprint(thumbprint: &[u8], cert_store: *mut c_void) -> Result<Certificate> {
    let mut certificate = CertEnumCertificatesInStore(cert_store, null_mut());

    while !certificate.is_null() {
        let cert_der = from_raw_parts((*certificate).pbCertEncoded, (*certificate).cbCertEncoded as usize);
        
        let mut sha1 = Sha1::new();
        sha1.update(cert_der);
        let cert_thumbprint = sha1.finalize().to_vec();

        if cert_thumbprint == thumbprint {
            let cert: Certificate = picky_asn1_der::from_bytes(cert_der)?;

            CertFreeCertificateContext(certificate);

            return Ok(cert);
        }

        let next_certificate = CertEnumCertificatesInStore(cert_store, certificate);

        certificate = next_certificate;
    }

    Err(Error::new(
        ErrorKind::InternalError,
        "Cannot find appropriate device certificate",
    ))
}

pub unsafe fn extract_certificate_by_thumbprint(thumbprint: &[u8]) -> Result<Certificate> {
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

    let cert = find_cert_by_thumbprint(thumbprint, cert_store)?;

    CertCloseStore(cert_store, 0);

    Ok(cert)
}

unsafe fn acquire_context(key_container_name: &str) -> Result<HCRYPTPROV> {
    let container_name = key_container_name
        .encode_utf16()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    let csp_name = "Microsoft Base Smart Card Crypto Provider"
        .encode_utf16()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    let mut crypt_context_handle = HCRYPTPROV::default();

    if CryptAcquireContextW(
        &mut crypt_context_handle,
        container_name.as_ptr() as *const _,
        csp_name.as_ptr() as *const _,
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

    String::from_utf8(reader_buff)
        .map_err(|_| Error::new(ErrorKind::InternalError, "reader name is not valid UTF-8 text"))
}

pub unsafe fn get_key_container_certificate(crypt_context_handle: HCRYPTPROV) -> Result<Certificate> {
    let mut key = HCRYPTKEY::default();

    if CryptGetUserKey(crypt_context_handle, AT_KEYEXCHANGE, &mut key) == 0 {
        return Err(Error::new(ErrorKind::InternalError, "Cannot acquire key handle."));
    }

    let mut cert_data_len = 0;
    if CryptGetKeyParam(key, KP_CERTIFICATE, null_mut(), &mut cert_data_len, 0) == 0 {
        return Err(Error::new(ErrorKind::InternalError, "Cannot get certificate data len."));
    }

    let mut cert_data = vec![0; cert_data_len as usize];
    if CryptGetKeyParam(key, KP_CERTIFICATE, cert_data.as_mut_ptr(), &mut cert_data_len, 0) == 0 {
        return Err(Error::new(ErrorKind::InternalError, "Cannot get certificate data."));
    }

    Ok(picky_asn1_der::from_bytes(&cert_data)?)
}

pub struct SmartCardInfo {
    pub key_container_name: String,
    pub reader_name: String,
    pub certificate: Certificate,
}

pub unsafe fn finalize_smart_card_info(cert_serial_number: &[u8]) -> Result<SmartCardInfo> {
    let csp_name = "Microsoft Base Smart Card Crypto Provider"
        .encode_utf16()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();

    let mut crypt_context_handle = HCRYPTPROV::default();
    if CryptAcquireContextW(
        &mut crypt_context_handle,
        null(),
        csp_name.as_ptr() as *const _,
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
        println!(
            "key container name: {:?} {:?}",
            String::from_utf8(key_container_name.clone()),
            key_container_name
        );
        let key_container_name = String::from_utf8(key_container_name).unwrap();

        let context = acquire_context(&key_container_name)?;

        if let Ok(certificate) = get_key_container_certificate(context) {
            if certificate.tbs_certificate.serial_number.0 == cert_serial_number {
                let reader_name = match get_reader_name(crypt_context_handle) {
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
                });
            }
        }

        is_first = false;
    }

    Err(Error::new(ErrorKind::InternalError, "Cannot get smart card info"))
}

#[cfg(test)]
mod tests {
    use super::extract_certificate_by_thumbprint;

    #[test]
    fn cert() {
        println!("cert here: {:?}", unsafe {
            extract_certificate_by_thumbprint(&[60, 51, 235, 194, 72, 148, 15, 37, 176, 168, 245, 241, 146, 185, 12, 11, 235, 139, 141, 82]).unwrap()
        });
    }
}
