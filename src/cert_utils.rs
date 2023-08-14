use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;

use picky_asn1::wrapper::{IA5StringAsn1, Utf8StringAsn1};
use picky_asn1_x509::{
    oids, AttributeTypeAndValueParameters, Certificate, DirectoryString, ExtensionView, GeneralName,
};
use sha1::{Digest, Sha1};
use winapi::ctypes::c_void;
use winapi::um::ncrypt::HCRYPTKEY;
use winapi::um::wincrypt::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore, CryptAcquireContextW,
    CryptGetKeyParam, CryptGetProvParam, CryptGetUserKey, AT_KEYEXCHANGE, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_FIRST, CRYPT_NEXT, CRYPT_SILENT,
    HCRYPTPROV, KP_CERTIFICATE, PP_ENUMCONTAINERS, PP_SMARTCARD_READER, PROV_RSA_FULL,
};

const CSP_NAME: &str = "Microsoft Base Smart Card Crypto Provider\0";

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
unsafe fn acquire_context(key_container_name: &str) -> Result<HCRYPTPROV> {
    let mut container_name = key_container_name
        .encode_utf16()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    // add wire null char
    container_name.extend_from_slice(&[0, 0]);
    let csp_name = CSP_NAME
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
        return Err(Error::new(ErrorKind::InternalError, "Cannot get certificate data len."));
    }

    let mut cert_data = vec![0; cert_data_len as usize];
    if CryptGetKeyParam(key, KP_CERTIFICATE, cert_data.as_mut_ptr(), &mut cert_data_len, 0) == 0 {
        return Err(Error::new(ErrorKind::InternalError, "Cannot get certificate data."));
    }

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

#[instrument(level = "trace", ret)]
pub unsafe fn finalize_smart_card_info(cert_serial_number: &[u8]) -> Result<SmartCardInfo> {
    let csp_name = CSP_NAME
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
        println!(
            "key container name: {:?} {:?}",
            String::from_utf8(key_container_name.clone()),
            key_container_name
        );
        let mut key_container_name = String::from_utf8(key_container_name).unwrap();
        // remove null char
        key_container_name.pop();

        let context = if let Ok(context) = acquire_context(&key_container_name) {
            context
        } else {
            continue;
        };

        if let Ok(certificate) = get_key_container_certificate(context) {
            if certificate.tbs_certificate.serial_number.0 == cert_serial_number {
                let reader_name = match get_reader_name(crypt_context_handle) {
                    Ok(reader_name) => reader_name,
                    Err(err) => {
                        error!(?err);
                        continue;
                    }
                };

                let mut csp_name = CSP_NAME.to_owned();
                // remove null byte
                csp_name.pop();

                return Ok(SmartCardInfo {
                    key_container_name,
                    reader_name,
                    certificate,
                    csp_name,
                    private_key_file_index: index,
                });
            }

            index += 1;
        }

        is_first = false;
    }

    Err(Error::new(ErrorKind::InternalError, "Cannot get smart card info"))
}

#[instrument(level = "trace", ret)]
pub fn extract_user_name_from_alt_name(certificate: &Certificate) -> Result<String> {
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
        _ => unreachable!(),
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

#[instrument(level = "trace", ret)]
pub fn extract_user_name_from_subject_name(certificate: &Certificate) -> Result<String> {
    let subject = &certificate.tbs_certificate.subject.0 .0;
    let subject_parts = subject
        .iter()
        .map(|subject_part| {
            let set = subject_part.0.get(0).unwrap();
            let t = set.ty.0.clone();
            let v = match &set.value {
                AttributeTypeAndValueParameters::CommonName(DirectoryString::PrintableString(name)) => name.to_string(),
                AttributeTypeAndValueParameters::CommonName(DirectoryString::Utf8String(name)) => name.clone(),
                AttributeTypeAndValueParameters::Custom(custom) => {
                    let string: IA5StringAsn1 = picky_asn1_der::from_bytes(&custom.0)?;
                    string.to_string()
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::IncompleteCredentials,
                        "Common name has unsupported value type",
                    ))
                }
            };
            Ok((t, v))
        })
        .collect::<Result<Vec<_>>>()?;

    let domain = subject_parts
        .iter()
        .filter(|subject_part| subject_part.0 == oids::domain_component())
        .map(|subject_part| subject_part.1.as_str())
        .rev()
        .fold(String::new(), |mut domain, subject_part| {
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(subject_part);
            domain
        });

    let user_name = subject_parts
        .iter()
        .filter(|subject_part| subject_part.0 == oids::at_common_name())
        .skip(1)
        .map(|subject_part| subject_part.1.as_str())
        .next()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::IncompleteMessage,
                "User name is not present in certificate common name field",
            )
        })?;

    Ok(format!("{}@{}", user_name, domain))
}

pub fn extract_user_name_from_certificate(certificate: &Certificate) -> Result<String> {
    match extract_user_name_from_alt_name(certificate) {
        Ok(user_name) => Ok(user_name),
        Err(_) => extract_user_name_from_subject_name(certificate),
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_raw_certificate_by_thumbprint, extract_user_name_from_alt_name};
    use crate::cert_utils::{
        extract_certificate_by_thumbprint, extract_user_name_from_subject_name, finalize_smart_card_info,
    };

    #[test]
    fn smart_card_info() {
        let serial_number = [
            126, 0, 0, 0, 15, 203, 194, 190, 102, 29, 163, 34, 144, 0, 0, 0, 0, 0, 15,
        ];
        println!("{:?}", unsafe { finalize_smart_card_info(&serial_number).unwrap() });
    }

    #[test]
    fn cert() {
        println!("cert here: {:?}", unsafe {
            extract_certificate_by_thumbprint(&[60, 51, 235, 194, 72, 148, 15, 37, 176, 168, 245, 241, 146, 185, 12, 11, 235, 139, 141, 82]).unwrap()
        });
    }

    #[test]
    fn username_extraction() {
        let cert = unsafe {
            extract_certificate_by_thumbprint(&[
                244, 5, 6, 138, 23, 82, 125, 87, 234, 251, 176, 71, 81, 51, 245, 207, 224, 92, 147, 141,
            ])
            .unwrap()
        };
        // dbg!(cert.1.clone());
        println!("username: {}", extract_user_name_from_alt_name(&cert.1).unwrap());
        println!("username: {}", extract_user_name_from_subject_name(&cert.1).unwrap());
    }
}
