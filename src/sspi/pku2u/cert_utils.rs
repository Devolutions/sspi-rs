use std::{ptr::{null, null_mut}, ffi::OsStr, os::windows::prelude::OsStrExt, slice::from_raw_parts};

use picky_asn1_x509::{
    signed_data::{CertificateChoices, SignedData},
    Certificate, PublicKey,
};
use rsa::{BigUint, RsaPublicKey};
use winapi::{um::wincrypt::{
    CertOpenStore, CryptExportKey, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
    CERT_SYSTEM_STORE_LOCATION_SHIFT, CertEnumCertificatesInStore, CryptAcquireCertificatePrivateKey, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, CERT_NCRYPT_KEY_SPEC,
}, shared::bcrypt::BCRYPT_RSAFULLPRIVATE_BLOB};
use windows_sys::Win32::{Security::Cryptography::{CERT_KEY_SPEC, NCryptExportKey}, Foundation};

use crate::{Error, ErrorKind, Result, utils::string_to_utf16};

/// Tries to find the device certificate and its private key
/// Requirements for the device certificate:
/// 1. Issuer CN = MS-Organization-Access
/// 2. Issuer OU = 82dbaca4-3e81-46ca-9c73-0950c1eaca97
pub fn extract_device_certificate() -> Result<()> {
    unsafe {
        let which = "My";
        let data = OsStr::new(which)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
        let cert_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT,
            data.as_ptr() as *mut _,
        );

        if cert_store.is_null() {
            return Err(Error::new(
                ErrorKind::InternalError,
                "Cannot initialize certificate store: permission denied".into(),
            ));
        }

        println!("cert_store: {:?}", cert_store);
        
        let mut certificate = CertEnumCertificatesInStore(
            cert_store,
            null_mut(),
        );

        println!("cert: {:?}", certificate);

        while !certificate.is_null() {
            println!("loop: {:?}", certificate);

            println!("{:?}", (*certificate).pbCertEncoded);
            println!("{:?}", (*certificate).cbCertEncoded);

            let cert_der = from_raw_parts((*certificate).pbCertEncoded, (*certificate).cbCertEncoded as usize);
            let cert: Certificate = picky_asn1_der::from_bytes(cert_der)?;

            let mut private_key_handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
            let mut spec = CERT_KEY_SPEC::default();
            let mut free = Foundation::BOOL::default();
            
            // extract private key
            let status = CryptAcquireCertificatePrivateKey(
                certificate,
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                null_mut(),
                &mut private_key_handle,
                &mut spec,
                &mut free,
            );

            println!("status: {}, free: {:?}, handle: {}", status, free, private_key_handle);

            if status != 0 && private_key_handle != 0 {
                println!("try export private key");

                let mut key_blob = null_mut();
                let mut result_len = 0;

                let blob_type_wide = string_to_utf16(BCRYPT_RSAFULLPRIVATE_BLOB);
                
                if spec & CERT_NCRYPT_KEY_SPEC != 0 {
                    println!("ncrypt");
                    let status = NCryptExportKey(
                        private_key_handle as _,
                        0,
                        blob_type_wide.as_ptr() as *const _,
                        null(),
                        key_blob,
                        0,
                        &mut result_len,
                        0,
                    );

                    println!("status: {}, key_blob: {:?}, result_len: {}", status, key_blob, result_len);
                } else {
                    println!("crypt");
                }
            }

            certificate = CertEnumCertificatesInStore(cert_store, certificate);
        }
    }

    Err(Error::new(ErrorKind::InternalError, "Cannot find appropriate device certificate".into()))
}

/// validates server's p2p certificate.
/// If certificate is valid then return its public key.
pub fn validate_server_p2p_certificate(signed_data: &SignedData, _ca_cert: &Certificate) -> Result<RsaPublicKey> {
    let certificates = &signed_data.certificates.0 .0;

    for certificate in certificates {
        let cert: Certificate = match certificate {
            CertificateChoices::Certificate(cert) => picky_asn1_der::from_bytes(&cert.0)?,
            _ => {
                return Err(Error::new(
                    ErrorKind::CertificateUnknown,
                    "Received unknown certificate format".into(),
                ))
            }
        };

        let public_key = match cert.tbs_certificate.subject_public_key_info.subject_public_key {
            PublicKey::Rsa(rsa) => rsa,
            _ => {
                return Err(Error::new(
                    ErrorKind::CertificateUnknown,
                    "Received certificate has unsupported public key type. Only RSA is supported.".into(),
                ))
            }
        }
        .0;

        return Ok(RsaPublicKey::new(
            BigUint::from_bytes_be(&public_key.modulus.0),
            BigUint::from_bytes_be(&public_key.public_exponent.0),
        )
        .map_err(|err| {
            Error::new(
                ErrorKind::InvalidToken,
                format!("Invalid certificate public key: {:?}", err),
            )
        })?);
    }

    Err(Error::new(
        ErrorKind::CertificateUnknown,
        "Received invalid server certificates".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::extract_device_certificate;

    #[test]
    fn ts() {
        extract_device_certificate().unwrap();
    }
}
