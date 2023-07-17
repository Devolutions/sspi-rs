use std::{slice::from_raw_parts, ptr::null_mut};

use picky_asn1_x509::Certificate;
use sha1::{Sha1, Digest};
use winapi::{um::wincrypt::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore,
    CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER_ID,
    CERT_SYSTEM_STORE_LOCATION_SHIFT,
}, ctypes::c_void};

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
