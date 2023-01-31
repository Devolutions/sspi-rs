use std::ffi::c_void;
use std::io::Read;
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;

use byteorder::{LittleEndian, ReadBytesExt};
use num_bigint_dig::BigUint;
use picky::key::PrivateKey;
use picky_asn1_x509::{oids, AttributeTypeAndValueParameters, Certificate, ExtensionView};
use winapi::shared::bcrypt::{BCRYPT_RSAFULLPRIVATE_BLOB, BCRYPT_RSAFULLPRIVATE_MAGIC};
use winapi::um::ncrypt::NCryptFreeObject;
use winapi::um::wincrypt::{
    CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext, CertOpenStore,
    CryptAcquireCertificatePrivateKey, CERT_CONTEXT, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER_ID,
    CERT_SYSTEM_STORE_LOCATION_SHIFT, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
};
use windows_sys::Win32::Foundation;
use windows_sys::Win32::Security::Cryptography::{NCryptExportKey, CERT_KEY_SPEC};

use crate::utils::string_to_utf16;
use crate::{Error, ErrorKind, Result};

/// [BCRYPT_RSAKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob)
/// ```not_rust
/// typedef struct _BCRYPT_RSAKEY_BLOB {
///   ULONG Magic;
///   ULONG BitLength;
///   ULONG cbPublicExp;
///   ULONG cbModulus;
///   ULONG cbPrime1;
///   ULONG cbPrime2;
/// } BCRYPT_RSAKEY_BLOB;
/// ```
#[derive(Debug)]
struct BcryptRsaKeyBlob {
    pub magic: u32,
    pub bit_len: u32,
    pub public_exp: u32,
    pub modulus: u32,
    pub prime1: u32,
    pub prime2: u32,
}

impl BcryptRsaKeyBlob {
    pub fn from_read(mut data: impl Read) -> Result<Self> {
        Ok(Self {
            magic: data.read_u32::<LittleEndian>()?,
            bit_len: data.read_u32::<LittleEndian>()?,
            public_exp: data.read_u32::<LittleEndian>()?,
            modulus: data.read_u32::<LittleEndian>()?,
            prime1: data.read_u32::<LittleEndian>()?,
            prime2: data.read_u32::<LittleEndian>()?,
        })
    }
}

fn decode_private_key(mut buffer: impl Read) -> Result<PrivateKey> {
    let rsa_key_blob = BcryptRsaKeyBlob::from_read(&mut buffer)?;

    if rsa_key_blob.magic != BCRYPT_RSAFULLPRIVATE_MAGIC {
        return Err(Error::new(
            ErrorKind::InternalError,
            "Cannot extract certificate private key: invalid key blob magic".into(),
        ));
    }

    let mut public_exp = vec![0; rsa_key_blob.public_exp as usize];
    buffer.read_exact(&mut public_exp)?;

    let mut modulus = vec![0; rsa_key_blob.modulus as usize];
    buffer.read_exact(&mut modulus)?;

    let mut prime1 = vec![0; rsa_key_blob.prime1 as usize];
    buffer.read_exact(&mut prime1)?;

    let mut prime2 = vec![0; rsa_key_blob.prime2 as usize];
    buffer.read_exact(&mut prime2)?;

    let mut exp = vec![0; rsa_key_blob.prime1 as usize];
    buffer.read_exact(&mut exp)?;

    let mut exp = vec![0; rsa_key_blob.prime2 as usize];
    buffer.read_exact(&mut exp)?;

    let mut coef = vec![0; rsa_key_blob.prime1 as usize];
    buffer.read_exact(&mut coef)?;

    let mut private_exp = vec![0; (rsa_key_blob.bit_len / 8) as usize];
    buffer.read_exact(&mut private_exp)?;

    let rsa_private_key = PrivateKey::from_rsa_components(
        &BigUint::from_bytes_be(&modulus),
        &BigUint::from_bytes_be(&public_exp),
        &BigUint::from_bytes_be(&private_exp),
        &[BigUint::from_bytes_be(&prime1), BigUint::from_bytes_be(&prime2)],
    )
    .map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("Can not create a private from components: {:?}", err),
        )
    })?;

    Ok(rsa_private_key)
}

/// Validates the device certificate
/// Requirements for the device certificate:
/// 1. Issuer CN starts with 'MS-Organization-P2P-Access'
/// 2. ClientAuth extended key usage present
fn validate_client_p2p_certificate(certificate: &Certificate) -> bool {
    let mut cn = false;

    for attr_type_and_value in certificate.tbs_certificate.issuer.0 .0.iter() {
        for v in attr_type_and_value.0.iter() {
            if v.ty.0 == oids::at_common_name() {
                if let AttributeTypeAndValueParameters::CommonName(name) = &v.value {
                    if name.to_utf8_lossy().starts_with("MS-Organization-P2P-Access") {
                        cn = true;
                    }
                }
            }
        }
    }

    if !cn {
        return false;
    }

    let mut client_auth = false;

    for extension in &certificate.tbs_certificate.extensions.0 .0 {
        if extension.extn_id().0 == oids::extended_key_usage() {
            if let ExtensionView::ExtendedKeyUsage(ext_key_usage) = extension.extn_value() {
                if ext_key_usage.contains(oids::kp_client_auth()) {
                    client_auth = true;
                }
            }
        }
    }

    client_auth
}

unsafe fn export_certificate_private_key(cert: *const CERT_CONTEXT) -> Result<PrivateKey> {
    let mut private_key_handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
    let mut spec = CERT_KEY_SPEC::default();
    let mut free = Foundation::BOOL::default();

    let status = CryptAcquireCertificatePrivateKey(
        cert,
        CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
        null_mut(),
        &mut private_key_handle,
        &mut spec,
        &mut free,
    );

    if status == 0 || private_key_handle == 0 {
        return Err(Error::new(
            ErrorKind::InternalError,
            "Cannot extract certificate private key: invalid handle".into(),
        ));
    }

    let mut private_key_buffer_len = 0;

    let mut blob_type_wide = string_to_utf16(BCRYPT_RSAFULLPRIVATE_BLOB);
    // add NULL char because the Rust library literal doesn't have it
    blob_type_wide.extend_from_slice(&[0, 0]);

    // The first call need to determine the size of the needed buffer for the private key
    // https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey
    // If pbOutput parameter is NULL, this function will place the required size in the pcbResult parameter.
    let status = NCryptExportKey(
        private_key_handle as _,
        0,
        blob_type_wide.as_ptr() as *const _,
        null(),
        null_mut::<u8>(),
        0,
        &mut private_key_buffer_len,
        0,
    );

    if status != 0 {
        NCryptFreeObject(private_key_handle);

        return Err(Error::new(
            ErrorKind::InternalError,
            format!(
                "Cannot extract certificate private key: unsuccessful extraction: {:x?}",
                status
            ),
        ));
    }

    let mut private_key_blob = vec![0; private_key_buffer_len as usize];

    let status = NCryptExportKey(
        private_key_handle as _,
        0,
        blob_type_wide.as_ptr() as *const _,
        null(),
        private_key_blob.as_mut_ptr(),
        private_key_blob.len() as _,
        &mut private_key_buffer_len,
        0,
    );

    NCryptFreeObject(private_key_handle);

    if status != 0 {
        return Err(Error::new(
            ErrorKind::InternalError,
            format!(
                "Cannot extract certificate private key: unsuccessful extraction: {:x?}",
                status
            ),
        ));
    }

    let private_key = decode_private_key(&private_key_blob[0..private_key_buffer_len as usize])?;

    Ok(private_key)
}

unsafe fn extract_client_p2p_certificate(cert_store: *mut c_void) -> Result<(Certificate, PrivateKey)> {
    let mut certificate = CertEnumCertificatesInStore(cert_store, null_mut());

    while !certificate.is_null() {
        let cert_der = from_raw_parts((*certificate).pbCertEncoded, (*certificate).cbCertEncoded as usize);
        let cert: Certificate = picky_asn1_der::from_bytes(cert_der)?;

        if !validate_client_p2p_certificate(&cert) {
            let next_certificate = CertEnumCertificatesInStore(cert_store, certificate);

            certificate = next_certificate;

            continue;
        }

        let private_key = export_certificate_private_key(certificate);

        CertFreeCertificateContext(certificate);

        return Ok((cert, private_key?));
    }

    Err(Error::new(
        ErrorKind::InternalError,
        "Cannot find appropriate device certificate".into(),
    ))
}

// There is no specification/documentation that said where the P2P certificates should be installed.
// During dev testing, we notice that they always are in the Personal folder.
// So we assume that the needed certificates are placed in this folder
// It uses the "My" certificates store that has access to the Personal folder in order to extract those certificates.
pub fn extract_client_p2p_cert_and_key() -> Result<(Certificate, PrivateKey)> {
    unsafe {
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
                "Cannot initialize certificate store: permission denied".into(),
            ));
        }

        let cert_and_key = extract_client_p2p_certificate(cert_store);

        CertCloseStore(cert_store, 0);

        cert_and_key
    }
}

#[cfg(test)]
mod tests {
    use picky_asn1_x509::Certificate;

    use super::validate_client_p2p_certificate;

    #[test]
    fn test_client_p2p_certificate_validation() {
        let certificate: Certificate = picky_asn1_der::from_bytes(&[
            48, 130, 3, 213, 48, 130, 2, 189, 160, 3, 2, 1, 2, 2, 16, 51, 247, 184, 98, 224, 162, 21, 50, 174, 177,
            189, 96, 58, 124, 107, 164, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 77, 49, 75, 48,
            73, 6, 3, 85, 4, 3, 30, 66, 0, 77, 0, 83, 0, 45, 0, 79, 0, 114, 0, 103, 0, 97, 0, 110, 0, 105, 0, 122, 0,
            97, 0, 116, 0, 105, 0, 111, 0, 110, 0, 45, 0, 80, 0, 50, 0, 80, 0, 45, 0, 65, 0, 99, 0, 99, 0, 101, 0, 115,
            0, 115, 0, 32, 0, 91, 0, 50, 0, 48, 0, 50, 0, 50, 0, 93, 48, 30, 23, 13, 50, 50, 49, 48, 50, 54, 49, 51,
            50, 51, 53, 56, 90, 23, 13, 50, 50, 49, 48, 50, 54, 49, 52, 50, 56, 53, 56, 90, 48, 129, 142, 49, 52, 48,
            50, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 36, 97, 57, 50, 53, 50, 52, 52, 56, 45, 57, 97,
            98, 55, 45, 52, 57, 98, 48, 45, 98, 98, 53, 99, 45, 102, 50, 102, 57, 50, 51, 99, 56, 52, 54, 55, 50, 49,
            61, 48, 59, 6, 3, 85, 4, 3, 12, 52, 83, 45, 49, 45, 49, 50, 45, 49, 45, 51, 54, 53, 51, 50, 49, 49, 48, 50,
            50, 45, 49, 51, 51, 57, 48, 48, 54, 52, 50, 50, 45, 50, 54, 50, 55, 53, 55, 51, 57, 48, 48, 45, 49, 53, 54,
            48, 55, 51, 52, 57, 49, 57, 49, 23, 48, 21, 6, 3, 85, 4, 3, 12, 14, 115, 55, 64, 100, 97, 116, 97, 97, 110,
            115, 46, 99, 111, 109, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1,
            15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 199, 60, 253, 49, 157, 172, 15, 185, 180, 104, 241, 218, 22, 185,
            120, 213, 135, 223, 222, 100, 75, 148, 218, 177, 71, 131, 140, 8, 195, 173, 7, 244, 41, 200, 45, 77, 173,
            68, 205, 213, 27, 72, 246, 147, 167, 184, 52, 81, 44, 28, 143, 238, 201, 186, 143, 111, 62, 224, 73, 86,
            69, 249, 239, 44, 79, 115, 37, 185, 243, 1, 23, 234, 116, 28, 244, 221, 99, 62, 177, 39, 128, 239, 115, 47,
            184, 135, 25, 43, 109, 246, 200, 11, 116, 38, 99, 167, 136, 48, 59, 187, 188, 40, 216, 85, 133, 246, 5,
            130, 177, 220, 6, 210, 34, 164, 15, 207, 125, 223, 42, 190, 77, 109, 69, 224, 132, 147, 115, 110, 39, 205,
            112, 140, 44, 215, 43, 252, 206, 89, 55, 161, 210, 166, 234, 223, 0, 198, 24, 70, 158, 56, 78, 23, 76, 249,
            86, 198, 95, 207, 53, 220, 75, 246, 91, 138, 99, 193, 186, 97, 57, 207, 115, 14, 1, 251, 111, 180, 121, 41,
            132, 254, 82, 109, 66, 202, 11, 20, 14, 31, 242, 55, 225, 112, 210, 220, 229, 155, 152, 202, 92, 54, 223,
            38, 153, 248, 173, 168, 180, 70, 146, 219, 186, 166, 251, 234, 149, 41, 18, 61, 227, 148, 13, 141, 229, 1,
            49, 212, 128, 67, 225, 120, 7, 122, 41, 102, 241, 223, 249, 198, 117, 89, 37, 177, 142, 85, 24, 136, 230,
            160, 136, 43, 89, 66, 41, 220, 85, 85, 2, 3, 1, 0, 1, 163, 111, 48, 109, 48, 14, 6, 3, 85, 29, 15, 1, 1,
            255, 4, 4, 3, 2, 5, 160, 48, 41, 6, 3, 85, 29, 17, 4, 34, 48, 32, 160, 30, 6, 10, 43, 6, 1, 4, 1, 130, 55,
            20, 2, 3, 160, 16, 12, 14, 115, 55, 64, 100, 97, 116, 97, 97, 110, 115, 46, 99, 111, 109, 48, 19, 6, 3, 85,
            29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 27, 6, 9, 43, 6, 1, 4, 1, 130, 55, 21, 10, 4, 14,
            48, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3,
            130, 1, 1, 0, 71, 217, 65, 65, 121, 161, 60, 132, 114, 210, 31, 169, 34, 170, 87, 169, 50, 137, 52, 187,
            116, 98, 61, 8, 255, 89, 197, 131, 73, 33, 17, 136, 188, 42, 180, 22, 239, 101, 126, 28, 138, 35, 108, 101,
            138, 50, 54, 5, 105, 17, 85, 172, 239, 78, 21, 202, 246, 237, 51, 210, 17, 184, 39, 190, 135, 109, 73, 210,
            243, 138, 142, 72, 67, 206, 58, 129, 133, 215, 161, 103, 57, 97, 99, 131, 85, 45, 160, 129, 144, 5, 184,
            191, 7, 114, 24, 7, 237, 81, 246, 242, 94, 232, 161, 230, 108, 97, 184, 185, 182, 200, 178, 44, 7, 76, 10,
            47, 156, 88, 110, 198, 193, 125, 190, 84, 225, 93, 53, 87, 183, 14, 49, 118, 233, 217, 171, 139, 75, 131,
            8, 222, 241, 87, 3, 146, 243, 55, 69, 62, 204, 146, 92, 118, 241, 104, 209, 178, 228, 246, 199, 220, 104,
            32, 189, 125, 84, 82, 250, 215, 218, 10, 9, 21, 185, 251, 180, 51, 254, 67, 144, 78, 230, 201, 78, 127, 92,
            159, 26, 51, 223, 195, 192, 177, 251, 137, 234, 64, 37, 65, 76, 246, 118, 216, 224, 83, 152, 110, 67, 117,
            201, 2, 253, 173, 128, 73, 76, 26, 179, 93, 24, 227, 242, 121, 254, 170, 226, 31, 88, 196, 194, 58, 86,
            255, 192, 36, 221, 100, 20, 198, 221, 242, 249, 196, 211, 98, 111, 198, 220, 135, 239, 82, 74, 139, 243, 2,
            25, 215,
        ])
        .unwrap();

        assert!(validate_client_p2p_certificate(&certificate));
    }
}
