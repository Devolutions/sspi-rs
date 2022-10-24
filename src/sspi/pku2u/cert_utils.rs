use picky_asn1_x509::{
    signed_data::{CertificateChoices, SignedData},
    Certificate, PublicKey,
};
use rsa::{BigUint, RsaPublicKey};
use schannel::cert_store::CertStore;
use winapi::um::wincrypt::CryptExportKey;

use crate::{Error, ErrorKind, Result};

/// Tries to find the device certificate and its private key
/// Requirements for the device certificate:
/// 1. Issuer CN = MS-Organization-Access
/// 2. Issuer OU = 82dbaca4-3e81-46ca-9c73-0950c1eaca97
pub fn extract_device_certificate() -> Result<()> {
    let cert_store = CertStore::open_local_machine("My").unwrap();
    let certs = cert_store.certs();

    for cert in certs {
        let certificate: Certificate = picky_asn1_der::from_bytes(cert.to_der())?;
        let mut cn = false;
        let mut ou = false;

        for issuer_info in certificate.tbs_certificate.issuer.0 .0 {
            for is in issuer_info.0 {
                println!("is: {:?}", is);
            }
        }

        if cn && ou {
            println!("found");
            let private_key = cert.private_key().acquire().unwrap();
            // let p = cert.

            use schannel::key_handle::KeyHandle;

            let mut v1 = vec![0; 5000];
            let mut len = 0;

            match private_key {
                KeyHandle::CryptProv(key_handle) => {
                    // key_handle.
                    unsafe {
                        //
                        let result = CryptExportKey(0, 0, 0, 0, v1.as_mut_ptr(), &mut len);
                    }
                }
                KeyHandle::NcryptKey(ncrypt) => {
                    // let r = ncrypt.borrow_mut();
                }
            }
        }
        println!("===============");
    }

    Ok(())
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
