#![cfg(feature = "scard")]

use std::borrow::Cow;
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

#[cfg(not(target_arch = "wasm32"))]
use cryptoki::context::{CInitializeArgs, Pkcs11};
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::mechanism::Mechanism;
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::session::{Session, UserType};
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::types::AuthPin;
use picky::key::PrivateKey;
use picky_asn1_x509::Certificate;
use uuid::Uuid;
use winscard::SmartCard as PivSmartCard;

use crate::pk_init::SigningScheme;
use crate::{Error, ErrorKind, Result, Secret, SmartCardIdentity, SmartCardType};

/// Smart cad API to use.
pub(crate) enum SmartCardApi {
    /// Represents emulated smart cards API.
    ///
    /// No real device or driver is needed.
    PivEmulated(Box<PivSmartCard<'static>>),
    #[cfg(not(target_arch = "wasm32"))]
    /// Represents system-provided smart card API.
    ///
    /// PKCS11 API will be used for data signing.
    Pkcs11 {
        /// PKCS11 module.
        pkcs11_module: Pkcs11,
        /// Reader name.
        ///
        /// Reader name is needed to determine which PKCS11 slot to use.
        reader_name: String,
        /// Smart card certificate.
        ///
        /// It is needed to determine which private key to use: a token can contain several of them.
        certificate: Box<Certificate>,
    },
    /// Represents Windows native smart card API.
    ///
    /// The native Windows API will be used for data signing.
    #[cfg(target_os = "windows")]
    Windows {
        /// key container name.
        container_name: String,
    },
}

impl fmt::Debug for SmartCardApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PivEmulated { .. } => f.write_str("SmartCardApi::PivEmulated"),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Pkcs11 { .. } => f.write_str("SmartCardApi::Pkcs11"),
            #[cfg(target_os = "windows")]
            Self::Windows { .. } => f.write_str("SmartCardApi::Windows"),
        }
    }
}

/// Generic interface for data signing using smart card.
///
/// This implementation can use any supported smart card type. It depends on the provided credentials set.
#[derive(Debug)]
pub(crate) struct SmartCard {
    smart_card_type: SmartCardApi,
    pin: Secret<Vec<u8>>,
    /// Signature scheme determined by the type of the smart card certificate key.
    signing_scheme: SigningScheme,
}

impl SmartCard {
    /// Creates a new [SmartCard] instance from the provided credentials.
    pub(crate) fn from_credentials(credentials: &SmartCardIdentity) -> Result<Self> {
        let SmartCardIdentity {
            username: _,
            certificate,
            reader_name,
            card_name: _,
            container_name: _container_name,
            csp_name: _,
            pin: user_pin,
            private_key,
            scard_type,
        } = credentials;

        let user_pin = user_pin.clone();
        let signing_scheme = SigningScheme::from_certificate(certificate)?;

        match scard_type {
            SmartCardType::Emulated { scard_pin } => {
                let private_key = private_key
                    .as_ref()
                    .ok_or(Error::new(
                        ErrorKind::IncompleteCredentials,
                        "emulated smart card private key is missing",
                    ))?
                    .as_ref()
                    .clone();

                Self::new_emulated(
                    Cow::Owned(reader_name.clone()),
                    scard_pin.as_ref().to_vec(),
                    user_pin,
                    private_key,
                    certificate,
                    signing_scheme,
                )
            }
            #[cfg(not(target_arch = "wasm32"))]
            SmartCardType::SystemProvided { pkcs11_module_path } => Self::new_system_provided(
                pkcs11_module_path,
                user_pin,
                reader_name.clone(),
                certificate.clone(),
                signing_scheme,
            ),
            #[cfg(target_os = "windows")]
            SmartCardType::WindowsNative => {
                if signing_scheme != SigningScheme::RsaSha1 {
                    return Err(Error::new(
                        ErrorKind::OperationNotSupported,
                        "EC keys are not supported by the Windows native smart card API yet",
                    ));
                }

                Self::new_windows_native(
                    user_pin,
                    _container_name
                        .as_ref()
                        .ok_or_else(|| Error::new(ErrorKind::NoCredentials, "container name is not provided"))?
                        .to_owned(),
                    signing_scheme,
                )
            }
        }
    }

    /// Creates a new [SmartCard] instance with the emulated smart card inside.
    fn new_emulated(
        reader_name: Cow<'static, str>,
        scard_pin: Vec<u8>,
        user_pin: Secret<Vec<u8>>,
        private_key: PrivateKey,
        certificate: &Certificate,
        signing_scheme: SigningScheme,
    ) -> Result<Self> {
        // The emulated smart card keeps the certificate in the form it returns it to the caller.
        let auth_cert_der = picky_asn1_der::to_vec(certificate)?;

        // This smart card is not backed by any resource manager context, so it has no externally
        // assigned identity: generate a fresh one for it.
        let scard = PivSmartCard::new(reader_name, Uuid::new_v4(), scard_pin, auth_cert_der, private_key)?;

        Ok(Self {
            smart_card_type: SmartCardApi::PivEmulated(Box::new(scard)),
            pin: user_pin,
            signing_scheme,
        })
    }

    /// Creates a new [SmartCard] instance with the system provided smart card inside (Windows API).
    #[cfg(target_os = "windows")]
    fn new_windows_native(
        user_pin: Secret<Vec<u8>>,
        container_name: String,
        signing_scheme: SigningScheme,
    ) -> Result<Self> {
        Ok(Self {
            smart_card_type: SmartCardApi::Windows { container_name },
            pin: user_pin,
            signing_scheme,
        })
    }

    /// Creates a new [SmartCard] instance with the system provided smart card inside.
    #[cfg(not(target_arch = "wasm32"))]
    fn new_system_provided(
        pkcs11_module_path: &Path,
        user_pin: Secret<Vec<u8>>,
        reader_name: String,
        certificate: Certificate,
        signing_scheme: SigningScheme,
    ) -> Result<Self> {
        use cryptoki::context::CInitializeFlags;

        let pkcs11 = Pkcs11::new(pkcs11_module_path)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

        Ok(Self {
            smart_card_type: SmartCardApi::Pkcs11 {
                pkcs11_module: pkcs11,
                reader_name,
                certificate: Box::new(certificate),
            },
            pin: user_pin,
            signing_scheme,
        })
    }

    /// Signs the provided data using smart card.
    ///
    /// The data is hashed according to the signing scheme of the smart card certificate key.
    pub(crate) fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let digest = self.signing_scheme.digest(data);

        match &mut self.smart_card_type {
            SmartCardApi::PivEmulated(scard) => {
                scard.verify_pin(self.pin.as_ref())?;

                Ok(match self.signing_scheme {
                    SigningScheme::RsaSha1 => scard.sign_hashed(digest)?,
                    SigningScheme::EcdsaP256Sha256 => scard.sign_ecdsa_hashed(digest)?,
                })
            }
            #[cfg(not(target_arch = "wasm32"))]
            SmartCardApi::Pkcs11 {
                pkcs11_module,
                reader_name,
                certificate,
            } => {
                let slot = 's: {
                    for slot in pkcs11_module.get_slots_with_token()? {
                        let slot_info = pkcs11_module.get_slot_info(slot)?;

                        if slot_info.slot_description() == reader_name {
                            break 's slot;
                        }
                    }

                    return Err(Error::new(
                        ErrorKind::NoCredentials,
                        format!("provided reader name ({reader_name}) does not match any smart card slots"),
                    ));
                };

                let session = pkcs11_module.open_ro_session(slot)?;

                let pin = String::from_utf8(self.pin.as_ref().to_vec())?;
                let pin = AuthPin::new(pin.into());
                session.login(UserType::User, Some(&pin))?;

                let (key_type, mechanism, data_to_sign) = match self.signing_scheme {
                    // PKCS#1 v1.5 signature over the DER-encoded `DigestInfo`.
                    SigningScheme::RsaSha1 => (KeyType::RSA, Mechanism::RsaPkcs, encode_digest(digest)?),
                    // `CKM_ECDSA` signs the raw digest.
                    SigningScheme::EcdsaP256Sha256 => (KeyType::EC, Mechanism::Ecdsa, digest),
                };

                for private_key in find_private_keys(&session, key_type, certificate)? {
                    if let Ok(signature) = session.sign(&mechanism, private_key, &data_to_sign) {
                        return match self.signing_scheme {
                            SigningScheme::RsaSha1 => Ok(signature),
                            SigningScheme::EcdsaP256Sha256 => ecdsa_signature_to_der(&signature),
                        };
                    }
                }

                Err(Error::new(
                    ErrorKind::NoCredentials,
                    format!(
                        "the selected PKCS11 slot ({reader_name}) does not have a suitable private key for data signing"
                    ),
                ))
            }
            #[cfg(target_os = "windows")]
            SmartCardApi::Windows { container_name } => sign_data_win_api(container_name, self.pin.as_ref(), &digest),
        }
    }
}

/// Finds the private keys to sign with using the smart card certificate.
///
/// A token can contain several keys of the same type, and any of them produces a valid signature, which the
/// KDC rejects afterwards. So, only the key with the same `CKA_ID` as the certificate has must be used.
/// All keys of the required type are returned only if the token does not link the certificate to a key.
#[cfg(not(target_arch = "wasm32"))]
fn find_private_keys(session: &Session, key_type: KeyType, certificate: &Certificate) -> Result<Vec<ObjectHandle>> {
    let certificates = session.find_objects(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Value(picky_asn1_der::to_vec(certificate)?),
    ])?;

    for certificate in certificates {
        for attribute in session.get_attributes(certificate, &[AttributeType::Id])? {
            let Attribute::Id(id) = attribute else {
                continue;
            };

            if id.is_empty() {
                continue;
            }

            let keys = session.find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(key_type),
                Attribute::Id(id),
            ])?;

            if !keys.is_empty() {
                return Ok(keys);
            }
        }
    }

    warn!("The smart card token does not link the certificate to a private key: trying all suitable keys");

    Ok(session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::KeyType(key_type)])?)
}

/// Converts the raw ECDSA signature returned by PKCS#11 into the DER-encoded `ECDSA-Sig-Value`.
///
/// [PKCS #11 Current Mechanisms Specification, ECDSA](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html):
/// > The signature octets correspond to the concatenation of the ECDSA values r and s, both represented as an octet string of equal length.
///
/// [RFC 5480, ECDSA-Sig-Value](https://www.rfc-editor.org/rfc/rfc5480#section-2.2.3)
fn ecdsa_signature_to_der(raw_signature: &[u8]) -> Result<Vec<u8>> {
    use picky_asn1::wrapper::IntegerAsn1;
    use serde::Serialize;

    #[derive(Serialize)]
    struct EcdsaSigValue {
        r: IntegerAsn1,
        s: IntegerAsn1,
    }

    if raw_signature.is_empty() || !raw_signature.len().is_multiple_of(2) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "invalid raw ECDSA signature length",
        ));
    }

    let (r, s) = raw_signature.split_at(raw_signature.len() / 2);

    Ok(picky_asn1_der::to_vec(&EcdsaSigValue {
        r: IntegerAsn1::from_bytes_be_unsigned(r.to_vec()),
        s: IntegerAsn1::from_bytes_be_unsigned(s.to_vec()),
    })?)
}

/// Constructs the [DigestInfo] structure and encodes it into byte vector.
///
/// During the RDP authorization, we need to sign the data digest using smart card. We must
/// use PKCS1 padding scheme. It means, that the [DigestInfo] structure must be constructed
/// with the digest inside. Smart card will sign encoded [DigestInfo] structure.
///
/// `sspi-rs` uses SHA1 during scard logon. Thus, input `digest` must be SHA1 hash of the data we want to sign.
fn encode_digest(digest: Vec<u8>) -> Result<Vec<u8>> {
    use picky_asn1::wrapper::OctetStringAsn1;
    use picky_asn1_x509::{AlgorithmIdentifier, DigestInfo};

    let digest_info = DigestInfo {
        oid: AlgorithmIdentifier::new_sha1(),
        digest: OctetStringAsn1::from(digest),
    };

    Ok(picky_asn1_der::to_vec(&digest_info)?)
}

/// Signs data using the Windows native API for smart cards.
///
/// This function uses the Cryptography Next Generation (CNG) API to sign the data: https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/.
#[cfg(target_os = "windows")]
fn sign_data_win_api(container_name: &str, pin: &[u8], data_to_sign: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;

    use windows::Win32::Security::Cryptography::{
        BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA1_ALGORITHM, CERT_KEY_SPEC, MS_SMART_CARD_KEY_STORAGE_PROVIDER,
        NCRYPT_FLAGS, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PIN_PROPERTY, NCRYPT_SILENT_FLAG, NCryptOpenKey,
        NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
    };
    use windows::core::{Owned, PCWSTR};

    use crate::{U16CString, U16CStringExt};

    let mut provider = Owned::default();
    // SAFETY: FFI call with no outstanding preconditions.
    unsafe { NCryptOpenStorageProvider(&mut *provider, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0) }.map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!(
                "failed to open smart card CNG key storage provider: {} ({:x})",
                err.message(),
                err.code().0
            ),
        )
    })?;

    let container_name = U16CString::from_str_truncate(container_name).into_vec_with_nul();
    let container_name = PCWSTR::from_raw(container_name.as_ptr());

    let mut key = Owned::default();
    // SAFETY:
    // - `provider` is a valid handle obtained from `NCryptOpenStorageProvider`.
    // - `container_name` is a valid UTF-16 string and null-terminated.
    unsafe {
        NCryptOpenKey(
            *provider,
            &mut *key,
            container_name,
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("failed to open smart card key: {} ({:x})", err.message(), err.code().0),
        )
    })?;

    // NCRYPT_PIN_PROPERTY: https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers
    // > A pointer to a null-terminated Unicode string that contains the PIN.
    let pin = U16CString::from_utf8_bytes(pin)?.to_bytes_with_nul();

    // SAFETY:
    // - `key` is a valid handle obtained from `NCryptOpenKey`.
    // - `pin` is a valid UTF-16 string and null-terminated.
    if let Err(err) = unsafe { NCryptSetProperty((*key).into(), NCRYPT_PIN_PROPERTY, pin.as_ref(), NCRYPT_FLAGS(0)) } {
        warn!(
            "Failed to set smart card PIN code: {} ({:x}) - this may cause issues with signing data.",
            err.message(),
            err.code().0
        );
    }

    let mut signature_len = 0;
    let padding_info = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: BCRYPT_SHA1_ALGORITHM,
    };
    // SAFETY:
    // - `key` is a valid handle obtained from `NCryptOpenKey`.
    // - `padding_info`, and `signature_len` are local variables.
    // - `padding_info` has the `BCRYPT_PKCS1_PADDING_INFO` type which corresponds to the `NCRYPT_PAD_PKCS1_FLAG` flag.
    // - `pbSignature` is allowed to be NULL.
    //   > If this parameter is NULL, this function will calculate the size required for the signature and return the size in the location pointed to by the pcbResult parameter.
    unsafe {
        NCryptSignHash(
            *key,
            Some(ptr::from_ref(&padding_info).cast()),
            data_to_sign,
            None,
            &mut signature_len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("failed to get signature length: {} ({:x})", err.message(), err.code().0),
        )
    })?;

    let mut signature = vec![0_u8; usize::try_from(signature_len)?];
    // SAFETY:
    // - `key` is a valid handle obtained from `NCryptOpenKey`.
    // - `padding_info`, `signature`, and `signature_len` are local variables.
    // - `padding_info` has the `BCRYPT_PKCS1_PADDING_INFO` type which corresponds to the `NCRYPT_PAD_PKCS1_FLAG` flag.
    unsafe {
        NCryptSignHash(
            *key,
            Some(ptr::from_ref(&padding_info).cast()),
            data_to_sign,
            Some(&mut signature),
            &mut signature_len,
            NCRYPT_PAD_PKCS1_FLAG,
        )
    }
    .map_err(|err| {
        Error::new(
            ErrorKind::InternalError,
            format!("failed to sign data: {} ({:x})", err.message(), err.code().0),
        )
    })?;

    Ok(signature)
}

#[cfg(test)]
mod tests {
    use picky::hash::HashAlgorithm;
    use picky::key::PrivateKey;
    use picky::signature::SignatureAlgorithm;
    use picky::x509::Cert;
    use picky_asn1_x509::Certificate;

    use super::{SmartCard, ecdsa_signature_to_der};
    use crate::Secret;
    use crate::pk_init::SigningScheme;

    const EC_P256_PRIVATE_KEY: &str = include_str!("../test_assets/ec_p256.key");

    #[test]
    fn emulated_ec_smart_card_signs_data() {
        let private_key = PrivateKey::from_pem_str(EC_P256_PRIVATE_KEY).unwrap();
        // The smart card does not check that the certificate matches the key, but the signing scheme is chosen by the certificate.
        let certificate: Certificate = Cert::from_pem_str(include_str!("../test_assets/ec_p256.cer"))
            .unwrap()
            .into();
        assert_eq!(
            SigningScheme::EcdsaP256Sha256,
            SigningScheme::from_certificate(&certificate).unwrap()
        );

        let mut smart_card = SmartCard::new_emulated(
            "Reader 0".into(),
            b"123456".to_vec(),
            Secret::new(b"123456".to_vec()),
            private_key.clone(),
            &certificate,
            SigningScheme::EcdsaP256Sha256,
        )
        .unwrap();

        let data = b"signed attributes";
        let signature = smart_card.sign(data).unwrap();

        // `picky` is an independent implementation: it must accept the DER encoded signature.
        SignatureAlgorithm::Ecdsa(HashAlgorithm::SHA2_256)
            .verify(&private_key.to_public_key().unwrap(), data, &signature)
            .expect("the signature must be valid");
    }

    #[test]
    fn emulated_ec_smart_card_rejects_wrong_pin() {
        let private_key = PrivateKey::from_pem_str(EC_P256_PRIVATE_KEY).unwrap();
        let certificate: Certificate = Cert::from_pem_str(include_str!("../test_assets/ec_p256.cer"))
            .unwrap()
            .into();

        let mut smart_card = SmartCard::new_emulated(
            "Reader 0".into(),
            b"123456".to_vec(),
            Secret::new(b"654321".to_vec()),
            private_key,
            &certificate,
            SigningScheme::EcdsaP256Sha256,
        )
        .unwrap();

        smart_card.sign(b"data").unwrap_err();
    }

    #[test]
    fn ecdsa_signature_conversion() {
        let mut raw = vec![0x11; 32];
        raw.extend_from_slice(&[0x22; 32]);

        let der = ecdsa_signature_to_der(&raw).unwrap();

        let mut expected = vec![0x30, 0x44, 0x02, 0x20];
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x02, 0x20]);
        expected.extend_from_slice(&[0x22; 32]);
        assert_eq!(expected, der);
    }

    #[test]
    fn ecdsa_signature_conversion_pads_and_trims_integers() {
        // `r` has the high bit set (needs a leading zero byte), `s` has leading zeros (must be trimmed).
        let mut raw = vec![0x80; 32];
        raw.extend_from_slice(&[0x00, 0x00]);
        raw.extend_from_slice(&[0x33; 30]);

        let der = ecdsa_signature_to_der(&raw).unwrap();

        let mut expected = vec![0x30, 0x44 - 2 + 1, 0x02, 0x21, 0x00];
        expected.extend_from_slice(&[0x80; 32]);
        expected.extend_from_slice(&[0x02, 0x1e]);
        expected.extend_from_slice(&[0x33; 30]);
        assert_eq!(expected, der);
    }

    #[test]
    fn ecdsa_signature_conversion_rejects_invalid_length() {
        ecdsa_signature_to_der(&[]).unwrap_err();
        ecdsa_signature_to_der(&[1, 2, 3]).unwrap_err();
    }
}
