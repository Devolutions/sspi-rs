use oid::ObjectIdentifier;
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::{ContentValue, EncapsulatedContentInfo};
use picky_asn1_x509::oids::PKINIT_DH_KEY_DATA;
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_asn1_x509::signer_info::{
    Attributes, CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber,
    SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo, UnsignedAttributes,
};
use picky_asn1_x509::{
    AlgorithmIdentifier, AlgorithmIdentifierParameters, Attribute, AttributeValues, Certificate, PublicKey, ShaVariant,
    SubjectPublicKeyInfo, oids,
};
use picky_krb::constants::types::{PA_PAC_REQUEST_TYPE, PA_PK_AS_REQ};
use picky_krb::crypto::diffie_hellman::compute_public_key;
use picky_krb::data_types::{KerbPaPacRequest, KerberosTime, PaData};
use picky_krb::messages::KdcReqBody;
use picky_krb::pkinit::{
    AuthPack, DhDomainParameters, DhReqInfo, DhReqKeyInfo, KdcDhKeyInfo, PaPkAsReq, PkAuthenticator,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use time::OffsetDateTime;

use crate::kerberos::client::generators::{MAX_MICROSECONDS, nonce_to_asn1};
use crate::{Error, ErrorKind, Result, Secret};

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// 9. This nonce string MUST be as long as the longest key length of the symmetric key types that the client supports.
/// Key length of Aes256 is equal to 32
pub(crate) const DH_NONCE_LEN: usize = 32;

/// Key agreement used by PKINIT to protect the reply key.
///
/// [RFC 4556: Using Diffie-Hellman Key Exchange][rfc4556-dh] is used for RSA certificates and
/// [RFC 5349: Elliptic Curve Cryptography Support for PKINIT][rfc5349] is used for EC certificates (the same as Windows does).
///
/// [rfc4556-dh]: https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.3.1
/// [rfc5349]: https://www.rfc-editor.org/rfc/rfc5349.html
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum KeyAgreement {
    Dh(DhParameters),
    // Only the smart card logon (the `scard` feature) selects ECDH.
    #[cfg_attr(not(feature = "scard"), allow(dead_code))]
    Ecdh(EcdhParameters),
}

impl KeyAgreement {
    /// Generates the client key agreement parameters suitable for the provided client certificate.
    #[cfg(feature = "scard")]
    pub(crate) fn for_certificate(certificate: &Certificate, rng: &mut rand::rngs::StdRng) -> Result<Self> {
        Ok(match SigningScheme::from_certificate(certificate)? {
            SigningScheme::RsaSha1 => Self::Dh(crate::pku2u::generate_client_dh_parameters(rng)),
            SigningScheme::EcdsaP256Sha256 => Self::Ecdh(EcdhParameters::generate(rng)),
        })
    }
}

/// Client parameters of the PKINIT ECDH key agreement on the P-256 curve.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EcdhParameters {
    /// Client private key (the 32-byte big-endian P-256 scalar).
    private_key: Secret<Vec<u8>>,
    pub client_nonce: [u8; DH_NONCE_LEN],
    pub server_nonce: Option<[u8; DH_NONCE_LEN]>,
}

impl EcdhParameters {
    #[cfg(feature = "scard")]
    pub(crate) fn generate(rng: &mut rand::rngs::StdRng) -> Self {
        use rand_core::Rng as _;

        let private_key = loop {
            let mut candidate = [0_u8; 32];
            rng.fill_bytes(&mut candidate);

            // Rejects zero and values greater than or equal to the curve order.
            if p256::SecretKey::from_slice(&candidate).is_ok() {
                break Secret::new(candidate.to_vec());
            }
        };

        let mut client_nonce = [0; DH_NONCE_LEN];
        rng.fill_bytes(&mut client_nonce);

        Self {
            private_key,
            client_nonce,
            server_nonce: None,
        }
    }

    fn secret_key(&self) -> Result<p256::SecretKey> {
        p256::SecretKey::from_slice(self.private_key.as_ref())
            .map_err(|_| Error::new(ErrorKind::InternalError, "invalid ECDH private key"))
    }

    /// Returns the client public key as an uncompressed SEC1 point.
    pub(crate) fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.secret_key()?.public_key().to_sec1_bytes().into_vec())
    }

    /// Computes the ECDH shared secret.
    ///
    /// [RFC 5349, Section 2.2](https://www.rfc-editor.org/rfc/rfc5349.html#section-2.2): the shared secret is the x-coordinate of the shared point.
    #[cfg(feature = "scard")]
    pub(crate) fn shared_secret(&self, server_public_key: &[u8]) -> Result<Vec<u8>> {
        let server_public_key = p256::PublicKey::from_sec1_bytes(server_public_key)
            .map_err(|_| Error::new(ErrorKind::InvalidToken, "KDC sent an invalid P-256 ECDH public key"))?;

        Ok(self
            .secret_key()?
            .diffie_hellman(&server_public_key)
            .raw_secret_bytes()
            .to_vec())
    }
}

/// The `AuthPack` with the EC `clientPublicValue`.
///
/// The `AuthPack` from the `picky-krb` crate supports only Diffie-Hellman public values.
///
/// [RFC 5349, Section 2.1](https://www.rfc-editor.org/rfc/rfc5349.html#section-2.1)
#[derive(Serialize, Deserialize)]
struct EcAuthPack {
    pk_authenticator: ExplicitContextTag0<PkAuthenticator>,
    client_public_value: ExplicitContextTag1<SubjectPublicKeyInfo>,
    supported_cms_types: ExplicitContextTag2<Asn1SequenceOf<AlgorithmIdentifier>>,
    client_dh_nonce: ExplicitContextTag3<OctetStringAsn1>,
}

/// Signature scheme used to sign the PKINIT `AuthPack` with the client certificate key.
///
/// The scheme is selected by the type of the client certificate public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningScheme {
    /// `rsaEncryption` signature over a SHA-1 digest.
    RsaSha1,
    /// `ecdsa-with-SHA256` signature over a SHA-256 digest. Only the P-256 curve is supported.
    EcdsaP256Sha256,
}

impl SigningScheme {
    /// Selects the signing scheme for the provided client certificate.
    pub(crate) fn from_certificate(certificate: &Certificate) -> Result<Self> {
        let spki = &certificate.tbs_certificate.subject_public_key_info;

        match &spki.subject_public_key {
            PublicKey::Rsa(_) => Ok(Self::RsaSha1),
            PublicKey::Ec(_) => {
                let is_p256 = matches!(
                    spki.algorithm.parameters(),
                    AlgorithmIdentifierParameters::Ec(params) if params.curve_oid() == &oids::secp256r1()
                );

                if is_p256 {
                    Ok(Self::EcdsaP256Sha256)
                } else {
                    Err(Error::new(
                        ErrorKind::OperationNotSupported,
                        "unsupported smart card certificate elliptic curve: only P-256 is supported",
                    ))
                }
            }
            _ => Err(Error::new(
                ErrorKind::OperationNotSupported,
                "unsupported smart card certificate public key type: only RSA and EC keys are supported",
            )),
        }
    }

    /// Hashes the data using the digest algorithm of this scheme.
    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::RsaSha1 => Sha1::digest(data).to_vec(),
            Self::EcdsaP256Sha256 => Sha256::digest(data).to_vec(),
        }
    }

    fn digest_algorithm(self) -> AlgorithmIdentifier {
        match self {
            Self::RsaSha1 => AlgorithmIdentifier::new_sha(ShaVariant::SHA1),
            Self::EcdsaP256Sha256 => AlgorithmIdentifier::new_sha(ShaVariant::SHA2_256),
        }
    }

    fn signature_algorithm(self) -> AlgorithmIdentifier {
        match self {
            Self::RsaSha1 => AlgorithmIdentifier::new_rsa_encryption(),
            Self::EcdsaP256Sha256 => AlgorithmIdentifier::new_ecdsa_with_sha256(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DhParameters {
    // g
    pub base: Vec<u8>,
    // p
    pub modulus: Vec<u8>,
    // q
    pub q: Vec<u8>,
    // generated private key
    pub private_key: Secret<Vec<u8>>,
    // received public key
    pub other_public_key: Option<Vec<u8>>,
    pub client_nonce: Option<[u8; DH_NONCE_LEN]>,
    pub server_nonce: Option<[u8; DH_NONCE_LEN]>,
}

// PA_DATAs in the Kerberos smart card logon is packed into a wrapper with OID.
// It's very similar to the `EncapsulatedContentInfo` structure, but the content field has another type.
#[derive(Serialize, Deserialize)]
pub(crate) struct Wrapper<T> {
    pub content_info: ObjectIdentifierAsn1,
    pub content: ExplicitContextTag0<T>,
}

pub(crate) type SignDataFn = Box<dyn FnMut(&[u8]) -> Result<Vec<u8>> + Send>;

pub(crate) struct GenerateAsPaDataOptions<'a> {
    pub p2p_cert: Certificate,
    pub kdc_req_body: &'a KdcReqBody,
    pub key_agreement: KeyAgreement,
    pub sign_data: SignDataFn,
    pub with_pre_auth: bool,
    pub authenticator_nonce: u32,
}

#[instrument(level = "trace", skip_all, ret)]
pub(crate) fn generate_pa_datas_for_as_req(options: &mut GenerateAsPaDataOptions<'_>) -> Result<Vec<PaData>> {
    generate_pa_datas_for_as_req_at(options, OffsetDateTime::now_utc())
}

pub(crate) fn generate_pa_datas_for_as_req_at(
    options: &mut GenerateAsPaDataOptions<'_>,
    current_date: OffsetDateTime,
) -> Result<Vec<PaData>> {
    let GenerateAsPaDataOptions {
        p2p_cert,
        kdc_req_body,
        key_agreement,
        sign_data,
        with_pre_auth,
        authenticator_nonce,
    } = options;

    if !*with_pre_auth {
        return Ok(vec![
            PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x00, 0x96])),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
            },
            PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                    &KerbPaPacRequest {
                        include_pac: ExplicitContextTag0::from(true),
                    },
                )?)),
            },
        ]);
    }

    let mut microseconds = current_date.microsecond();
    if microseconds > MAX_MICROSECONDS {
        microseconds = MAX_MICROSECONDS;
    }

    // [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
    // paChecksum: Contains the SHA1 checksum, performed over KDC-REQ-BODY.
    let encoded_kdc_req_body = picky_asn1_der::to_vec(&kdc_req_body)?;
    trace!(?kdc_req_body, "Encoded KdcReqBody");

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_kdc_req_body);

    let kdc_req_body_sha1_hash = sha1.finalize().to_vec();

    let pk_authenticator = ExplicitContextTag0::from(PkAuthenticator {
        cusec: ExplicitContextTag0::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag1::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        nonce: ExplicitContextTag2::from(nonce_to_asn1(*authenticator_nonce)),
        pa_checksum: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1::from(
            kdc_req_body_sha1_hash,
        )))),
    });

    let encoded_auth_pack = match key_agreement {
        KeyAgreement::Dh(dh_parameters) => {
            let public_value = compute_public_key(
                dh_parameters.private_key.as_ref(),
                &dh_parameters.modulus,
                &dh_parameters.base,
            )?;

            let auth_pack = AuthPack {
                pk_authenticator,
                client_public_value: Optional::from(Some(ExplicitContextTag1::from(DhReqInfo {
                    key_info: DhReqKeyInfo {
                        identifier: ObjectIdentifierAsn1::from(oids::diffie_hellman()),
                        key_info: DhDomainParameters {
                            p: IntegerAsn1::from(dh_parameters.modulus.clone()),
                            g: IntegerAsn1::from(dh_parameters.base.clone()),
                            q: IntegerAsn1::from(dh_parameters.q.clone()),
                            j: Optional::from(None),
                            validation_params: Optional::from(None),
                        },
                    },
                    key_value: BitStringAsn1::from(BitString::with_bytes(picky_asn1_der::to_vec(&IntegerAsn1::from(
                        public_value,
                    ))?)),
                }))),
                supported_cms_types: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(Vec::new())))),
                client_dh_nonce: Optional::from(
                    dh_parameters
                        .client_nonce
                        .as_ref()
                        .map(|nonce| ExplicitContextTag3::from(OctetStringAsn1::from(nonce.to_vec()))),
                ),
            };

            picky_asn1_der::to_vec(&auth_pack)?
        }
        KeyAgreement::Ecdh(ecdh_parameters) => {
            let auth_pack = EcAuthPack {
                pk_authenticator,
                client_public_value: ExplicitContextTag1::from(SubjectPublicKeyInfo::new_ec_key(
                    oids::secp256r1(),
                    BitString::with_bytes(ecdh_parameters.public_key()?),
                )),
                supported_cms_types: ExplicitContextTag2::from(Asn1SequenceOf::from(Vec::new())),
                client_dh_nonce: ExplicitContextTag3::from(OctetStringAsn1::from(
                    ecdh_parameters.client_nonce.to_vec(),
                )),
            };

            picky_asn1_der::to_vec(&auth_pack)?
        }
    };

    trace!(?encoded_auth_pack, "Encoded auth pack");

    let signing_scheme = SigningScheme::from_certificate(p2p_cert)?;
    let digest = signing_scheme.digest(&encoded_auth_pack);

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![signing_scheme.digest_algorithm()])),
        content_info: EncapsulatedContentInfo::new(oids::pkinit_auth_data(), Some(encoded_auth_pack)),
        certificates: Optional::from(CertificateSet(vec![CertificateChoices::Certificate(Asn1RawDer(
            picky_asn1_der::to_vec(p2p_cert)?,
        ))])),
        crls: None,
        signers_infos: SignersInfos(Asn1SetOf::from(vec![generate_signer_info(
            p2p_cert, digest, sign_data,
        )?])),
    };

    let e = Wrapper {
        content_info: ObjectIdentifierAsn1::from(oids::signed_data()),
        content: ExplicitContextTag0::from(signed_data),
    };

    let pa_pk_as_req = PaPkAsReq {
        signed_auth_pack: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&e)?)),
        trusted_certifiers: Optional::from(None),
        kdc_pk_id: Optional::from(None),
    };

    Ok(vec![
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PK_AS_REQ.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&pa_pk_as_req)?)),
        },
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x12])),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
        },
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&KerbPaPacRequest {
                include_pac: ExplicitContextTag0::from(true),
            })?)),
        },
    ])
}

pub(crate) fn generate_signer_info(
    p2p_cert: &Certificate,
    digest: Vec<u8>,
    sign_data: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<SignerInfo> {
    let signing_scheme = SigningScheme::from_certificate(p2p_cert)?;

    let signed_attributes = Asn1SetOf::from(vec![
        Attribute {
            ty: ObjectIdentifierAsn1::from(oids::content_type()),
            value: AttributeValues::ContentType(Asn1SetOf::from(vec![ObjectIdentifierAsn1::from(
                oids::pkinit_auth_data(),
            )])),
        },
        Attribute {
            ty: ObjectIdentifierAsn1::from(oids::message_digest()),
            value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![OctetStringAsn1::from(digest)])),
        },
    ]);

    let encoded_signed_attributes = picky_asn1_der::to_vec(&signed_attributes)?;

    let signature = sign_data(&encoded_signed_attributes)?;

    trace!(?encoded_signed_attributes, ?signature, "Signed attributes",);

    Ok(SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: p2p_cert.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(p2p_cert.tbs_certificate.serial_number.clone()),
        }),
        digest_algorithm: DigestAlgorithmIdentifier(signing_scheme.digest_algorithm()),
        signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(signed_attributes.0))),
        signature_algorithm: SignatureAlgorithmIdentifier(signing_scheme.signature_algorithm()),
        signature: SignatureValue(OctetStringAsn1::from(signature)),
        unsigned_attrs: Optional::from(UnsignedAttributes(Vec::new())),
    })
}

/// Extracts the server DH public key (the DER-encoded `INTEGER` inside of the `subjectPublicKey`).
#[instrument(level = "trace", ret)]
pub(crate) fn extract_server_dh_public_key(signed_data: &SignedData) -> Result<Vec<u8>> {
    let dh_key_info = extract_kdc_dh_key_info(signed_data)?;

    let key: IntegerAsn1 = picky_asn1_der::from_bytes(dh_key_info.subject_public_key.0.payload_view())?;

    Ok(key.as_unsigned_bytes_be().to_vec())
}

/// Extracts the server ECDH public key (the SEC1-encoded EC point stored in the `subjectPublicKey`).
///
/// [RFC 5349, Section 2.2](https://www.rfc-editor.org/rfc/rfc5349.html#section-2.2)
#[cfg(feature = "scard")]
#[instrument(level = "trace", ret)]
pub(crate) fn extract_server_ecdh_public_key(signed_data: &SignedData) -> Result<Vec<u8>> {
    Ok(extract_kdc_dh_key_info(signed_data)?
        .subject_public_key
        .0
        .payload_view()
        .to_vec())
}

fn extract_kdc_dh_key_info(signed_data: &SignedData) -> Result<KdcDhKeyInfo> {
    let pkinit_dh_key_data = ObjectIdentifier::try_from(PKINIT_DH_KEY_DATA).unwrap();
    if signed_data.content_info.content_type.0 != pkinit_dh_key_data {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "Invalid content info identifier: {:?}. Expected: {:?}",
                signed_data.content_info.content_type.0, pkinit_dh_key_data
            ),
        ));
    }

    let dh_key_info_data = match &signed_data
        .content_info
        .content
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "content info is not present"))?
        .0
    {
        ContentValue::OctetString(data) => &data.0,
        content_value => {
            error!(
                ?content_value,
                "The server has sent KDC DH key info in unsupported format. Only ContentValue::OctetString is supported",
            );

            return Err(Error::new(ErrorKind::InvalidToken, "unexpected content info"));
        }
    };

    Ok(picky_asn1_der::from_bytes(dh_key_info_data)?)
}

#[cfg(test)]
mod tests {
    use picky::x509::Cert;
    use picky_asn1::wrapper::{Asn1SetOf, ObjectIdentifierAsn1, OctetStringAsn1};
    use picky_asn1_x509::{Attribute, AttributeValues, Certificate, oids};

    use super::{SigningScheme, generate_signer_info};

    fn load_certificate(pem: &str) -> Certificate {
        Cert::from_pem_str(pem).unwrap().into()
    }

    #[test]
    fn signing_scheme_is_selected_by_certificate_key_type() {
        let rsa = load_certificate(include_str!("../test_assets/pw11.cer"));
        let ec_p256 = load_certificate(include_str!("../test_assets/ec_p256.cer"));

        assert_eq!(SigningScheme::RsaSha1, SigningScheme::from_certificate(&rsa).unwrap());
        assert_eq!(
            SigningScheme::EcdsaP256Sha256,
            SigningScheme::from_certificate(&ec_p256).unwrap()
        );
    }

    #[test]
    fn unsupported_curve_is_rejected() {
        let ec_p384 = load_certificate(include_str!("../test_assets/ec_p384.cer"));

        SigningScheme::from_certificate(&ec_p384).unwrap_err();
    }

    #[test]
    fn signing_scheme_digest_lengths() {
        assert_eq!(20, SigningScheme::RsaSha1.digest(b"data").len());
        assert_eq!(32, SigningScheme::EcdsaP256Sha256.digest(b"data").len());
    }

    #[test]
    fn signer_info_algorithms_follow_certificate_key_type() {
        let rsa = load_certificate(include_str!("../test_assets/pw11.cer"));
        let ec_p256 = load_certificate(include_str!("../test_assets/ec_p256.cer"));

        let signer_info = generate_signer_info(&rsa, vec![0; 20], &mut |_| Ok(vec![1, 2, 3])).unwrap();
        assert!(signer_info.digest_algorithm.0.is_a(oids::sha1()));
        assert!(signer_info.signature_algorithm.0.is_a(oids::rsa_encryption()));

        let signer_info = generate_signer_info(&ec_p256, vec![0; 32], &mut |_| Ok(vec![1, 2, 3])).unwrap();
        assert!(signer_info.digest_algorithm.0.is_a(oids::sha256()));
        assert!(signer_info.signature_algorithm.0.is_a(oids::ecdsa_with_sha256()));
    }

    #[test]
    fn signing() {
        let digest = vec![
            22, 144, 59, 22, 68, 47, 213, 64, 69, 126, 237, 38, 151, 109, 213, 92, 122, 198, 202, 21,
        ];
        let signed_attributes = Asn1SetOf::from(vec![
            Attribute {
                ty: ObjectIdentifierAsn1::from(oids::content_type()),
                value: AttributeValues::ContentType(Asn1SetOf::from(vec![ObjectIdentifierAsn1::from(
                    oids::pkinit_auth_data(),
                )])),
            },
            Attribute {
                ty: ObjectIdentifierAsn1::from(oids::message_digest()),
                value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![OctetStringAsn1::from(digest)])),
            },
        ]);
        let encoded_signed_attributes = picky_asn1_der::to_vec(&signed_attributes).unwrap();
        println!("{encoded_signed_attributes:?}");
    }
}

#[cfg(all(test, feature = "scard"))]
mod ecdh_tests {
    use picky::x509::Cert;
    use picky_asn1::wrapper::{Asn1SetOf, ObjectIdentifierAsn1, OctetStringAsn1};
    use picky_asn1_x509::signed_data::SignedData;
    use picky_asn1_x509::{Certificate, oids};
    use picky_krb::pkinit::PaPkAsReq;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;
    use time::OffsetDateTime;

    use super::{
        EcAuthPack, EcdhParameters, GenerateAsPaDataOptions, KeyAgreement, Wrapper, generate_pa_datas_for_as_req_at,
    };
    use crate::ClientRequestFlags;
    use crate::kerberos::client::generators::{GenerateAsReqOptions, generate_as_req_kdc_body};

    fn load_certificate(pem: &str) -> Certificate {
        Cert::from_pem_str(pem).unwrap().into()
    }

    #[test]
    fn ecdh_shared_secret_is_symmetric() {
        let mut rng = StdRng::seed_from_u64(7);
        let client = EcdhParameters::generate(&mut rng);
        let server = EcdhParameters::generate(&mut rng);

        let client_public_key = client.public_key().unwrap();
        assert_eq!(65, client_public_key.len());
        assert_eq!(0x04, client_public_key[0]);

        let client_secret = client.shared_secret(&server.public_key().unwrap()).unwrap();
        let server_secret = server.shared_secret(&client_public_key).unwrap();

        assert_eq!(32, client_secret.len());
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn ecdh_rejects_invalid_server_public_key() {
        let mut rng = StdRng::seed_from_u64(7);
        let client = EcdhParameters::generate(&mut rng);

        client.shared_secret(&[]).unwrap_err();
        client.shared_secret(&[0x04; 65]).unwrap_err();
    }

    #[test]
    fn ec_certificate_produces_ecdh_as_req() {
        let mut rng = StdRng::seed_from_u64(7);
        let certificate = load_certificate(include_str!("../test_assets/ec_p256.cer"));
        let key_agreement = KeyAgreement::for_certificate(&certificate, &mut rng).unwrap();
        let KeyAgreement::Ecdh(ecdh) = &key_agreement else {
            panic!("EC certificate must select ECDH");
        };
        let expected_public_key = ecdh.public_key().unwrap();
        let expected_nonce = ecdh.client_nonce.to_vec();

        let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: "EXAMPLE.COM",
            username: "user",
            cname_type: 1,
            snames: &["krbtgt", "EXAMPLE.COM"],
            nonce: 1,
            hostname: "host",
            context_requirements: ClientRequestFlags::empty(),
        })
        .unwrap();

        let pa_datas = generate_pa_datas_for_as_req_at(
            &mut GenerateAsPaDataOptions {
                p2p_cert: certificate,
                kdc_req_body: &kdc_req_body,
                key_agreement,
                sign_data: Box::new(|data| {
                    // The signing callback receives the DER-encoded signed attributes.
                    assert_eq!(0x31, data[0]);
                    Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
                }),
                with_pre_auth: true,
                authenticator_nonce: 1,
            },
            OffsetDateTime::now_utc(),
        )
        .unwrap();

        let pa_pk_as_req: PaPkAsReq =
            picky_asn1_der::from_bytes(&pa_datas[0].padata_data.0.0).expect("PA-PK-AS-REQ is decodable");
        let signed_data: Wrapper<SignedData> =
            picky_asn1_der::from_bytes(&pa_pk_as_req.signed_auth_pack.0.0).expect("SignedData is decodable");
        let signed_data = signed_data.content.0;

        assert!(signed_data.digest_algorithms.0.0[0].is_a(oids::sha256()));
        let signer_info = &signed_data.signers_infos.0.0[0];
        assert!(signer_info.digest_algorithm.0.is_a(oids::sha256()));
        assert!(signer_info.signature_algorithm.0.is_a(oids::ecdsa_with_sha256()));

        let picky_asn1_x509::content_info::ContentValue::OctetString(encoded_auth_pack) =
            &signed_data.content_info.content.as_ref().unwrap().0
        else {
            panic!("the AuthPack must be an octet string");
        };
        let auth_pack: EcAuthPack = picky_asn1_der::from_bytes(&encoded_auth_pack.0).expect("EC AuthPack is decodable");

        let public_value = &auth_pack.client_public_value.0;
        assert!(public_value.algorithm.is_a(oids::ec_public_key()));
        assert!(matches!(
            public_value.algorithm.parameters(),
            picky_asn1_x509::AlgorithmIdentifierParameters::Ec(params) if params.curve_oid() == &oids::secp256r1()
        ));
        let picky_asn1_x509::PublicKey::Ec(point) = &public_value.subject_public_key else {
            panic!("clientPublicValue must be an EC key");
        };
        assert_eq!(expected_public_key, point.0.payload_view());
        assert_eq!(expected_nonce, auth_pack.client_dh_nonce.0.0);
    }

    #[test]
    fn server_ecdh_public_key_extraction() {
        use picky_asn1::bit_string::BitString;
        use picky_asn1::wrapper::{BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, IntegerAsn1, Optional};
        use picky_asn1_x509::cmsversion::CmsVersion;
        use picky_asn1_x509::content_info::{ContentValue, EncapsulatedContentInfo};
        use picky_asn1_x509::signed_data::{CertificateSet, DigestAlgorithmIdentifiers, SignersInfos};
        use picky_krb::pkinit::KdcDhKeyInfo;

        use super::extract_server_ecdh_public_key;

        let mut rng = StdRng::seed_from_u64(11);
        let server_public_key = EcdhParameters::generate(&mut rng).public_key().unwrap();

        let kdc_dh_key_info = KdcDhKeyInfo {
            subject_public_key: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(
                server_public_key.clone(),
            ))),
            nonce: ExplicitContextTag1::from(IntegerAsn1::from(vec![1])),
            dh_key_expiration: Optional::from(None),
        };

        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(Vec::new())),
            content_info: EncapsulatedContentInfo {
                content_type: ObjectIdentifierAsn1::from(oids::kpinit_dh_key_data()),
                // The deserialized KDC replies carry the content as the `OctetString` variant.
                content: Some(ExplicitContextTag0::from(ContentValue::OctetString(
                    OctetStringAsn1::from(picky_asn1_der::to_vec(&kdc_dh_key_info).unwrap()),
                ))),
            },
            certificates: Optional::from(CertificateSet(Vec::new())),
            crls: None,
            signers_infos: SignersInfos(Asn1SetOf::from(Vec::new())),
        };

        assert_eq!(server_public_key, extract_server_ecdh_public_key(&signed_data).unwrap());
    }
}
