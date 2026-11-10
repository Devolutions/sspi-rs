use picky_krb::data_types::PaData;
use picky_krb::messages::AsRep;
use time::OffsetDateTime;

use crate::kerberos::client::extractors::{extract_session_key_from_as_rep, extract_session_key_from_as_rep_with_key};
use crate::kerberos::client::generators::{
    GenerateAsPaDataOptions as AuthIdentityPaDataOptions, GenerateKeytabPaDataOptions,
    generate_pa_datas_for_as_req_at as generate_password_based_at,
    generate_pa_datas_for_as_req_with_key_at as generate_keytab_based_at,
};
use crate::kerberos::encryption_params::EncryptionParams;
#[cfg(feature = "scard")]
use crate::kerberos::kdc_cert::KdcTrust;
#[cfg(feature = "scard")]
use crate::pk_init::{
    GenerateAsPaDataOptions as SmartCardPaDataOptions, generate_pa_datas_for_as_req_at as generate_private_key_based_at,
};
use crate::{Result, Secret};

// PA-DATAs are very different for the Kerberos logon using username+password and smart card.
// This enum provides a unified way to generate PA-DATAs based on the provided options.
pub(crate) enum AsReqPaDataOptions<'a> {
    AuthIdentity(AuthIdentityPaDataOptions<'a>),
    #[cfg(feature = "scard")]
    SmartCard(Box<SmartCardPaDataOptions<'a>>),
    Keytab(GenerateKeytabPaDataOptions),
}

impl AsReqPaDataOptions<'_> {
    pub(crate) fn generate(&mut self, now: OffsetDateTime) -> Result<Vec<PaData>> {
        match self {
            AsReqPaDataOptions::AuthIdentity(options) => generate_password_based_at(options, now),
            #[cfg(feature = "scard")]
            AsReqPaDataOptions::SmartCard(options) => generate_private_key_based_at(options, now),
            AsReqPaDataOptions::Keytab(options) => generate_keytab_based_at(options, now),
        }
    }

    pub(crate) fn with_pre_auth(&mut self, pre_auth: bool) {
        match self {
            AsReqPaDataOptions::AuthIdentity(options) => options.with_pre_auth = pre_auth,
            #[cfg(feature = "scard")]
            AsReqPaDataOptions::SmartCard(options) => options.with_pre_auth = pre_auth,
            AsReqPaDataOptions::Keytab(options) => options.with_pre_auth = pre_auth,
        }
    }

    pub(crate) fn with_salt(&mut self, salt: Vec<u8>) {
        match self {
            AsReqPaDataOptions::AuthIdentity(options) => options.salt = salt,
            #[cfg(feature = "scard")]
            AsReqPaDataOptions::SmartCard(_) => {}
            // The keytab key is pre-derived; the KDC-supplied salt is irrelevant.
            AsReqPaDataOptions::Keytab(_) => {}
        }
    }

    pub(crate) fn salt(&self) -> &[u8] {
        match self {
            AsReqPaDataOptions::AuthIdentity(options) => &options.salt,
            #[cfg(feature = "scard")]
            AsReqPaDataOptions::SmartCard(_) => &[],
            AsReqPaDataOptions::Keytab(_) => &[],
        }
    }
}

/// Validates the `SignedData` of the KDC reply and extracts the KDC key agreement public key from it.
///
/// The signing certificate is checked against `trust` and `now`, and the signature
/// and the `content-type` signed attribute are verified.
/// `extract_public_key` is expected to check the expiration of the key against `now`.
#[cfg(feature = "scard")]
fn verify_kdc_reply(
    signed_data: &picky_asn1_x509::signed_data::SignedData,
    trust: KdcTrust<'_>,
    now: OffsetDateTime,
    extract_public_key: fn(&picky_asn1_x509::signed_data::SignedData, Option<OffsetDateTime>) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    use super::kdc_cert::{validate_content_type_attribute, validate_kdc_certificate};
    use crate::pku2u::{validate_server_p2p_certificate, validate_signed_data};

    validate_kdc_certificate(signed_data, trust, now)?;
    let rsa_public_key = validate_server_p2p_certificate(signed_data)?;
    validate_signed_data(signed_data, &rsa_public_key)?;
    validate_content_type_attribute(signed_data)?;

    extract_public_key(signed_data, Some(now))
}

// ApRep session key extraction process is different for the Kerberos logon using username+password and smart card.
// This enum provides a unified way to extract session key from the AsRep.
#[derive(Debug)]
pub(super) enum AsRepSessionKeyExtractor<'a> {
    AuthIdentity {
        salt: &'a str,
        password: &'a Secret<String>,
        enc_params: &'a EncryptionParams,
    },
    Keytab {
        key: &'a Secret<Vec<u8>>,
        enc_params: &'a EncryptionParams,
    },
    #[cfg(feature = "scard")]
    SmartCard {
        key_agreement: &'a mut crate::pk_init::KeyAgreement,
        enc_params: &'a mut EncryptionParams,
        /// Trust anchor for the KDC certificate. The system trust store is used if it is not set.
        ca_cert: Option<&'a crate::CertificateRaw>,
        /// The time to validate the KDC certificate and the KDC DH key against.
        now: OffsetDateTime,
    },
}

impl AsRepSessionKeyExtractor<'_> {
    #[instrument(level = "trace", ret, skip(self))]
    pub(super) fn session_key(&mut self, as_rep: &AsRep) -> Result<Secret<Vec<u8>>> {
        match self {
            AsRepSessionKeyExtractor::AuthIdentity {
                salt,
                password,
                enc_params,
            } => extract_session_key_from_as_rep(as_rep, salt, password.as_ref(), enc_params),
            AsRepSessionKeyExtractor::Keytab { key, enc_params } => {
                extract_session_key_from_as_rep_with_key(as_rep, key.as_ref(), enc_params)
            }
            #[cfg(feature = "scard")]
            AsRepSessionKeyExtractor::SmartCard {
                key_agreement,
                enc_params,
                ca_cert,
                now,
            } => {
                use picky_asn1_x509::signed_data::SignedData;
                use picky_krb::crypto::CipherSuite;
                use picky_krb::crypto::diffie_hellman::{DhNonce, generate_key, generate_key_from_shared_secret};
                use picky_krb::pkinit::PaPkAsRep;

                use crate::pk_init::{
                    KeyAgreement, Wrapper, extract_server_dh_public_key, extract_server_ecdh_public_key,
                };
                use crate::pku2u::{extract_pa_pk_as_rep, extract_server_nonce};
                use crate::{Error, ErrorKind, check_if_empty};

                let dh_rep_info = match extract_pa_pk_as_rep(as_rep)? {
                    PaPkAsRep::DhInfo(dh) => dh.0,
                    PaPkAsRep::EncKeyPack(_) => {
                        return Err(Error::new(
                            ErrorKind::OperationNotSupported,
                            "encKeyPack is not supported for the PA-PK-AS-REP",
                        ));
                    }
                };

                let server_nonce = extract_server_nonce(&dh_rep_info)?;

                let wrapped_signed_data: Wrapper<SignedData> =
                    picky_asn1_der::from_bytes(&dh_rep_info.dh_signed_data.0)?;
                let signed_data = wrapped_signed_data.content.0;

                let ca_cert = ca_cert.map(picky_asn1_x509::Certificate::from);
                let trust = KdcTrust::from_env(ca_cert.as_ref());

                enc_params.encryption_type = Some(CipherSuite::try_from(as_rep.0.enc_part.0.etype.0.0.as_slice())?);
                let cipher =
                    check_if_empty!(enc_params.encryption_type.as_ref(), "encryption type is not set").cipher();

                let key = match key_agreement {
                    KeyAgreement::Dh(dh_parameters) => {
                        dh_parameters.server_nonce = Some(server_nonce);

                        let public_key = verify_kdc_reply(&signed_data, trust, *now, extract_server_dh_public_key)?;
                        dh_parameters.other_public_key = Some(public_key);

                        generate_key(
                            check_if_empty!(dh_parameters.other_public_key.as_ref(), "dh public key is not set"),
                            dh_parameters.private_key.as_ref(),
                            &dh_parameters.modulus,
                            Some(DhNonce {
                                client_nonce: check_if_empty!(
                                    dh_parameters.client_nonce.as_ref(),
                                    "dh client none is not set"
                                ),
                                server_nonce: check_if_empty!(
                                    dh_parameters.server_nonce.as_ref(),
                                    "dh server nonce is not set"
                                ),
                            }),
                            cipher.as_ref(),
                        )?
                    }
                    KeyAgreement::Ecdh(ecdh_parameters) => {
                        let server_public_key =
                            verify_kdc_reply(&signed_data, trust, *now, extract_server_ecdh_public_key)?;
                        let shared_secret = ecdh_parameters.shared_secret(&server_public_key)?;

                        generate_key_from_shared_secret(
                            shared_secret,
                            Some(DhNonce {
                                client_nonce: &ecdh_parameters.client_nonce,
                                server_nonce: &server_nonce,
                            }),
                            cipher.as_ref(),
                        )?
                    }
                };

                let session_key = extract_session_key_from_as_rep_with_key(as_rep, &key, enc_params)?;

                Ok(session_key)
            }
        }
    }
}

#[cfg(all(test, feature = "scard"))]
mod tests {
    use picky::hash::HashAlgorithm;
    use picky::key::PrivateKey;
    use picky::signature::SignatureAlgorithm;
    use picky::x509::Cert;
    use picky::x509::certificate::CertificateBuilder;
    use picky::x509::date::UtcDate;
    use picky::x509::name::DirectoryName;
    use picky_asn1::bit_string::BitString;
    use picky_asn1::date::GeneralizedTime;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, Asn1SetOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
        IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
    };
    use picky_asn1_der::Asn1RawDer;
    use picky_asn1_x509::cmsversion::CmsVersion;
    use picky_asn1_x509::content_info::EncapsulatedContentInfo;
    use picky_asn1_x509::signed_data::{
        CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
    };
    use picky_asn1_x509::signer_info::{
        Attributes, CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber,
        SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo, UnsignedAttributes,
    };
    use picky_asn1_x509::{AlgorithmIdentifier, Attribute, AttributeValues, Certificate, ShaVariant, oids};
    use picky_krb::data_types::KerberosTime;
    use picky_krb::pkinit::KdcDhKeyInfo;
    use time::{Date, Month, OffsetDateTime};

    use super::{KdcTrust, verify_kdc_reply};
    use crate::ErrorKind;
    use crate::pk_init::extract_server_dh_public_key;

    const DH_PUBLIC_KEY: [u8; 3] = [0x01, 0x02, 0x03];

    struct KdcFixture {
        root: Cert,
        kdc_cert: Cert,
        kdc_key: PrivateKey,
    }

    fn date(year: u16) -> UtcDate {
        UtcDate::ymd(year, 1, 1).unwrap()
    }

    fn utc(year: i32, month: Month) -> OffsetDateTime {
        Date::from_calendar_date(year, month, 1)
            .unwrap()
            .midnight()
            .assume_utc()
    }

    fn now() -> OffsetDateTime {
        utc(2027, Month::June)
    }

    fn kdc_fixture(kdc_valid_to: u16) -> KdcFixture {
        let root_key = PrivateKey::generate_rsa(2048).unwrap();
        let root = CertificateBuilder::new()
            .validity(date(2026), date(2030))
            .self_signed(DirectoryName::new_common_name("Test Root"), &root_key)
            .ca(true)
            .build()
            .unwrap();
        let kdc_key = PrivateKey::generate_rsa(2048).unwrap();
        let kdc_cert = CertificateBuilder::new()
            .validity(date(2026), date(kdc_valid_to))
            .subject(DirectoryName::new_common_name("kdc"), kdc_key.to_public_key().unwrap())
            .issuer_cert(&root, &root_key)
            .ca(false)
            .build()
            .unwrap();

        KdcFixture {
            root,
            kdc_cert,
            kdc_key,
        }
    }

    fn asn1_cert(cert: &Cert) -> Certificate {
        picky_asn1_der::from_bytes(&cert.to_der().unwrap()).unwrap()
    }

    /// Builds the DH reply `SignedData` the way a KDC does, signed with the KDC key.
    fn signed_dh_reply(
        fixture: &KdcFixture,
        with_content_type: bool,
        dh_key_expiration: Option<OffsetDateTime>,
    ) -> SignedData {
        let key_info = KdcDhKeyInfo {
            subject_public_key: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(
                picky_asn1_der::to_vec(&IntegerAsn1::from(DH_PUBLIC_KEY.to_vec())).unwrap(),
            ))),
            nonce: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x07])),
            dh_key_expiration: Optional::from(
                dh_key_expiration
                    .map(|time| ExplicitContextTag2::from(KerberosTime::from(GeneralizedTime::from(time)))),
            ),
        };
        let content = picky_asn1_der::to_vec(&key_info).unwrap();

        let mut attributes = Vec::new();
        if with_content_type {
            attributes.push(Attribute {
                ty: ObjectIdentifierAsn1::from(oids::content_type()),
                value: AttributeValues::ContentType(Asn1SetOf::from(vec![ObjectIdentifierAsn1::from(
                    oids::kpinit_dh_key_data(),
                )])),
            });
        }
        attributes.push(Attribute {
            ty: ObjectIdentifierAsn1::from(oids::message_digest()),
            value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![OctetStringAsn1::from(
                HashAlgorithm::SHA1.digest(&content),
            )])),
        });
        let signature = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)
            .sign(
                &picky_asn1_der::to_vec(&Asn1SetOf::from(attributes.clone())).unwrap(),
                &fixture.kdc_key,
            )
            .unwrap();

        let kdc_cert = asn1_cert(&fixture.kdc_cert);
        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
            content_info: EncapsulatedContentInfo::new(oids::kpinit_dh_key_data(), Some(content)),
            certificates: Optional::from(CertificateSet(vec![CertificateChoices::Certificate(Asn1RawDer(
                fixture.kdc_cert.to_der().unwrap(),
            ))])),
            crls: None,
            signers_infos: SignersInfos(Asn1SetOf::from(vec![SignerInfo {
                version: CmsVersion::V1,
                sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                    issuer: kdc_cert.tbs_certificate.issuer.clone(),
                    serial_number: CertificateSerialNumber(kdc_cert.tbs_certificate.serial_number.clone()),
                }),
                digest_algorithm: DigestAlgorithmIdentifier(AlgorithmIdentifier::new_sha(ShaVariant::SHA1)),
                signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(attributes))),
                signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
                signature: SignatureValue(OctetStringAsn1::from(signature)),
                unsigned_attrs: Optional::from(UnsignedAttributes(Vec::new())),
            }])),
        };

        // The content is only decoded as an octet string when it is read from the wire.
        picky_asn1_der::from_bytes(&picky_asn1_der::to_vec(&signed_data).unwrap()).unwrap()
    }

    fn verify(signed_data: &SignedData, trust: KdcTrust<'_>, now: OffsetDateTime) -> crate::Result<Vec<u8>> {
        verify_kdc_reply(signed_data, trust, now, extract_server_dh_public_key)
    }

    #[test]
    fn well_formed_dh_reply_is_accepted_and_yields_the_dh_key() {
        let fixture = kdc_fixture(2028);
        let signed_data = signed_dh_reply(&fixture, true, Some(now() + time::Duration::hours(1)));

        let key = verify(&signed_data, KdcTrust::CaCert(&asn1_cert(&fixture.root)), now()).unwrap();

        assert_eq!(key, DH_PUBLIC_KEY);
    }

    #[test]
    fn dh_reply_without_content_type_attribute_is_rejected() {
        let fixture = kdc_fixture(2028);
        let signed_data = signed_dh_reply(&fixture, false, None);

        let error = verify(&signed_data, KdcTrust::CaCert(&asn1_cert(&fixture.root)), now()).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    #[test]
    fn dh_reply_with_expired_dh_key_is_rejected() {
        let fixture = kdc_fixture(2028);
        let signed_data = signed_dh_reply(&fixture, true, Some(now() - time::Duration::hours(1)));

        let error = verify(&signed_data, KdcTrust::CaCert(&asn1_cert(&fixture.root)), now()).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    #[test]
    fn dh_reply_signed_with_an_expired_kdc_certificate_is_rejected() {
        let fixture = kdc_fixture(2027);
        let signed_data = signed_dh_reply(&fixture, true, None);

        let error = verify(&signed_data, KdcTrust::Skip, utc(2027, Month::February)).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn dh_reply_signed_by_a_certificate_outside_the_trust_anchor_is_rejected() {
        let fixture = kdc_fixture(2028);
        let other = kdc_fixture(2028);
        let signed_data = signed_dh_reply(&fixture, true, None);

        let error = verify(&signed_data, KdcTrust::CaCert(&asn1_cert(&other.root)), now()).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn dh_reply_is_accepted_when_the_chain_verification_is_skipped() {
        let fixture = kdc_fixture(2028);
        let signed_data = signed_dh_reply(&fixture, true, None);

        let key = verify(&signed_data, KdcTrust::Skip, now()).unwrap();

        assert_eq!(key, DH_PUBLIC_KEY);
    }
}
