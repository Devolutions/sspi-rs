//! Validation of the KDC reply of the PKINIT smart card logon.

use picky::key::PublicKey as RsaPublicKey;
use picky_asn1_x509::signed_data::{CertificateChoices, SignedData};
use picky_asn1_x509::{AttributeValues, Certificate, ExtensionView, oids};
use time::OffsetDateTime;

use crate::pku2u::{extract_signing_certificate, is_valid_at, signing_certificate_der};
use crate::{Error, ErrorKind, Result};

/// If this environment variable is set to `1` or `true` (case-insensitive), the KDC certificate must be verified.
/// Otherwise, a failed verification against the system trust store only logs a warning.
const ENFORCE_CA_ENV: &str = "SSPI_SCARD_ENFORCE_CA";

/// Only an explicit truthy value enables the requirement.
fn is_enforce_requested(value: &str) -> bool {
    let value = value.trim();

    value == "1" || value.eq_ignore_ascii_case("true")
}

// UNTESTED: the variable is read on every validation, so changing it at runtime takes effect on the next logon.
// Tests cover `is_enforce_requested` and pass the flag explicitly, so check this wiring when changing it.
fn is_ca_enforced() -> bool {
    std::env::var(ENFORCE_CA_ENV).is_ok_and(|value| is_enforce_requested(&value))
}

/// Validates the certificate the KDC used to sign its PKINIT reply.
///
/// The validity period of the KDC certificate is always checked against `now`.
/// If `ca_cert` is provided, the certificate must chain up to it.
/// Otherwise, the chain is checked against the system trust store.
/// If the store does not vouch for the certificate, validation fails when `SSPI_SCARD_ENFORCE_CA` is set
/// to `1` or `true`, and only logs a warning otherwise.
pub(crate) fn validate_kdc_certificate(
    signed_data: &SignedData,
    ca_cert: Option<&Certificate>,
    now: OffsetDateTime,
) -> Result<()> {
    validate_kdc_certificate_with(signed_data, ca_cert, system_trust_anchors, is_ca_enforced(), now)
}

/// Same as [`validate_kdc_certificate`], but the system trust anchors and the enforcement are provided by the caller.
fn validate_kdc_certificate_with(
    signed_data: &SignedData,
    ca_cert: Option<&Certificate>,
    system_trust_anchors: impl FnOnce() -> Result<Vec<Certificate>>,
    enforce_ca: bool,
    now: OffsetDateTime,
) -> Result<()> {
    let kdc_cert = extract_signing_certificate(signed_data)?;
    check_validity_period(&kdc_cert, now)?;

    if let Some(ca_cert) = ca_cert {
        return verify_kdc_chain(signed_data, kdc_cert, std::slice::from_ref(ca_cert), now);
    }

    let result = system_trust_anchors().and_then(|anchors| verify_kdc_chain(signed_data, kdc_cert, &anchors, now));

    match result {
        Ok(()) => Ok(()),
        Err(error) if enforce_ca => Err(Error::new(
            error.error_type,
            format!(
                "no CA certificate is configured and {ENFORCE_CA_ENV} requires the system trust store to vouch for the KDC certificate: {error}"
            ),
        )),
        Err(error) => {
            warn!(
                %error,
                "The KDC certificate chain is not verified; set {ENFORCE_CA_ENV}=1 to reject an unverified KDC certificate"
            );

            Ok(())
        }
    }
}

/// Loads the trust anchors of the system trust store.
///
/// The store is read on every call, so a CA installed or removed after the process started takes effect.
/// Certificates that cannot be read or parsed are skipped.
#[cfg(not(target_arch = "wasm32"))]
fn system_trust_anchors() -> Result<Vec<Certificate>> {
    let loaded = rustls_native_certs::load_native_certs();

    for error in &loaded.errors {
        warn!(%error, "Failed to load a certificate from the system trust store");
    }

    Ok(loaded
        .certs
        .iter()
        .filter_map(|cert| picky_asn1_der::from_bytes::<Certificate>(cert.as_ref()).ok())
        .collect())
}

/// The system trust store cannot be loaded on wasm, so the CA certificate has to be provided explicitly.
///
/// TODO: load the trust anchors from `webpki-roots` on wasm instead.
#[cfg(target_arch = "wasm32")]
fn system_trust_anchors() -> Result<Vec<Certificate>> {
    Err(Error::new(
        ErrorKind::Pku2uCertFailure,
        "no CA certificate is configured and the system trust store is not available on wasm",
    ))
}

/// Verifies that the KDC certificate chains up to one of the `trust_anchors`.
///
/// The certificates of the reply other than the signer are the candidate intermediates.
fn verify_kdc_chain(
    signed_data: &SignedData,
    kdc_cert: Certificate,
    trust_anchors: &[Certificate],
    now: OffsetDateTime,
) -> Result<()> {
    let signer_der = signing_certificate_der(signed_data)?;
    let intermediates = signed_data
        .certificates
        .0
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(raw) if raw.0.as_slice() != signer_der => {
                let certificate = picky_asn1_der::from_bytes::<Certificate>(&raw.0).ok()?;
                Some((certificate, raw.0.as_slice()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut used = vec![false; intermediates.len()];

    verify_path(&kdc_cert, signer_der, &intermediates, &mut used, trust_anchors, now)
}

/// Searches for a path from `current` to one of the `trust_anchors`, backtracking over the candidates.
///
/// `current_der` is the encoding of `current`. Each intermediate is used at most once on a path,
/// which bounds the path length and rules out loops.
fn verify_path(
    current: &Certificate,
    current_der: &[u8],
    intermediates: &[(Certificate, &[u8])],
    used: &mut [bool],
    trust_anchors: &[Certificate],
    now: OffsetDateTime,
) -> Result<()> {
    let mut error = Error::new(
        ErrorKind::Pku2uCertFailure,
        "KDC certificate does not chain up to a trusted CA certificate",
    );

    // An issuer may have several certificates with the same name (for example, after a CA key renewal),
    // so every one of them is tried.
    for anchor in trust_anchors
        .iter()
        .filter(|anchor| anchor.tbs_certificate.subject == current.tbs_certificate.issuer)
    {
        match check_validity_period(anchor, now).and_then(|()| verify_issued_by(current_der, anchor, false)) {
            Ok(()) => return Ok(()),
            Err(anchor_error) => error = anchor_error,
        }
    }

    for (index, (intermediate, intermediate_der)) in intermediates.iter().enumerate() {
        if used[index] || intermediate.tbs_certificate.subject != current.tbs_certificate.issuer {
            continue;
        }

        let issued =
            check_validity_period(intermediate, now).and_then(|()| verify_issued_by(current_der, intermediate, true));
        if let Err(issued_error) = issued {
            error = issued_error;
            continue;
        }

        used[index] = true;
        let path = verify_path(intermediate, intermediate_der, intermediates, used, trust_anchors, now);
        used[index] = false;

        match path {
            Ok(()) => return Ok(()),
            Err(path_error) => error = path_error,
        }
    }

    Err(error)
}

/// Verifies that `issuer` signed the certificate encoded as `der`.
///
/// If `enforce_ca_constraints` is set, the issuer must also be allowed to sign certificates.
/// The configured trust anchor is trusted as is, so its constraints are not enforced.
fn verify_issued_by(der: &[u8], issuer: &Certificate, enforce_ca_constraints: bool) -> Result<()> {
    use picky::signature::SignatureAlgorithm;
    use picky_asn1::wrapper::BitStringAsn1;
    use picky_asn1_der::Asn1RawDer;
    use picky_asn1_x509::AlgorithmIdentifier;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct SignedCertificate {
        tbs_certificate: Asn1RawDer,
        signature_algorithm: AlgorithmIdentifier,
        signature_value: BitStringAsn1,
    }

    if enforce_ca_constraints {
        // [Basic Constraints](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9): only a CA key may verify
        // certificate signatures, and an asserted key usage extension must allow `keyCertSign`.
        let is_ca = issuer
            .basic_constraints()
            .and_then(|basic_constraints| basic_constraints.ca())
            .unwrap_or(false);
        let allows_cert_sign = issuer
            .extensions()
            .iter()
            .find_map(|extension| match extension.extn_value() {
                ExtensionView::KeyUsage(key_usage) => Some(key_usage.key_cert_sign()),
                _ => None,
            })
            .unwrap_or(true);
        if !is_ca || !allows_cert_sign {
            return Err(Error::new(
                ErrorKind::Pku2uCertFailure,
                "KDC certificate issuer is not allowed to sign certificates",
            ));
        }
    }

    let signed: SignedCertificate = picky_asn1_der::from_bytes(der)?;
    let issuer_key = RsaPublicKey::from(issuer.tbs_certificate.subject_public_key_info.clone());
    let algorithm = SignatureAlgorithm::from_algorithm_identifier(&signed.signature_algorithm).map_err(|error| {
        Error::new(
            ErrorKind::Pku2uCertFailure,
            format!("unsupported certificate signature algorithm: {error}"),
        )
    })?;

    algorithm
        .verify(
            &issuer_key,
            &signed.tbs_certificate.0,
            signed.signature_value.0.payload_view(),
        )
        .map_err(|error| {
            Error::new(
                ErrorKind::Pku2uCertFailure,
                format!("invalid certificate signature: {error}"),
            )
        })
}

fn check_validity_period(certificate: &Certificate, now: OffsetDateTime) -> Result<()> {
    if !is_valid_at(certificate, now)? {
        return Err(Error::new(
            ErrorKind::Pku2uCertFailure,
            format!("certificate is not valid at {now}"),
        ));
    }

    Ok(())
}

/// Requires the `content-type` signed attribute and that it equals the encapsulated content type.
///
/// [Signed-data Type](https://www.rfc-editor.org/rfc/rfc5652#section-5.3):
/// "The signedAttrs [...] MUST include a content-type attribute having as its value the content type of the
/// EncapsulatedContentInfo value being signed."
pub(crate) fn validate_content_type_attribute(signed_data: &SignedData) -> Result<()> {
    let signer_info = signed_data
        .signers_infos
        .0
        .0
        .first()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing signers_infos in signed data"))?;

    let content_type_attributes = signer_info
        .signed_attrs
        .0
        .0
        .0
        .iter()
        .filter(|attribute| attribute.ty.0 == oids::content_type())
        .collect::<Vec<_>>();
    let [attribute] = content_type_attributes.as_slice() else {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "SignedData must have exactly one content-type attribute",
        ));
    };
    let AttributeValues::ContentType(values) = &attribute.value else {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "SignedData content-type attribute has an unexpected value",
        ));
    };
    let [content_type] = values.0.as_slice() else {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "SignedData content-type attribute must have exactly one value",
        ));
    };

    if content_type.0 != signed_data.content_info.content_type.0 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "SignedData content-type attribute does not match its encapsulated content type",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use picky::key::PrivateKey;
    use picky::x509::Cert;
    use picky::x509::certificate::CertificateBuilder;
    use picky::x509::date::UtcDate;
    use picky::x509::name::DirectoryName;
    use picky_asn1::wrapper::{Asn1SequenceOf, Asn1SetOf, OctetStringAsn1, Optional};
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
    use picky_asn1_x509::{AlgorithmIdentifier, KeyUsage, ShaVariant, oids};
    use time::{Date, Month, OffsetDateTime};

    use super::{is_enforce_requested, validate_kdc_certificate_with};
    use crate::ErrorKind;
    use crate::log_capture::LogCapture;

    /// Lab KDC certificate issued by a Windows enterprise CA.
    /// Valid from 2026-01-08 17:25:25 UTC until 2027-01-08 17:25:25 UTC.
    const LAB_KDC_CERT: &str = include_str!("../../test_assets/kdc_cert.cer");

    fn signed_data_with_certificates(certificates: &[&Cert]) -> SignedData {
        signed_data_with_signer(certificates, certificates[0])
    }

    fn signed_data_with_signer(certificates: &[&Cert], signer: &Cert) -> SignedData {
        SignedData {
            version: CmsVersion::V3,
            digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
            content_info: EncapsulatedContentInfo::new(oids::kpinit_dh_key_data(), Some(Vec::new())),
            certificates: Optional::from(CertificateSet(
                certificates
                    .iter()
                    .map(|cert| CertificateChoices::Certificate(Asn1RawDer(cert.to_der().unwrap())))
                    .collect(),
            )),
            crls: None,
            signers_infos: SignersInfos(Asn1SetOf::from(vec![signer_info(&asn1_cert(signer))])),
        }
    }

    fn signer_info(signer: &picky_asn1_x509::Certificate) -> SignerInfo {
        SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: signer.tbs_certificate.issuer.clone(),
                serial_number: CertificateSerialNumber(signer.tbs_certificate.serial_number.clone()),
            }),
            digest_algorithm: DigestAlgorithmIdentifier(AlgorithmIdentifier::new_sha(ShaVariant::SHA1)),
            signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(Vec::new()))),
            signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
            signature: SignatureValue(OctetStringAsn1::from(Vec::new())),
            unsigned_attrs: Optional::from(UnsignedAttributes(Vec::new())),
        }
    }

    fn utc(year: i32, month: Month, day: u8, hour: u8, minute: u8, second: u8) -> OffsetDateTime {
        Date::from_calendar_date(year, month, day)
            .unwrap()
            .with_hms(hour, minute, second)
            .unwrap()
            .assume_utc()
    }

    /// Tests of the chain check pass the CA certificate explicitly, so they do not depend on the environment.
    fn validate_unenforced(
        signed_data: &SignedData,
        ca_cert: Option<&picky_asn1_x509::Certificate>,
        now: OffsetDateTime,
    ) -> crate::Result<()> {
        validate_kdc_certificate_with(signed_data, ca_cert, no_system_roots, false, now)
    }

    fn no_system_roots() -> crate::Result<Vec<picky_asn1_x509::Certificate>> {
        Ok(Vec::new())
    }

    fn lab_kdc_certificate_result_at(now: OffsetDateTime) -> crate::Result<()> {
        let kdc_cert = Cert::from_pem_str(LAB_KDC_CERT).unwrap();
        let signed_data = signed_data_with_certificates(&[&kdc_cert]);

        validate_unenforced(&signed_data, None, now)
    }

    // oracle: reference `openssl x509 -dates` output for the committed fixture test_assets/kdc_cert.cer
    #[test]
    fn lab_kdc_certificate_is_accepted_inside_its_validity_period() {
        lab_kdc_certificate_result_at(utc(2026, Month::June, 1, 0, 0, 0)).unwrap();
    }

    // oracle: spec RFC 5280 §4.1.2.5 (the validity interval includes notBefore and notAfter)
    #[test]
    fn lab_kdc_certificate_is_accepted_at_not_before() {
        lab_kdc_certificate_result_at(utc(2026, Month::January, 8, 17, 25, 25)).unwrap();
    }

    #[test]
    fn lab_kdc_certificate_is_accepted_at_not_after() {
        lab_kdc_certificate_result_at(utc(2027, Month::January, 8, 17, 25, 25)).unwrap();
    }

    #[test]
    fn lab_kdc_certificate_is_rejected_before_not_before() {
        let error = lab_kdc_certificate_result_at(utc(2026, Month::January, 8, 17, 25, 24)).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn lab_kdc_certificate_is_rejected_after_not_after() {
        let error = lab_kdc_certificate_result_at(utc(2027, Month::January, 8, 17, 25, 26)).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    struct Pki {
        ca_key: PrivateKey,
        ca: Cert,
    }

    // RSA-1024 keeps key generation fast in debug builds. Nothing in the validation depends on the key size.
    fn generate_key() -> PrivateKey {
        PrivateKey::generate_rsa(1024).unwrap()
    }

    fn date(year: u16, month: u8) -> UtcDate {
        UtcDate::ymd(year, month, 1).unwrap()
    }

    fn root_ca(name: &str) -> Pki {
        root_ca_valid_until(name, date(2030, 1))
    }

    fn root_ca_valid_until(name: &str, valid_to: UtcDate) -> Pki {
        let ca_key = generate_key();
        let ca = CertificateBuilder::new()
            .validity(date(2026, 1), valid_to)
            .self_signed(DirectoryName::new_common_name(name), &ca_key)
            .ca(true)
            .build()
            .unwrap();

        Pki { ca_key, ca }
    }

    /// Issues a certificate for a freshly generated key. Returns the certificate and its key.
    fn issue(issuer: &Pki, name: &str, ca: bool, valid_from: UtcDate, valid_to: UtcDate) -> Pki {
        issue_with_key(issuer, generate_key(), name, ca, valid_from, valid_to)
    }

    /// Issues a certificate for `key`, so the same key can be certified by several issuers.
    fn issue_with_key(
        issuer: &Pki,
        key: PrivateKey,
        name: &str,
        ca: bool,
        valid_from: UtcDate,
        valid_to: UtcDate,
    ) -> Pki {
        let cert = CertificateBuilder::new()
            .validity(valid_from, valid_to)
            .subject(DirectoryName::new_common_name(name), key.to_public_key().unwrap())
            .issuer_cert(&issuer.ca, &issuer.ca_key)
            .ca(ca)
            .build()
            .unwrap();

        Pki { ca_key: key, ca: cert }
    }

    fn asn1_cert(cert: &Cert) -> picky_asn1_x509::Certificate {
        picky_asn1_der::from_bytes(&cert.to_der().unwrap()).unwrap()
    }

    fn validate_in_2027(reply_certificates: &[&Cert], anchor: &Cert) -> crate::Result<()> {
        let signed_data = signed_data_with_certificates(reply_certificates);

        validate_unenforced(
            &signed_data,
            Some(&asn1_cert(anchor)),
            utc(2027, Month::June, 1, 0, 0, 0),
        )
    }

    // The trust anchor is trusted by configuration, so it does not have to carry CA constraints.
    #[test]
    fn trust_anchor_with_ca_false_is_accepted() {
        let root = self_signed_without_ca_constraint("Test Root", Some(false));
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2028, 1));

        validate_in_2027(&[&kdc.ca], &root.ca).unwrap();
    }

    #[test]
    fn trust_anchor_without_basic_constraints_is_accepted() {
        let root = self_signed_without_ca_constraint("Test Root", None);
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2028, 1));

        validate_in_2027(&[&kdc.ca], &root.ca).unwrap();
    }

    fn self_signed_without_ca_constraint(name: &str, ca: Option<bool>) -> Pki {
        let ca_key = generate_key();
        let builder = CertificateBuilder::new();
        builder
            .validity(date(2026, 1), date(2030, 1))
            .self_signed(DirectoryName::new_common_name(name), &ca_key);
        if let Some(ca) = ca {
            builder.ca(ca);
        }

        Pki {
            ca: builder.build().unwrap(),
            ca_key,
        }
    }

    #[test]
    fn kdc_certificate_issued_by_trust_anchor_is_accepted() {
        let root = root_ca("Test Root");
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2028, 1));

        validate_in_2027(&[&kdc.ca], &root.ca).unwrap();
    }

    #[test]
    fn kdc_certificate_is_accepted_through_intermediates_from_the_reply() {
        let root = root_ca("Test Root");
        let intermediate = issue(&root, "Test Intermediate", true, date(2026, 3), date(2029, 1));
        let kdc = issue(&intermediate, "kdc", false, date(2026, 6), date(2028, 1));

        validate_in_2027(&[&kdc.ca, &intermediate.ca], &root.ca).unwrap();
    }

    #[test]
    fn kdc_certificate_signed_by_another_key_with_the_anchor_name_is_rejected() {
        let root = root_ca("Test Root");
        let imposter = root_ca("Test Root");
        let kdc = issue(&imposter, "kdc", false, date(2026, 6), date(2028, 1));

        let error = validate_in_2027(&[&kdc.ca], &root.ca).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn kdc_certificate_without_a_path_to_the_anchor_is_rejected() {
        let root = root_ca("Test Root");
        let other = root_ca("Other Root");
        let kdc = issue(&other, "kdc", false, date(2026, 6), date(2028, 1));

        let error = validate_in_2027(&[&kdc.ca], &root.ca).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn kdc_certificate_with_expired_intermediate_is_rejected() {
        let root = root_ca("Test Root");
        let intermediate = issue(&root, "Test Intermediate", true, date(2026, 3), date(2026, 12));
        let kdc = issue(&intermediate, "kdc", false, date(2026, 6), date(2028, 1));

        let error = validate_in_2027(&[&kdc.ca, &intermediate.ca], &root.ca).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn valid_intermediate_is_found_among_the_same_named_intermediates() {
        let root = root_ca("Test Root");
        let expired = issue(&root, "Test Intermediate", true, date(2026, 3), date(2026, 12));
        let renewed = issue(&root, "Test Intermediate", true, date(2026, 3), date(2030, 1));
        let kdc = issue(&renewed, "kdc", false, date(2026, 6), date(2028, 1));

        validate_in_2027(&[&kdc.ca, &expired.ca, &renewed.ca], &root.ca).unwrap();
    }

    #[test]
    fn kdc_certificate_issued_by_a_non_ca_intermediate_is_rejected() {
        let root = root_ca("Test Root");
        let intermediate = issue(&root, "Test Intermediate", false, date(2026, 3), date(2029, 1));
        let kdc = issue(&intermediate, "kdc", false, date(2026, 6), date(2028, 1));

        let error = validate_in_2027(&[&kdc.ca, &intermediate.ca], &root.ca).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn kdc_certificate_validity_is_checked_when_the_anchor_is_set() {
        let root = root_ca("Test Root");
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2026, 12));

        let error = validate_in_2027(&[&kdc.ca], &root.ca).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn kdc_certificate_with_expired_trust_anchor_is_rejected() {
        let root = root_ca_valid_until("Test Root", date(2026, 12));
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2028, 1));

        let error = validate_in_2027(&[&kdc.ca], &root.ca).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn kdc_certificate_issued_by_an_issuer_without_key_cert_sign_is_rejected() {
        let root = root_ca("Test Root");
        let key = generate_key();
        let intermediate = Pki {
            ca: CertificateBuilder::new()
                .validity(date(2026, 3), date(2029, 1))
                .subject(
                    DirectoryName::new_common_name("Test Intermediate"),
                    key.to_public_key().unwrap(),
                )
                .issuer_cert(&root.ca, &root.ca_key)
                .ca(true)
                .key_usage(KeyUsage::new(9))
                .build()
                .unwrap(),
            ca_key: key,
        };
        let kdc = issue(&intermediate, "kdc", false, date(2026, 6), date(2028, 1));

        let error = validate_in_2027(&[&kdc.ca, &intermediate.ca], &root.ca).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    #[test]
    fn lab_kdc_certificate_is_rejected_by_an_unrelated_trust_anchor() {
        let kdc_cert = Cert::from_pem_str(LAB_KDC_CERT).unwrap();
        let unrelated_ca = Cert::from_pem_str(include_str!("../../test_assets/pw11.cer")).unwrap();
        let signed_data = signed_data_with_certificates(&[&kdc_cert]);

        let error = validate_unenforced(
            &signed_data,
            Some(&asn1_cert(&unrelated_ca)),
            utc(2026, Month::June, 1, 0, 0, 0),
        )
        .unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    fn validate_in_2027_with_system_roots(
        reply_certificates: &[&Cert],
        ca_cert: Option<&Cert>,
        system_roots: &[&Cert],
        enforce_ca: bool,
    ) -> crate::Result<()> {
        let signed_data = signed_data_with_certificates(reply_certificates);
        let ca_cert = ca_cert.map(asn1_cert);
        let system_roots = system_roots.iter().map(|cert| asn1_cert(cert)).collect::<Vec<_>>();

        validate_kdc_certificate_with(
            &signed_data,
            ca_cert.as_ref(),
            || Ok(system_roots.clone()),
            enforce_ca,
            utc(2027, Month::June, 1, 0, 0, 0),
        )
    }

    const UNVERIFIED_CHAIN_WARNING: &str = "chain is not verified";

    // oracle: spec RFC 5280 §6.1 (a chain that ends in a trust anchor is valid)
    #[test]
    fn system_trust_anchor_vouches_for_the_kdc_certificate() {
        let root = root_ca("Test Root");
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2028, 1));
        let logs = LogCapture::start(tracing::Level::WARN);

        validate_in_2027_with_system_roots(&[&kdc.ca], None, &[&root.ca], false).unwrap();

        assert!(!logs.output().contains(UNVERIFIED_CHAIN_WARNING));
    }

    // oracle: mutant an unverified chain is logged and the logon continues
    #[test]
    fn kdc_certificate_unknown_to_the_system_store_is_accepted_with_a_warning_when_not_enforced() {
        let trusted = root_ca("Test Root");
        let unknown = root_ca("Other Root");
        let kdc = issue(&unknown, "kdc", false, date(2026, 6), date(2028, 1));
        let logs = LogCapture::start(tracing::Level::WARN);

        validate_in_2027_with_system_roots(&[&kdc.ca], None, &[&trusted.ca], false).unwrap();

        let output = logs.output();
        assert!(output.contains(UNVERIFIED_CHAIN_WARNING), "no warning in: {output}");
    }

    // oracle: spec RFC 5280 §6.1 (a chain that ends in an untrusted root is not valid)
    #[test]
    fn kdc_certificate_unknown_to_the_system_store_is_rejected_when_enforced() {
        let trusted = root_ca("Test Root");
        let unknown = root_ca("Other Root");
        let kdc = issue(&unknown, "kdc", false, date(2026, 6), date(2028, 1));

        let error = validate_in_2027_with_system_roots(&[&kdc.ca], None, &[&trusted.ca], true).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    // oracle: mutant an unavailable store is logged and the logon continues
    #[test]
    fn unavailable_system_store_is_accepted_with_a_warning_when_not_enforced() {
        let root = root_ca("Test Root");
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2028, 1));
        let signed_data = signed_data_with_certificates(&[&kdc.ca]);
        let logs = LogCapture::start(tracing::Level::WARN);

        validate_kdc_certificate_with(
            &signed_data,
            None,
            || Err(crate::Error::new(ErrorKind::Pku2uCertFailure, "store is unavailable")),
            false,
            utc(2027, Month::June, 1, 0, 0, 0),
        )
        .unwrap();

        assert!(logs.output().contains(UNVERIFIED_CHAIN_WARNING));
    }

    // oracle: mutant an unavailable store fails the logon when enforced
    #[test]
    fn unavailable_system_store_is_rejected_when_enforced() {
        let root = root_ca("Test Root");
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2028, 1));
        let signed_data = signed_data_with_certificates(&[&kdc.ca]);

        let error = validate_kdc_certificate_with(
            &signed_data,
            None,
            || Err(crate::Error::new(ErrorKind::Pku2uCertFailure, "store is unavailable")),
            true,
            utc(2027, Month::June, 1, 0, 0, 0),
        )
        .unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    // oracle: spec RFC 5280 §6.1 (a chain that does not end in the configured trust anchor is not valid)
    #[test]
    fn configured_ca_cert_that_does_not_vouch_is_rejected_even_when_not_enforced() {
        let configured = root_ca("Other Root");
        let system = root_ca("Test Root");
        let kdc = issue(&system, "kdc", false, date(2026, 6), date(2028, 1));

        let error =
            validate_in_2027_with_system_roots(&[&kdc.ca], Some(&configured.ca), &[&system.ca], false).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    // oracle: spec RFC 5280 §6.1 (a same-named trust anchor with the matching key is a valid anchor)
    #[test]
    fn issuer_with_a_renewed_key_is_found_among_the_same_named_trust_anchors() {
        let old_root = root_ca("Test Root");
        let renewed_root = root_ca("Test Root");
        let kdc = issue(&renewed_root, "kdc", false, date(2026, 6), date(2028, 1));
        let logs = LogCapture::start(tracing::Level::WARN);

        validate_in_2027_with_system_roots(&[&kdc.ca], None, &[&old_root.ca, &renewed_root.ca], false).unwrap();

        assert!(!logs.output().contains(UNVERIFIED_CHAIN_WARNING));
    }

    // oracle: spec RFC 5280 §4.1.2.5 (an expired certificate is not valid even without a verified chain)
    #[test]
    fn missing_system_store_still_checks_the_validity_period() {
        let root = root_ca("Test Root");
        let kdc = issue(&root, "kdc", false, date(2026, 6), date(2027, 1));
        let signed_data = signed_data_with_certificates(&[&kdc.ca]);

        let error = validate_kdc_certificate_with(
            &signed_data,
            None,
            no_system_roots,
            false,
            utc(2027, Month::June, 1, 0, 0, 0),
        )
        .unwrap_err();

        assert_eq!(error.error_type, ErrorKind::Pku2uCertFailure);
    }

    // oracle: mutant only the explicit values 1 and true enable the requirement
    #[test]
    fn only_explicit_values_enable_the_ca_requirement() {
        for (value, expected) in [
            ("1", true),
            ("true", true),
            ("TRUE", true),
            (" True ", true),
            ("0", false),
            ("false", false),
            ("", false),
            ("yes", false),
        ] {
            assert_eq!(is_enforce_requested(value), expected, "value {value:?}");
        }
    }

    // oracle: spec RFC 5652 §5.1 (the certificates are a collection in no required order; §5.3 sid names the signer)
    #[test]
    fn signer_is_selected_by_its_signer_info_when_an_intermediate_comes_first() {
        let root = root_ca("Test Root");
        let intermediate = issue(&root, "Intermediate", true, date(2026, 6), date(2028, 1));
        let kdc = issue(&intermediate, "kdc", false, date(2026, 6), date(2028, 1));
        let signed_data = signed_data_with_signer(&[&intermediate.ca, &kdc.ca], &kdc.ca);

        validate_kdc_certificate_with(
            &signed_data,
            Some(&asn1_cert(&root.ca)),
            no_system_roots,
            false,
            utc(2027, Month::June, 1, 0, 0, 0),
        )
        .unwrap();
    }

    // oracle: mutant greedy intermediate selection fails when the first same-named intermediate cannot reach an anchor
    #[test]
    fn same_named_intermediate_with_another_issuer_does_not_hide_the_valid_path() {
        let root = root_ca("Test Root");
        let other = root_ca("Other Root");
        let intermediate_key = generate_key();
        let untrusted = issue_with_key(
            &other,
            intermediate_key.clone(),
            "Intermediate",
            true,
            date(2026, 6),
            date(2028, 1),
        );
        let trusted = issue_with_key(
            &root,
            intermediate_key,
            "Intermediate",
            true,
            date(2026, 6),
            date(2028, 1),
        );
        let kdc = issue(&trusted, "kdc", false, date(2026, 6), date(2028, 1));
        let signed_data = signed_data_with_signer(&[&kdc.ca, &untrusted.ca, &trusted.ca], &kdc.ca);

        validate_kdc_certificate_with(
            &signed_data,
            Some(&asn1_cert(&root.ca)),
            no_system_roots,
            false,
            utc(2027, Month::June, 1, 0, 0, 0),
        )
        .unwrap();
    }

    // oracle: mutant an anchor with the issuer's name but another key ends the search before a cross-certified path
    #[test]
    fn cross_certified_renewed_key_is_accepted_when_the_old_anchor_has_the_same_name() {
        let old_root = root_ca("Test Root");
        let renewed_key = generate_key();
        let cross_certificate = issue_with_key(&old_root, renewed_key, "Test Root", true, date(2026, 6), date(2028, 1));
        let kdc = issue(&cross_certificate, "kdc", false, date(2026, 6), date(2028, 1));
        let signed_data = signed_data_with_signer(&[&kdc.ca, &cross_certificate.ca], &kdc.ca);

        validate_kdc_certificate_with(
            &signed_data,
            Some(&asn1_cert(&old_root.ca)),
            no_system_roots,
            false,
            utc(2027, Month::June, 1, 0, 0, 0),
        )
        .unwrap();
    }
}

#[cfg(test)]
mod content_type_tests {
    use picky_asn1::wrapper::{Asn1SequenceOf, Asn1SetOf, ObjectIdentifierAsn1, OctetStringAsn1, Optional};
    use picky_asn1_x509::cmsversion::CmsVersion;
    use picky_asn1_x509::content_info::EncapsulatedContentInfo;
    use picky_asn1_x509::signed_data::{CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos};
    use picky_asn1_x509::signer_info::{
        Attributes, CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber,
        SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo, UnsignedAttributes,
    };
    use picky_asn1_x509::{AlgorithmIdentifier, Attribute, AttributeValues, ShaVariant, oids};

    use super::validate_content_type_attribute;
    use crate::ErrorKind;

    fn content_type_attribute(oid: oid::ObjectIdentifier) -> Attribute {
        Attribute {
            ty: ObjectIdentifierAsn1::from(oids::content_type()),
            value: AttributeValues::ContentType(Asn1SetOf::from(vec![ObjectIdentifierAsn1::from(oid)])),
        }
    }

    fn message_digest_attribute() -> Attribute {
        Attribute {
            ty: ObjectIdentifierAsn1::from(oids::message_digest()),
            value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![OctetStringAsn1::from(vec![0; 20])])),
        }
    }

    /// Builds a DH key data SignedData whose only signer carries the given signed attributes.
    fn signed_data_with_attributes(attributes: Vec<Attribute>) -> SignedData {
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: Default::default(),
                serial_number: CertificateSerialNumber(vec![1].into()),
            }),
            digest_algorithm: DigestAlgorithmIdentifier(AlgorithmIdentifier::new_sha(ShaVariant::SHA1)),
            signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(attributes))),
            signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
            signature: SignatureValue(OctetStringAsn1::from(Vec::new())),
            unsigned_attrs: Optional::from(UnsignedAttributes(Vec::new())),
        };

        SignedData {
            version: CmsVersion::V3,
            digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
            content_info: EncapsulatedContentInfo::new(oids::kpinit_dh_key_data(), Some(Vec::new())),
            certificates: Optional::from(CertificateSet(Vec::new())),
            crls: None,
            signers_infos: SignersInfos(Asn1SetOf::from(vec![signer_info])),
        }
    }

    // oracle: spec RFC 5652 §11.1 (the content-type attribute MUST be present and MUST match the encapsulated type)
    #[test]
    fn content_type_attribute_matching_the_content_is_accepted() {
        let signed_data = signed_data_with_attributes(vec![
            content_type_attribute(oids::kpinit_dh_key_data()),
            message_digest_attribute(),
        ]);

        validate_content_type_attribute(&signed_data).unwrap();
    }

    #[test]
    fn missing_content_type_attribute_is_rejected() {
        let signed_data = signed_data_with_attributes(vec![message_digest_attribute()]);

        let error = validate_content_type_attribute(&signed_data).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    #[test]
    fn content_type_attribute_differing_from_the_content_is_rejected() {
        let signed_data = signed_data_with_attributes(vec![
            content_type_attribute(oids::pkinit_auth_data()),
            message_digest_attribute(),
        ]);

        let error = validate_content_type_attribute(&signed_data).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    fn content_type_attribute_with_values(values: Vec<oid::ObjectIdentifier>) -> Attribute {
        Attribute {
            ty: ObjectIdentifierAsn1::from(oids::content_type()),
            value: AttributeValues::ContentType(Asn1SetOf::from(
                values.into_iter().map(ObjectIdentifierAsn1::from).collect::<Vec<_>>(),
            )),
        }
    }

    // oracle: spec RFC 5652 §11.1 (ContentType is a single OBJECT IDENTIFIER)
    #[test]
    fn content_type_attribute_with_several_values_is_rejected() {
        let signed_data = signed_data_with_attributes(vec![
            content_type_attribute_with_values(vec![oids::kpinit_dh_key_data(), oids::pkinit_auth_data()]),
            message_digest_attribute(),
        ]);

        let error = validate_content_type_attribute(&signed_data).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    // oracle: mutant a second content-type attribute hides a mismatching first one
    #[test]
    fn duplicate_content_type_attributes_are_rejected() {
        let signed_data = signed_data_with_attributes(vec![
            content_type_attribute(oids::kpinit_dh_key_data()),
            content_type_attribute(oids::kpinit_dh_key_data()),
            message_digest_attribute(),
        ]);

        let error = validate_content_type_attribute(&signed_data).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    // oracle: mutant an empty content-type attribute is skipped and hides the matching one
    #[test]
    fn empty_content_type_attribute_next_to_a_matching_one_is_rejected() {
        let signed_data = signed_data_with_attributes(vec![
            content_type_attribute_with_values(Vec::new()),
            content_type_attribute(oids::kpinit_dh_key_data()),
            message_digest_attribute(),
        ]);

        let error = validate_content_type_attribute(&signed_data).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }
}
