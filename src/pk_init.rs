use chrono::Utc;
use picky::hash::HashAlgorithm;
use picky::key::PrivateKey;
use picky::signature::SignatureAlgorithm;
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{IntegerAsn1, ObjectIdentifierAsn1, Optional, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, OctetStringAsn1, BitStringAsn1, Asn1SetOf, ImplicitContextTag0, Asn1SequenceOf};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::signer_info::{SignerInfo, IssuerAndSerialNumber, CertificateSerialNumber, DigestAlgorithmIdentifier, SignatureAlgorithmIdentifier, UnsignedAttributes, Attributes, SignerIdentifier, SignatureValue};
use picky_asn1_x509::{Certificate, AlgorithmIdentifier, Attribute, AttributeValues, ShaVariant, oids};
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::EncapsulatedContentInfo;
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_krb::constants::types::PA_PK_AS_REQ;
use picky_krb::crypto::diffie_hellman::compute_public_key;
use picky_krb::data_types::{PaData, KerberosTime};
use picky_krb::messages::KdcReqBody;
use picky_krb::pkinit::{DhReqKeyInfo, AuthPack, DhDomainParameters, DhReqInfo, PkAuthenticator, PaPkAsReq};
use sha1::{Sha1, Digest};

use crate::kerberos::client::generators::MAX_MICROSECONDS_IN_SECOND;
use crate::pku2u::DhParameters;
use crate::{Result, Error, ErrorKind};

#[instrument(level = "trace", ret)]
pub fn generate_pa_datas_for_as_req(
    p2p_cert: &Certificate,
    kdc_req_body: &KdcReqBody,
    dh_parameters: &DhParameters,
    private_key: &PrivateKey,
) -> Result<Vec<PaData>> {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    // [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
    // paChecksum: Contains the SHA1 checksum, performed over KDC-REQ-BODY.
    let encoded_kdc_req_body = picky_asn1_der::to_vec(&kdc_req_body)?;
    trace!(?kdc_req_body, "Encoded KdcReqBody");

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_kdc_req_body);

    let kdc_req_body_sha1_hash = sha1.finalize().to_vec();

    let public_value = compute_public_key(&dh_parameters.private_key, &dh_parameters.modulus, &dh_parameters.base);

    let auth_pack = AuthPack {
        pk_authenticator: ExplicitContextTag0::from(PkAuthenticator {
            cusec: ExplicitContextTag0::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
            ctime: ExplicitContextTag1::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            // always 0 in Pku2u
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(vec![0])),
            pa_checksum: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1::from(
                kdc_req_body_sha1_hash,
            )))),
        }),
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
        supported_cms_types: Optional::from(None),
        client_dh_nonce: Optional::from(
            dh_parameters
                .client_nonce
                .as_ref()
                .map(|nonce| ExplicitContextTag3::from(OctetStringAsn1::from(nonce.to_vec()))),
        ),
    };

    let encoded_auth_pack = picky_asn1_der::to_vec(&auth_pack)?;
    trace!(?encoded_auth_pack, "Encoded auth pack");

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_auth_pack);

    let digest = sha1.finalize().to_vec();

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
        content_info: EncapsulatedContentInfo::new(oids::pkinit_auth_data(), Some(encoded_auth_pack)),
        certificates: Optional::from(CertificateSet(vec![CertificateChoices::Certificate(Asn1RawDer(
            picky_asn1_der::to_vec(p2p_cert)?,
        ))])),
        crls: None,
        signers_infos: SignersInfos(Asn1SetOf::from(vec![generate_signer_info(
            p2p_cert,
            digest,
            private_key,
        )?])),
    };

    let pa_pk_as_req = PaPkAsReq {
        signed_auth_pack: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&signed_data)?)),
        trusted_certifiers: Optional::from(None),
        kdc_pk_id: Optional::from(None),
    };

    Ok(vec![PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PK_AS_REQ.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&pa_pk_as_req)?)),
    }])
}

pub fn generate_signer_info(p2p_cert: &Certificate, digest: Vec<u8>, private_key: &PrivateKey) -> Result<SignerInfo> {
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

    let signature = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)
        .sign(&encoded_signed_attributes, private_key)
        .map_err(|err| {
            Error::new(
                ErrorKind::InternalError,
                format!("Cannot calculate signer info signature: {:?}", err),
            )
        })?;

    trace!(?encoded_signed_attributes, ?signature, "Pku2u signed attributes",);

    Ok(SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: p2p_cert.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(p2p_cert.tbs_certificate.serial_number.clone()),
        }),
        digest_algorithm: DigestAlgorithmIdentifier(AlgorithmIdentifier::new_sha(ShaVariant::SHA1)),
        signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(signed_attributes.0))),
        signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
        signature: SignatureValue(OctetStringAsn1::from(signature)),
        unsigned_attrs: Optional::from(UnsignedAttributes(Vec::new())),
    })
}