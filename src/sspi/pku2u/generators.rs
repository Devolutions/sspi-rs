use std::convert::TryFrom;
use std::fmt::Debug;
use std::str::FromStr;

use chrono::Utc;
use oid::ObjectIdentifier;
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::{BMPString, IA5String};
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BMPStringAsn1, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1,
    ExplicitContextTag2, ExplicitContextTag3, ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1,
    Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::EncapsulatedContentInfo;
use picky_asn1_x509::oids::{AT_COMMON_NAME, DIFFIE_HELLMAN, GSS_PKU2U, NEGOEX, NTLM_SSP, PKINIT_AUTH_DATA, SPNEGO};
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_asn1_x509::signer_info::{
    Attributes, CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber,
    SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo, UnsignedAttributes,
};
use picky_asn1_x509::{
    AlgorithmIdentifier, Attribute, AttributeTypeAndValue, AttributeTypeAndValueParameters, AttributeValues,
    Certificate, DirectoryString, Name, RdnSequence, RelativeDistinguishedName, ShaVariant, SubjectKeyIdentifier,
    Version,
};
use picky_krb::constants::gss_api::ACCEPT_INCOMPLETE;
use picky_krb::constants::types::{NT_SRV_INST, PA_PK_AS_REQ};
use picky_krb::crypto::diffie_hellman::{compute_public_key, generate_private_key, get_default_parameters};
use picky_krb::data_types::{KerberosStringAsn1, KerberosTime, PaData, PrincipalName, Realm};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg,
};
use picky_krb::messages::KdcReqBody;
use picky_krb::pkinit::{
    AuthPack, DhDomainParameters, DhReqInfo, DhReqKeyInfo, PaPkAsReq, PkAuthenticator, Pku2uNegoBody, Pku2uNegoReq,
    Pku2uNegoReqMetadata, Pku2uValue, Pku2uValueInner,
};
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, PaddingScheme};
use sha1::{Digest, Sha1};

use super::{DhParameters, Pku2uConfig};
use crate::kerberos::client::generators::MAX_MICROSECONDS_IN_SECOND;
use crate::kerberos::SERVICE_NAME;
use crate::Result;

/// [The PKU2U Realm Name](https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-09#section-3)
/// The PKU2U realm name is defined as a reserved Kerberos realm name, and it has the value of "WELLKNOWN:PKU2U".
pub const WELLKNOWN_REALM: &str = "WELLKNOWN:PKU2U";

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// 9. This nonce string MUST be as long as the longest key length of the symmetric key types that the client supports.
/// Key length of Aes256 is equal to 32
pub const DH_NONCE_LEN: usize = 32;

// returns supported authentication types
pub fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![
        MechType::from(ObjectIdentifier::try_from(NEGOEX).unwrap()),
        MechType::from(ObjectIdentifier::try_from(NTLM_SSP).unwrap()),
    ])
}

pub fn generate_pku2u_nego_req(_username: &str, config: &Pku2uConfig) -> Result<Pku2uNegoReq> {
    Ok(Pku2uNegoReq {
        metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![Pku2uNegoReqMetadata {
            inner: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                &config.p2p_certificate.tbs_certificate.issuer,
            )?)),
        }])),
        body: ExplicitContextTag1::from(Pku2uNegoBody {
            realm: ExplicitContextTag0::from(Realm::from(IA5String::from_str(WELLKNOWN_REALM)?)),
            sname: ExplicitContextTag1::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_str(SERVICE_NAME)?),
                    // KerberosStringAsn1::from(IA5String::from_str(username).unwrap()),
                    // for the debugging
                    KerberosStringAsn1::from(IA5String::from_str("192.168.0.117")?),
                ])),
            }),
        }),
    })
}

pub fn generate_neg_token_init(mech_token: Vec<u8>) -> Result<ApplicationTag0<GssApiNegInit>> {
    Ok(ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(SPNEGO).unwrap()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(get_mech_list()))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(mech_token)))),
            mech_list_mic: Optional::from(None),
        }),
    }))
}

pub fn generate_neg_token_targ(token: Vec<u8>) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    Ok(ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(token)))),
        mech_list_mic: Optional::from(None),
    }))
}

// pub fn version_to_cms_version(v: Version) -> CmsVersion {
//     match v {
//         Version::V1 => CmsVersion::V1,
//         Version::V2 => CmsVersion::V2,
//         Version::V3 => CmsVersion::V3,
//     }
// }

pub fn generate_signer_info(p2p_cert: &Certificate, digest: Vec<u8>, encrypted: Vec<u8>) -> SignerInfo {
    // SignerInfo {
    //     version: version_to_cms_version(p2p_ca_cert.tbs_certificate.version.0),
    //     sid: SignerIdentifier::SubjectKeyIdentifier(ImplicitContextTag0::from(SubjectKeyIdentifier::from(
    //         p2p_ca_cert.subject_key_identifier().unwrap().to_vec(),
    //     ))),
    //     digest_algorithm: DigestAlgorithmIdentifier(
    //         p2p_ca_cert.tbs_certificate.subject_public_key_info.algorithm.clone(),
    //     ),
    //     signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(vec![]))),
    //     signature_algorithm: SignatureAlgorithmIdentifier(p2p_ca_cert.signature_algorithm.clone()),
    //     signature: SignatureValue(OctetStringAsn1::from(p2p_ca_cert.signature_value.0.inner())),
    //     unsigned_attrs: Optional::from(UnsignedAttributes(vec![])),
    // }
    println!("{:x?}", p2p_cert.tbs_certificate.serial_number);
    println!("{:?}", picky_asn1_der::to_vec(&p2p_cert.tbs_certificate.serial_number).unwrap());
    SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            // issuer: Name(RdnSequence::from(vec![
            //     RelativeDistinguishedName::from(vec![
            //         AttributeTypeAndValue {
            //             ty: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("2.5.4.3").unwrap()),
            //             value: AttributeTypeAndValueParameters::CommonName(DirectoryString::BmpString(BMPStringAsn1(BMPString::from_str("\0M\0S\0-\0O\0r\0g\0a\0n\0i\0z\0a\0t\0i\0o\0n\0-\0P\02\0P\0-\0A\0c\0c\0e\0s\0s\0 \0[\02\00\02\02\0]").unwrap()))),
            //         },
            //     ]),
            // ])),
            issuer: p2p_cert.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(p2p_cert.tbs_certificate.serial_number.clone()),
        }),
        digest_algorithm: DigestAlgorithmIdentifier(
            AlgorithmIdentifier::new_sha(ShaVariant::SHA1)
        ),
        signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(vec![
            Attribute {
                ty: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("1.2.840.113549.1.9.3").unwrap()),
                value: AttributeValues::ContentType(Asn1SetOf::from(vec![
                    ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("1.3.6.1.5.2.3.1").unwrap()),
                ])),
            },
            Attribute {
                ty: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("1.2.840.113549.1.9.4").unwrap()),
                value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![
                    OctetStringAsn1::from(digest),
                ])),
            },
        ]))),
        signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
        signature: SignatureValue(OctetStringAsn1::from(encrypted)),
        unsigned_attrs: Optional::from(UnsignedAttributes(Vec::new())),
    }
}

pub fn generate_client_dh_parameters() -> Result<DhParameters> {
    let (p, g, q) = get_default_parameters();

    let mut rng = OsRng::default();

    let private_key = generate_private_key(&q, &mut rng);

    Ok(DhParameters {
        base: g,
        modulus: p,
        q,
        private_key,
        other_public_key: None,
        client_nonce: Some([
            142, 91, 149, 4, 44, 55, 103, 6, 75, 168, 207, 165, 162, 197, 172, 27, 2, 108, 166, 10, 240, 52, 179, 24,
            56, 73, 137, 103, 160, 81, 236, 230,
        ]),
        server_nonce: None,
    })
}

pub fn generate_pa_datas_for_as_req(
    p2p_cert: &Certificate,
    p2p_ca_cert: &Certificate,
    kdc_req_body: &KdcReqBody,
    auth_nonce: u32,
    dh_parameters: &DhParameters,
    private_key: &RsaPrivateKey,
) -> Result<Vec<PaData>> {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    // [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
    // paChecksum: Contains the SHA1 checksum, performed over KDC-REQ-BODY.
    let encoded_kdc_req_body = picky_asn1_der::to_vec(&kdc_req_body)?;

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_kdc_req_body);

    let kdc_req_body_sha1_hash = sha1.finalize().to_vec();

    // let public_value = compute_public_key(&dh_parameters.private_key, &dh_parameters.modulus, &dh_parameters.base);
    let public_value = vec![
        2, 129, 129, 0, 249, 88, 64, 57, 194, 169, 38, 81, 23, 108, 110, 192, 241, 51, 44, 113, 50, 16, 179, 173, 72,
        57, 1, 65, 37, 199, 206, 229, 194, 186, 223, 122, 110, 117, 97, 237, 76, 86, 102, 153, 66, 47, 52, 176, 243,
        60, 14, 170, 4, 193, 138, 1, 193, 17, 154, 245, 113, 70, 182, 157, 112, 20, 178, 250, 176, 201, 248, 194, 226,
        23, 111, 177, 147, 141, 23, 77, 151, 226, 57, 213, 242, 172, 56, 40, 47, 191, 10, 135, 217, 26, 111, 24, 45,
        196, 40, 228, 106, 72, 173, 249, 255, 19, 254, 97, 184, 175, 205, 84, 209, 200, 11, 137, 117, 233, 218, 62,
        190, 76, 27, 110, 224, 185, 213, 207, 159, 52, 106, 94,
    ];

    println!("public key value len: {:?} bytes", public_value);

    let auth_pack = AuthPack {
        pk_authenticator: ExplicitContextTag0::from(PkAuthenticator {
            // cusec: ExplicitContextTag0::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
            cusec: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x04, 0x4e, 0x14])),
            ctime: ExplicitContextTag1::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            // nonce: ExplicitContextTag2::from(IntegerAsn1::from(auth_nonce.to_be_bytes().to_vec())),
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(vec![0])),
            pa_checksum: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1::from(
                kdc_req_body_sha1_hash,
            )))),
        }),
        client_public_value: Optional::from(Some(ExplicitContextTag1::from(DhReqInfo {
            key_info: DhReqKeyInfo {
                identifier: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(DIFFIE_HELLMAN).unwrap()),
                key_info: DhDomainParameters {
                    p: IntegerAsn1::from(dh_parameters.modulus.clone()),
                    g: IntegerAsn1::from(dh_parameters.base.clone()),
                    q: IntegerAsn1::from(dh_parameters.q.clone()),
                    j: Optional::from(None),
                    validation_params: Optional::from(None),
                },
            },
            key_value: BitStringAsn1::from(BitString::with_bytes(
                // picky_asn1_der::to_vec(&IntegerAsn1::from(
                //     public_value,
                // ))?
                vec![
                    2, 129, 129, 0, 249, 88, 64, 57, 194, 169, 38, 81, 23, 108, 110, 192, 241, 51, 44, 113, 50, 16,
                    179, 173, 72, 57, 1, 65, 37, 199, 206, 229, 194, 186, 223, 122, 110, 117, 97, 237, 76, 86, 102,
                    153, 66, 47, 52, 176, 243, 60, 14, 170, 4, 193, 138, 1, 193, 17, 154, 245, 113, 70, 182, 157, 112,
                    20, 178, 250, 176, 201, 248, 194, 226, 23, 111, 177, 147, 141, 23, 77, 151, 226, 57, 213, 242, 172,
                    56, 40, 47, 191, 10, 135, 217, 26, 111, 24, 45, 196, 40, 228, 106, 72, 173, 249, 255, 19, 254, 97,
                    184, 175, 205, 84, 209, 200, 11, 137, 117, 233, 218, 62, 190, 76, 27, 110, 224, 185, 213, 207, 159,
                    52, 106, 94,
                ],
            )),
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

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_auth_pack);

    let digest = sha1.finalize().to_vec();
    println!("digest: {:?}", digest);

    let mut new_digest = b"AzureAD\\MS-Organization-P2P-Access [2022]\\faadc5d3-fb45-4d03-902e-9965a96c463e".to_vec();
    new_digest.extend_from_slice(&[0x00]);
    // new_digest.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    new_digest.extend_from_slice(&digest);

    let mut sha1 = Sha1::new();
    sha1.update(&new_digest);

    let h = sha1.finalize().to_vec();

    let rsa_signature = private_key.sign(
        // PaddingScheme::new_pkcs1v15_sign(None),
        PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA1)),
        &h,
    ).unwrap();
    println!("rsa_signature: {} {:?}", rsa_signature.len(), rsa_signature);

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
        content_info: EncapsulatedContentInfo::new(
            ObjectIdentifier::try_from(PKINIT_AUTH_DATA).unwrap(),
            Some(encoded_auth_pack),
        ),
        certificates: Optional::from(CertificateSet(vec![CertificateChoices::Certificate(Asn1RawDer(
            picky_asn1_der::to_vec(p2p_cert)?,
        ))])),
        crls: None,
        signers_infos: SignersInfos(Asn1SetOf::from(vec![generate_signer_info(p2p_cert, digest, rsa_signature)])),
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

pub fn generate_neg<T: Debug + PartialEq + Clone>(
    krb_msg: T,
    krb5_token_id: [u8; 2],
) -> ApplicationTag<KrbMessage<T>, 0> {
    ApplicationTag::from(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(GSS_PKU2U).unwrap()),
        krb5_token_id,
        krb_msg,
    })
}

#[cfg(test)]
mod tests {
    use oid::ObjectIdentifier;
    use picky_asn1::bit_string::BitString;
    use picky_asn1::wrapper::{BitStringAsn1, ObjectIdentifierAsn1};
    use picky_asn1_x509::oids::NEGOEX;
    use picky_krb::crypto::CipherSuite;
    use sha1::{Digest, Sha1};

    use super::generate_pku2u_nego_req;
    use crate::sspi::pku2u::generators::generate_neg;
    use crate::sspi::pku2u::Pku2uConfig;

    #[test]
    fn _neg_token_init_generation() {
        let token = generate_pku2u_nego_req("", &Pku2uConfig::default()).unwrap();

        println!("{:?}", picky_asn1_der::to_vec(&token).unwrap());
    }

    #[test]
    fn neg() {
        let o = ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(NEGOEX).unwrap());

        let token = generate_neg(o, [0x05, 0x00]);

        println!("{:?}", picky_asn1_der::to_vec(&token).unwrap());
    }

    #[test]
    fn bit() {
        let data = [
            3, 129, 133, 0, 2, 129, 129, 0, 249, 88, 64, 57, 194, 169, 38, 81, 23, 108, 110, 192, 241, 51, 44, 113, 50,
            16, 179, 173, 72, 57, 1, 65, 37, 199, 206, 229, 194, 186, 223, 122, 110, 117, 97, 237, 76, 86, 102, 153,
            66, 47, 52, 176, 243, 60, 14, 170, 4, 193, 138, 1, 193, 17, 154, 245, 113, 70, 182, 157, 112, 20, 178, 250,
            176, 201, 248, 194, 226, 23, 111, 177, 147, 141, 23, 77, 151, 226, 57, 213, 242, 172, 56, 40, 47, 191, 10,
            135, 217, 26, 111, 24, 45, 196, 40, 228, 106, 72, 173, 249, 255, 19, 254, 97, 184, 175, 205, 84, 209, 200,
            11, 137, 117, 233, 218, 62, 190, 76, 27, 110, 224, 185, 213, 207, 159, 52, 106, 94,
        ];

        let b: BitStringAsn1 = picky_asn1_der::from_bytes(&data).unwrap();
        let c = BitStringAsn1::from(BitString::with_bytes(vec![
            2, 129, 129, 0, 249, 88, 64, 57, 194, 169, 38, 81, 23, 108, 110, 192, 241, 51, 44, 113, 50, 16, 179, 173,
            72, 57, 1, 65, 37, 199, 206, 229, 194, 186, 223, 122, 110, 117, 97, 237, 76, 86, 102, 153, 66, 47, 52, 176,
            243, 60, 14, 170, 4, 193, 138, 1, 193, 17, 154, 245, 113, 70, 182, 157, 112, 20, 178, 250, 176, 201, 248,
            194, 226, 23, 111, 177, 147, 141, 23, 77, 151, 226, 57, 213, 242, 172, 56, 40, 47, 191, 10, 135, 217, 26,
            111, 24, 45, 196, 40, 228, 106, 72, 173, 249, 255, 19, 254, 97, 184, 175, 205, 84, 209, 200, 11, 137, 117,
            233, 218, 62, 190, 76, 27, 110, 224, 185, 213, 207, 159, 52, 106, 94,
        ]));
        println!("{:?}", b);
        println!("{:?}", c);
        assert_eq!(b, c);
    }

    #[test]
    fn s1() {
        let data = [48, 130, 1, 12, 160, 7, 3, 5, 0, 64, 129, 0, 16, 161, 107, 48, 105, 160, 3, 2, 1, 128, 161, 98, 48, 96, 27, 94, 65, 122, 117, 114, 101, 65, 68, 92, 77, 83, 45, 79, 114, 103, 97, 110, 105, 122, 97, 116, 105, 111, 110, 45, 80, 50, 80, 45, 65, 99, 99, 101, 115, 115, 32, 91, 50, 48, 50, 50, 93, 92, 83, 45, 49, 45, 49, 50, 45, 49, 45, 51, 54, 53, 51, 50, 49, 49, 48, 50, 50, 45, 49, 51, 51, 57, 48, 48, 54, 52, 50, 50, 45, 50, 54, 50, 55, 53, 55, 51, 57, 48, 48, 45, 49, 53, 54, 48, 55, 51, 52, 57, 49, 57, 162, 17, 27, 15, 87, 69, 76, 76, 75, 78, 79, 87, 78, 58, 80, 75, 85, 50, 85, 163, 35, 48, 33, 160, 3, 2, 1, 2, 161, 26, 48, 24, 27, 7, 84, 69, 82, 77, 83, 82, 86, 27, 13, 49, 57, 50, 46, 49, 54, 56, 46, 48, 46, 49, 49, 55, 165, 17, 24, 15, 50, 48, 50, 50, 49, 48, 48, 53, 48, 56, 51, 54, 51, 50, 90, 166, 17, 24, 15, 50, 48, 50, 50, 49, 48, 48, 53, 48, 56, 51, 54, 51, 50, 90, 167, 3, 2, 1, 0, 168, 18, 48, 16, 2, 1, 18, 2, 1, 17, 2, 1, 23, 2, 1, 24, 2, 2, 255, 121, 169, 29, 48, 27, 48, 25, 160, 3, 2, 1, 20, 161, 18, 4, 16, 68, 69, 83, 75, 84, 79, 80, 45, 56, 70, 51, 51, 82, 70, 72, 32];

        let mut sha1 = Sha1::new();

        sha1.update(&data);

        let hash = sha1.finalize().to_vec();

        assert_eq!(
            &[249, 161, 134, 235, 134, 197, 25, 245, 122, 58, 180, 205, 8, 178, 158, 103, 207, 8, 208, 168],
            hash.as_slice(),
        );
    }
}
