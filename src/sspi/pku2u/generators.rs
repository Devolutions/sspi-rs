use std::convert::TryFrom;
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
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::EncapsulatedContentInfo;
use picky_asn1_x509::oids::{AT_COMMON_NAME, DIFFIE_HELLMAN, GSS_PKU2U, NEGOEX, PKINIT_AUTH_DATA, SPNEGO};
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_asn1_x509::signer_info::{
    Attributes, DigestAlgorithmIdentifier, SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo,
    UnsignedAttributes,
};
use picky_asn1_x509::{AlgorithmIdentifier, Certificate, SubjectKeyIdentifier, Version};
use picky_krb::constants::gss_api::ACCEPT_INCOMPLETE;
use picky_krb::constants::types::{NT_SRV_INST, PA_PK_AS_REQ};
use picky_krb::data_types::{KerberosStringAsn1, KerberosTime, PaData, PrincipalName, Realm};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg,
};
use picky_krb::messages::KdcReqBody;
use picky_krb::pkinit::{
    AuthPack, DhDomainParameters, DhReqInfo, DhReqKeyInfo, PaPkAsReq, PkAuthenticator, Pku2uNegoBody, Pku2uNegoReq,
    Pku2uNegoReqMetadata, Pku2uValue, Pku2uValueInner,
};
use sha1::{Digest, Sha1};

use super::DhParameters;
use crate::kerberos::client::generators::MAX_MICROSECONDS_IN_SECOND;
use crate::kerberos::SERVICE_NAME;
use crate::Result;

/// [The PKU2U Realm Name](https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-09#section-3)
/// The PKU2U realm name is defined as a reserved Kerberos realm name, and it has the value of "WELLKNOWN:PKU2U".
pub const WELLKNOWN_REALM: &str = "WELLKNOWN:PKU2U";

/// "MS-Organization-P2P-Access [2021]" in UTF-16
pub const MS_ORGANIZATION_P2P_ACCESS: &str =
    "\0M\0S\0-\0O\0r\0g\0a\0n\0i\0z\0a\0t\0i\0o\0n\0-\0P\02\0P\0-\0A\0c\0c\0e\0s\0s\0 \0[\02\00\02\01\0]";

/// [Generation of Client Request](https://www.rfc-editor.org/rfc/rfc4556.html#section-3.2.1)
/// 9. This nonce string MUST be as long as the longest key length of the symmetric key types that the client supports.
/// Key length of Aes256 is equal to 32
pub const DH_NONCE_LEN: usize = 32;

// returns supported authentication types
pub fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![
        MechType::from(ObjectIdentifier::try_from(NEGOEX).unwrap()),
        // MechType::from(ObjectIdentifier::try_from(NTLM_SSP).unwrap()),
    ])
}

pub fn generate_pku2u_nego_req(username: &str) -> Result<Pku2uNegoReq> {
    let inner = Pku2uValue {
        inner: Asn1SetOf::from(vec![Pku2uValueInner {
            identifier: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(AT_COMMON_NAME).unwrap()),
            value: BMPStringAsn1::from(BMPString::from_str(MS_ORGANIZATION_P2P_ACCESS).unwrap()),
        }]),
    };

    Ok(Pku2uNegoReq {
        metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![Pku2uNegoReqMetadata {
            inner: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&inner)?)),
        }])),
        body: ExplicitContextTag1::from(Pku2uNegoBody {
            realm: ExplicitContextTag0::from(Realm::from(IA5String::from_str(WELLKNOWN_REALM).unwrap())),
            sname: ExplicitContextTag1::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_str(SERVICE_NAME).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_str(username).unwrap()),
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

pub fn version_to_cms_version(v: Version) -> CmsVersion {
    match v {
        Version::V1 => CmsVersion::V1,
        Version::V2 => CmsVersion::V2,
        Version::V3 => CmsVersion::V3,
    }
}

pub fn generate_signer_info(p2p_ca_cert: &Certificate) -> SignerInfo {
    SignerInfo {
        version: version_to_cms_version(p2p_ca_cert.tbs_certificate.version.0),
        sid: SignerIdentifier::SubjectKeyIdentifier(ImplicitContextTag0::from(SubjectKeyIdentifier::from(
            p2p_ca_cert.subject_key_identifier().unwrap().to_vec(),
        ))),
        digest_algorithm: DigestAlgorithmIdentifier(
            p2p_ca_cert.tbs_certificate.subject_public_key_info.algorithm.clone(),
        ),
        signed_attrs: Optional::from(Attributes(Asn1SequenceOf::from(vec![]))),
        signature_algorithm: SignatureAlgorithmIdentifier(p2p_ca_cert.signature_algorithm.clone()),
        signature: SignatureValue(OctetStringAsn1::from(p2p_ca_cert.signature_value.0.inner())),
        unsigned_attrs: Optional::from(UnsignedAttributes(vec![])),
    }
}

pub fn generate_client_dh_parameters() -> DhParameters {
    let modulus = vec![
        0, 255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220,
        28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221,
        239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228,
        133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238,
        56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255,
        255, 255, 255, 255, 255, 255, 255,
    ];
    let q = vec![
        127, 255, 255, 255, 255, 255, 255, 255, 228, 135, 237, 81, 16, 180, 97, 26, 98, 99, 49, 69, 192, 110, 14, 104,
        148, 129, 39, 4, 69, 51, 230, 58, 1, 5, 223, 83, 29, 137, 205, 145, 40, 165, 4, 60, 199, 26, 2, 110, 247, 202,
        140, 217, 230, 157, 33, 141, 152, 21, 133, 54, 249, 47, 138, 27, 167, 240, 154, 182, 182, 168, 225, 34, 242,
        66, 218, 187, 49, 47, 63, 99, 122, 38, 33, 116, 211, 27, 246, 181, 133, 255, 174, 91, 122, 3, 91, 246, 247, 28,
        53, 253, 173, 68, 207, 210, 215, 79, 146, 8, 190, 37, 143, 243, 36, 148, 51, 40, 246, 115, 41, 192, 255, 255,
        255, 255, 255, 255, 255, 255,
    ];

    DhParameters {
        base: 2,
        modulus,
        q,
        private_key: todo!(),
        other_public_key: None,
        client_nonce: Some([
            72, 91, 60, 222, 24, 28, 4, 155, 141, 138, 44, 10, 136, 54, 202, 60, 146, 234, 183, 130, 109, 34, 94, 10,
            87, 237, 162, 55, 173, 100, 115, 43,
        ]),
        server_nonce: None,
    }
}

pub fn generate_pa_datas_for_as_req(
    p2p_cert: &Certificate,
    p2p_ca_cert: &Certificate,
    kdc_req_body: &KdcReqBody,
    auth_nonce: u32,
    dh_parameters: &DhParameters,
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

    let sha1_hash = sha1.finalize().to_vec();

    let auth_pack = AuthPack {
        pk_authenticator: ExplicitContextTag0::from(PkAuthenticator {
            cusec: ExplicitContextTag0::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
            ctime: ExplicitContextTag1::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(auth_nonce.to_be_bytes().to_vec())),
            pa_checksum: Optional::from(Some(ExplicitContextTag3::from(OctetStringAsn1::from(sha1_hash)))),
        }),
        client_public_value: Optional::from(Some(ExplicitContextTag1::from(DhReqInfo {
            key_info: DhReqKeyInfo {
                identifier: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(DIFFIE_HELLMAN).unwrap()),
                key_info: DhDomainParameters {
                    p: IntegerAsn1::from(dh_parameters.modulus.clone()),
                    g: IntegerAsn1::from(dh_parameters.base.to_be_bytes().to_vec()),
                    q: IntegerAsn1::from(dh_parameters.q.clone()),
                    j: Optional::from(None),
                    validation_params: Optional::from(None),
                },
            },
            key_value: BitStringAsn1::from(BitString::with_bytes(vec![
                2, 129, 129, 0, 219, 78, 185, 183, 129, 7, 4, 73, 79, 203, 237, 216, 60, 162, 113, 232, 36, 233, 162,
                75, 8, 200, 168, 109, 49, 32, 207, 86, 26, 198, 121, 143, 205, 90, 248, 169, 6, 178, 153, 1, 237, 156,
                2, 145, 162, 150, 218, 232, 144, 183, 193, 58, 7, 27, 217, 215, 160, 30, 69, 15, 211, 28, 18, 216, 145,
                196, 14, 47, 119, 76, 163, 178, 243, 136, 213, 190, 122, 108, 59, 140, 94, 32, 75, 114, 17, 239, 99,
                81, 208, 221, 232, 214, 193, 129, 129, 135, 191, 117, 72, 254, 44, 211, 92, 124, 203, 235, 196, 113, 1,
                123, 74, 139, 101, 121, 212, 210, 119, 162, 26, 230, 153, 254, 123, 68, 151, 135, 52, 29,
            ])),
        }))),
        supported_cms_types: Optional::from(None),
        client_dh_nonce: Optional::from(
            dh_parameters
                .client_nonce
                .as_ref()
                .map(|nonce| ExplicitContextTag3::from(OctetStringAsn1::from(nonce.to_vec()))),
        ),
    };

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![
            AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
        ])),
        content_info: EncapsulatedContentInfo::new(
            ObjectIdentifier::try_from(PKINIT_AUTH_DATA).unwrap(),
            Some(picky_asn1_der::to_vec(&auth_pack)?),
        ),
        certificates: Optional::from(CertificateSet(vec![CertificateChoices::Certificate(Asn1RawDer(
            picky_asn1_der::to_vec(p2p_cert)?,
        ))])),
        crls: None,
        signers_infos: SignersInfos(Asn1SetOf::from(vec![generate_signer_info(p2p_ca_cert)])),
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

pub fn generate_neg<T: Clone>(krb_msg: T, krb5_token_id: [u8; 2]) -> ApplicationTag0<KrbMessage<T>> {
    ApplicationTag0(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(GSS_PKU2U).unwrap()),
        krb5_token_id,
        krb_msg,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn neg_token_init_generation() {
        //
    }
}
