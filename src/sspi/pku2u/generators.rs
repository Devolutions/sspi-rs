use std::convert::TryFrom;
use std::str::FromStr;

use chrono::Utc;
use oid::ObjectIdentifier;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::{BMPString, IA5String};
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BMPStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::EncapsulatedContentInfo;
use picky_asn1_x509::oids::{AT_COMMON_NAME, KERBEROS_V5_PKINIT, NEGOEX, SPNEGO};
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_asn1_x509::signer_info::{
    Attributes, DigestAlgorithmIdentifier, SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo,
    UnsignedAttributes,
};
use picky_asn1_x509::{AlgorithmIdentifier, Certificate, SubjectKeyIdentifier, Version};
use picky_krb::constants::gss_api::{ACCEPT_INCOMPLETE, AS_REQ_TOKEN_ID};
use picky_krb::constants::types::{NT_SRV_INST, PA_PK_AS_REQ};
use picky_krb::data_types::{KerberosStringAsn1, KerberosTime, PaData, PrincipalName, Realm};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg,
};
use picky_krb::messages::{AsReq, KdcReqBody};
use picky_krb::pkinit::{
    AuthPack, PaPkAsReq, PkAuthenticator, Pku2uNegoBody, Pku2uNegoReq, Pku2uNegoReqMetadata, Pku2uValue,
    Pku2uValueInner,
};
use sha1::{Digest, Sha1};

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

pub fn generate_pa_datas_for_as_req(
    p2p_cert: &Certificate,
    p2p_ca_cert: &Certificate,
    kdc_req_body: &KdcReqBody,
    auth_nonce: u32,
    dh_nonce: Option<&[u8; DH_NONCE_LEN]>,
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
        client_public_value: Optional::from(Some(ExplicitContextTag1::from(
            p2p_cert.tbs_certificate.subject_public_key_info.clone(),
        ))),
        supported_cms_types: Optional::from(None),
        client_dh_nonce: Optional::from(
            dh_nonce.map(|nonce| ExplicitContextTag3::from(OctetStringAsn1::from(nonce.to_vec()))),
        ),
    };

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![
            AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
        ])),
        content_info: EncapsulatedContentInfo::new(
            ObjectIdentifier::try_from(KERBEROS_V5_PKINIT).unwrap(),
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

pub fn generate_neg_as_req(as_req: AsReq) -> ApplicationTag0<KrbMessage<AsReq>> {
    ApplicationTag0(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("GSS_PKU2U").unwrap()),
        krb5_token_id: AS_REQ_TOKEN_ID,
        krb_msg: as_req,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn neg_token_init_generation() {
        //
    }
}
