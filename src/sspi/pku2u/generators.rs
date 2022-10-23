use std::convert::TryFrom;
use std::fmt::Debug;
use std::str::FromStr;

use chrono::{Utc, Duration};
use oid::ObjectIdentifier;
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::{BMPString, IA5String};
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BMPStringAsn1, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1,
    ExplicitContextTag2, ExplicitContextTag3, ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1,
    Optional, ExplicitContextTag8, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag10, ExplicitContextTag9, GeneralizedTimeAsn1,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::EncapsulatedContentInfo;
use picky_asn1_x509::oids::{AT_COMMON_NAME, DIFFIE_HELLMAN, GSS_PKU2U, NEGOEX, NTLM_SSP, PKINIT_AUTH_DATA, SPNEGO, PKINIT_DH_KEY_DATA};
use picky_asn1_x509::signed_data::{
    CertificateChoices, CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos,
};
use picky_asn1_x509::signer_info::{
    Attributes, CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber,
    SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo, UnsignedAttributes,
};
use picky_asn1_x509::{
    AlgorithmIdentifier, Attribute, AttributeValues,
    Certificate, ShaVariant,
};
use picky_krb::constants::gss_api::{ACCEPT_INCOMPLETE, AUTHENTICATOR_CHECKSUM_TYPE, ACCEPT_COMPLETE};
use picky_krb::constants::key_usages::{AS_REP_ENC, AP_REP_ENC};
use picky_krb::constants::types::{NT_SRV_INST, PA_PK_AS_REQ, AD_AUTH_DATA_AP_OPTION_TYPE, KERB_AP_OPTIONS_CBT, PA_PK_AS_REP};
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::diffie_hellman::{compute_public_key, generate_private_key};
use picky_krb::data_types::{KerberosStringAsn1, KerberosTime, PaData, PrincipalName, Realm, Authenticator, AuthorizationDataInner, AuthorizationData, AuthenticatorInner, EncryptionKey, Checksum, Ticket, EncryptedData, LastReq, LastReqInner, TicketInner, KerbAdRestrictionEntry, LsapTokenInfoIntegrity, EncApRepPart, EncApRepPartInner};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{KdcReqBody, AsRep, KdcRep, EncAsRepPart, EncKdcRepPart, ApRep, ApRepInner};
use picky_krb::pkinit::{
    AuthPack, DhDomainParameters, DhReqInfo, DhReqKeyInfo, PaPkAsReq, PkAuthenticator, Pku2uNegoBody, Pku2uNegoReq,
    Pku2uNegoReqMetadata, PaPkAsRep, DhRepInfo, KdcDhKeyInfo,
};
use rand::rngs::OsRng;
use rsa::{Hash, PaddingScheme, RsaPrivateKey};
use sha1::{Digest, Sha1};

use super::{DhParameters, Pku2uConfig};
use crate::crypto::compute_md5_channel_bindings_hash;
use crate::kerberos::client::generators::{MAX_MICROSECONDS_IN_SECOND, GenerateAuthenticatorOptions, ChecksumOptions};
use crate::kerberos::SERVICE_NAME;
use crate::{Result, ErrorKind, Error, KERBEROS_VERSION};

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
                    KerberosStringAsn1::from(IA5String::from_str("dest.dataans.com")?),
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

pub fn generate_neg_token_init_s(mech_token: Vec<u8>) -> Result<NegTokenTarg1> {
    Ok(ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(vec![0x0a, 0x01, 0x01])))),
        supported_mech: Optional::from(Some(ExplicitContextTag1::from(MechType::from(ObjectIdentifier::try_from(NEGOEX).unwrap())))),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(mech_token)))),
        mech_list_mic: Optional::from(None),
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

pub fn generate_neg_token_completed(token: Vec<u8>) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    Ok(ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_COMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(token)))),
        mech_list_mic: Optional::from(None),
    }))
}

pub fn generate_signer_info(
    p2p_cert: &Certificate,
    digest: Vec<u8>,
    private_key: &RsaPrivateKey,
) -> Result<SignerInfo> {
    println!("{:x?}", p2p_cert.tbs_certificate.serial_number);
    println!(
        "{:?}",
        picky_asn1_der::to_vec(&p2p_cert.tbs_certificate.serial_number).unwrap()
    );

    let signed_attributes = Asn1SetOf::from(vec![
        Attribute {
            ty: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("1.2.840.113549.1.9.3").unwrap()),
            value: AttributeValues::ContentType(Asn1SetOf::from(vec![ObjectIdentifierAsn1::from(
                ObjectIdentifier::try_from("1.3.6.1.5.2.3.1").unwrap(),
            )])),
        },
        Attribute {
            ty: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("1.2.840.113549.1.9.4").unwrap()),
            value: AttributeValues::MessageDigest(Asn1SetOf::from(vec![OctetStringAsn1::from(digest)])),
        },
    ]);

    let encoded_signed_attributes = picky_asn1_der::to_vec(&signed_attributes)?;

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_signed_attributes);

    let hashed_signed_attributes = sha1.finalize().to_vec();

    let signature = private_key
        .sign(
            PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1)),
            &hashed_signed_attributes,
        )
        .unwrap();

    println!("signature: {} {:?}", signature.len(), signature);

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

/// returns (p, g, q)
pub fn get_default_parameters() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        vec![
            0, 255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52, 196, 198, 98, 139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2, 11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149, 25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53, 109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66, 233, 166, 55, 237, 107, 11, 255, 92, 182, 244, 6, 183, 237, 238, 56, 107, 251, 90, 137, 159, 165, 174, 159, 36, 17, 124, 75, 31, 230, 73, 40, 102, 81, 236, 230, 83, 129, 255, 255, 255, 255, 255, 255, 255, 255
        ],
        vec![2],
        vec![
            127, 255, 255, 255, 255, 255, 255, 255, 228, 135, 237, 81, 16, 180, 97, 26, 98, 99, 49, 69, 192, 110, 14, 104, 148, 129, 39, 4, 69, 51, 230, 58, 1, 5, 223, 83, 29, 137, 205, 145, 40, 165, 4, 60, 199, 26, 2, 110, 247, 202, 140, 217, 230, 157, 33, 141, 152, 21, 133, 54, 249, 47, 138, 27, 167, 240, 154, 182, 182, 168, 225, 34, 242, 66, 218, 187, 49, 47, 63, 99, 122, 38, 33, 116, 211, 27, 246, 181, 133, 255, 174, 91, 122, 3, 91, 246, 247, 28, 53, 253, 173, 68, 207, 210, 215, 79, 146, 8, 190, 37, 143, 243, 36, 148, 51, 40, 246, 115, 41, 192, 255, 255, 255, 255, 255, 255, 255, 255
        ],
    )
}

pub fn generate_server_dh_parameters() -> Result<DhParameters> {
    Ok(DhParameters {
        base: Vec::new(),
        modulus: Vec::new(),
        q: Vec::new(),
        private_key: Vec::new(),
        other_public_key: None,
        server_nonce: Some([
            142, 91, 149, 4, 44, 55, 103, 6, 75, 168, 207, 165, 162, 197, 172, 27, 2, 108, 166, 10, 240, 52, 179, 24,
            56, 73, 137, 103, 160, 81, 236, 230,
        ]),
        client_nonce: None,
    })
}

pub fn generate_client_dh_parameters() -> Result<DhParameters> {
    let (p, g, q) = get_default_parameters();

    let mut rng = OsRng::default();

    let private_key = generate_private_key(&q, &mut rng);

    println!("dh private_key: {:?}", private_key);

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

    let public_value = compute_public_key(&dh_parameters.private_key, &dh_parameters.modulus, &dh_parameters.base);

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
                picky_asn1_der::to_vec(&IntegerAsn1::from(
                    public_value,
                ))?
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

fn conv(s: &str) -> Vec<u8> {
    let mut d = Vec::new();

    for b in s.bytes() {
        d.push(b);
        d.push(0x00);
    }

    d
}

pub fn generate_authenticator(options: GenerateAuthenticatorOptions) -> Result<Authenticator> {
    let GenerateAuthenticatorOptions {
        kdc_rep,
        seq_num,
        sub_key,
        checksum,
        channel_bindings,
        extension,
    } = options;

    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    let lsap_token = LsapTokenInfoIntegrity {
        flags: 1,
        token_il: 0x00002000,
        machine_id: [92, 95, 64, 72, 191, 160, 228, 23, 98, 35, 78, 151, 207, 227, 96, 126, 97, 180, 15, 98, 127, 211, 90, 177, 119, 132, 45, 113, 206, 90, 169, 124],
    };

    let mut encoded_lsap_token = Vec::with_capacity(40);
    lsap_token.encode(&mut encoded_lsap_token)?;

    let restriction_entry = KerbAdRestrictionEntry {
        restriction_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
        restriction: ExplicitContextTag1::from(OctetStringAsn1::from(encoded_lsap_token)),
    };

    let authorization_data = Optional::from(Some(ExplicitContextTag8::from(AuthorizationData::from(vec![
        AuthorizationDataInner {
            ad_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x01])),
            ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![AuthorizationDataInner {
                    ad_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x00, 0x8d])),
                    ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(
                        picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![restriction_entry]))?
                    )),
                }]))?
            )),
        },
    ]))));

    let cksum = if let Some(ChecksumOptions {
        checksum_type,
        mut checksum_value,
    }) = checksum
    {
        if checksum_type == AUTHENTICATOR_CHECKSUM_TYPE && channel_bindings.is_some() {
            if checksum_value.len() < 20 {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    format!(
                        "Invalid authenticator checksum length: expected >= 20 but got {}. ",
                        checksum_value.len()
                    ),
                ));
            }
            // [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
            // 4..19 - Channel binding information (19 inclusive).
            checksum_value[4..20]
                .copy_from_slice(&compute_md5_channel_bindings_hash(channel_bindings.as_ref().unwrap()));
        }
        checksum_value = vec![16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 64, 0, 0, 0, 0, 0, 2, 0, 0, 0, 27, 48, 25, 161, 23, 48, 21, 160, 3, 2, 1, 16, 161, 14, 4, 12];
        checksum_value.extend_from_slice(&extension);
        println!("checksum_value: {:?} {:?}", checksum_value, checksum_value.len());
        Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(checksum_type)),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum_value)),
        })))
    } else {
        Optional::from(None)
    };

    Ok(Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum,
        // cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(vec![0x08])),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(sub_key.map(|sub_key| {
            ExplicitContextTag6::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(sub_key)),
            })
        })),
        seq_number: Optional::from(seq_num.map(|seq_num| {
            ExplicitContextTag7::from(IntegerAsn1::from_bytes_be_unsigned(
                // seq_num.to_be_bytes().to_vec()
                vec![0x1e, 0xcb, 0x01, 0x27]
                // vec![0x00]
            ))
        })),
        authorization_data,
    }))
}

pub fn generate_pa_datas_for_as_rep(
    p2p_cert: &Certificate,
    dh_server_nonce: &[u8],
    dh_public_key: &[u8],
    private_key: &RsaPrivateKey,
) -> Result<Vec<PaData>> {
    let kdc_dh_key_info = KdcDhKeyInfo {
        subject_public_key: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_bytes(
            picky_asn1_der::to_vec(&IntegerAsn1::from(dh_public_key.to_vec()))?
        ))),
        nonce: ExplicitContextTag1::from(IntegerAsn1::from(vec![0])),
        dh_key_expiration: Optional::from(None),
    };

    let encoded_auth_pack = picky_asn1_der::to_vec(&kdc_dh_key_info)?;

    let mut sha1 = Sha1::new();
    sha1.update(&encoded_auth_pack);

    let digest = sha1.finalize().to_vec();
    println!("digest: {:?}", digest);

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: DigestAlgorithmIdentifiers(Asn1SetOf::from(vec![AlgorithmIdentifier::new_sha1()])),
        content_info: EncapsulatedContentInfo::new(
            ObjectIdentifier::try_from(PKINIT_DH_KEY_DATA).unwrap(),
            Some(encoded_auth_pack),
        ),
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

    let pa_pk_as_rep = PaPkAsRep::DhInfo(ExplicitContextTag0::from(DhRepInfo {
        dh_signed_data: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&signed_data)?)),
        server_dh_nonce: Optional::from(Some(ExplicitContextTag1::from(OctetStringAsn1::from(dh_server_nonce.to_vec())))),
    }));

    Ok(vec![PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PK_AS_REP.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&pa_pk_as_rep)?)),
    }])
}

pub fn get_bad_ticket() -> Ticket {
    ApplicationTag::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
        realm: ExplicitContextTag1::from(KerberosStringAsn1::from(IA5String::from_str("WELLKNOWN:PKU2U").unwrap())),
        sname: ExplicitContextTag2::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_str("TERMSRV").unwrap()),
                // KerberosStringAsn1::from(IA5String::from_str("192.168.0.117").unwrap()),
                KerberosStringAsn1::from(IA5String::from_str("dest.dataans.com").unwrap()),
            ])),
        }),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![211, 68, 200, 157, 66, 82, 128, 82, 220, 246, 214, 194, 27, 126, 129, 98, 58, 221, 245, 200, 112, 218, 4, 68, 97, 0, 222, 203, 69, 31, 41, 86, 106, 196, 62, 240, 167, 246, 248, 193, 104, 59, 22, 204, 24, 99, 193, 25, 94, 201, 86, 198, 11, 100, 155, 58, 22, 14, 173, 195, 112, 223, 23, 161, 48, 80, 40, 189, 52, 81, 213, 229, 176, 161, 14, 85, 128, 46, 151, 112, 93, 183, 164, 240, 98, 133, 6, 224, 79, 41, 127, 15, 65, 143, 127, 154, 182, 50, 91, 134, 38, 116, 244, 228, 187, 205, 75, 146, 35, 228, 38, 136, 152, 24, 116, 41, 119, 147, 20, 242, 111, 224, 9, 236, 174, 193, 254, 96, 89, 84, 214, 95, 130, 60, 213, 229, 73, 173, 34, 144, 149, 15, 58, 63, 163, 199, 138, 204, 45, 163, 152, 36, 75, 26, 241, 237, 88, 241, 124, 80, 154, 114, 99, 20, 24, 82, 105, 219, 61, 226, 81, 196, 171, 182, 111, 160, 207, 97, 246, 217, 128, 35, 79, 72, 79, 30, 46, 3, 243, 180, 0, 42, 153, 219, 218, 96, 13, 16, 98, 61, 38, 4, 76, 63, 77, 242, 129, 16, 71, 39, 250, 84, 42, 179, 188, 5, 3, 137, 127, 203, 110, 37, 135, 246, 251, 26, 154, 6, 116, 200, 240, 199, 205, 105, 182, 201, 75, 63, 71, 29, 111, 140, 30, 24, 78, 47, 38, 97, 45, 24, 130, 141, 22, 103, 199, 110, 160, 163, 11, 147, 127, 90, 93, 135, 202, 191, 7, 90, 109, 66, 127, 148, 61, 219, 191, 178, 203, 162, 218, 241, 235, 89, 10, 138, 101, 44, 70, 26, 64, 177, 170, 253, 124, 192, 185, 192, 148, 172, 109, 58, 207, 7, 89, 130, 53, 73, 103, 223, 28, 228, 57, 199, 168, 136, 44, 27, 202, 10, 73, 49, 137, 246, 98, 164, 197, 127, 230, 147, 168, 210, 23, 17, 63, 106, 157, 113, 20, 7, 146, 174, 79, 242, 241, 22, 6, 134, 1, 225, 222, 124, 254, 22, 139, 72, 156, 224, 73, 101, 179, 168, 34, 245, 221, 122, 35, 61, 115, 35, 96, 19, 199, 149, 176, 54, 147, 108, 225, 73, 149, 204, 100, 1, 177, 205, 139, 138, 134, 133, 225, 119, 111, 84, 104, 167, 146, 163, 254, 56, 86, 233, 162, 4, 145, 161, 228, 122, 201, 16, 92, 171, 164, 237, 146, 210, 143, 127, 233, 184, 148, 110, 238, 253, 103, 98, 0, 96, 96, 12, 113, 168, 99, 137, 37, 124, 76, 108, 188, 200, 82, 199, 169, 192, 229, 34, 232, 198, 107, 217, 54, 60, 152, 198, 234, 110, 87, 50, 200, 237, 67, 226, 214, 208, 178, 100, 118, 240, 242, 212, 25, 149, 80, 2, 202, 143, 52, 140, 235, 222, 211, 54, 169, 228, 164, 136, 35, 62, 16, 53, 63, 55, 58, 144, 11, 32, 68, 79, 6, 35, 178, 147, 228, 21, 103, 27, 111, 22, 103, 77, 181, 230, 252, 90, 156, 47, 75, 171, 246, 217, 173, 55, 94, 241, 157, 143, 231, 92, 90, 114, 50, 210, 97, 152, 254, 49, 135, 116, 248, 220, 42, 5, 236, 41, 44, 112, 134, 29, 180, 186, 250, 220, 152, 27, 227, 28, 61, 194, 125, 162, 254, 168, 51, 59, 43, 134, 56, 202, 226, 51, 207, 243, 88, 169, 114, 101, 83, 97, 201, 39, 215, 123, 9, 6, 182, 125, 167, 189, 57, 221, 73, 28, 0, 198, 243, 75, 115, 232, 83, 119, 145, 193, 152, 25, 43, 116, 110, 193, 96, 178, 156, 156, 189, 51, 50, 231, 80, 236, 201, 236, 151, 211, 149, 56, 141, 37, 196, 209, 178, 94, 62, 151, 129, 214, 215, 227, 216, 92, 87, 131, 105, 101, 186, 99, 18, 168, 83, 55, 190, 108, 132, 217, 179, 77, 43, 189, 230, 43, 208, 213, 46, 46, 239, 40, 166, 93, 149, 65, 92, 109, 213, 99, 202, 249, 197, 34, 84, 171, 2, 75, 47, 134, 22, 114, 10, 251, 55, 98, 90, 163, 225, 69, 1, 142, 86, 189, 30, 248, 31, 11, 117, 3, 145, 87, 65, 247, 185, 59, 28, 13, 159, 197, 134, 36, 142, 48, 187, 210, 221, 225, 38, 89, 7, 23, 58, 191, 2, 217, 182, 175, 144, 9, 229, 218, 113, 88, 191, 30, 249, 234, 43, 143, 202, 105, 58, 79, 57, 215, 15, 56, 48, 175, 33, 100, 229, 96, 226, 104, 200, 255, 105, 151, 106, 248, 228, 23, 209, 34, 252, 24, 136, 156, 194, 117, 199, 48, 221, 251, 98, 15, 248, 61, 136, 110, 151, 173, 55, 134, 246, 166, 72, 254, 73, 181, 43, 71, 132, 132, 120, 244, 151, 161, 36, 52, 218, 247, 227, 218, 110, 10, 172, 41, 139, 88, 227, 175, 244, 200, 112, 24, 20, 122, 23, 168, 77, 16, 42, 74, 119, 188, 130, 198, 132, 102, 45, 152, 131, 201, 200, 49, 243, 171, 128])),
        }),
    })
}

pub fn generate_as_rep(pa_datas: Vec<PaData>, session_key: &[u8], new_key: Vec<u8>) -> Result<AsRep> {
    let lt_req = Utc::now()
        .checked_sub_signed(Duration::hours(1))
        .unwrap();

    let now = Utc::now();
    let end_time = now.clone().checked_add_signed(Duration::hours(1)).unwrap();

    let enc_part = EncAsRepPart::from(EncKdcRepPart {
        key: ExplicitContextTag0::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(new_key)),
        }),
        last_req: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
            LastReqInner {
                lr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
                lr_value: ExplicitContextTag1::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(lt_req))),
            }
        ])),
        nonce: ExplicitContextTag2::from(IntegerAsn1::from(vec![0])),
        key_expiration: Optional::from(None),
        flags: ExplicitContextTag4::from(BitStringAsn1::from(BitString::with_bytes(vec![0, 64, 224, 0, 0]))),
        auth_time: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(now.clone()))),
        start_time: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(now))))),
        end_time: ExplicitContextTag7::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(end_time.clone()))),
        renew_till: Optional::from(Some(ExplicitContextTag8::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(end_time))))),
        srealm: ExplicitContextTag9::from(
            KerberosStringAsn1::from(IA5String::from_str("WELLKNOWN:PKU2U").unwrap()),
        ),
        sname: ExplicitContextTag10::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_str("TERMSRV").unwrap()),
                // KerberosStringAsn1::from(IA5String::from_str("192.168.0.117").unwrap()),
                KerberosStringAsn1::from(IA5String::from_str("dest.dataans.com").unwrap()),
            ])),
        }),
        caadr: Optional::from(None),
        encrypted_pa_data: Optional::from(None),
    });
    let enc_encoded = picky_asn1_der::to_vec(&enc_part)?;

    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let enc_encrypted = cipher.encrypt(&session_key, AS_REP_ENC, &enc_encoded)?;

    Ok(AsRep::from(KdcRep {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![11])),
        padata: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(pa_datas)))),
        crealm: ExplicitContextTag3::from(KerberosStringAsn1::from(IA5String::from_str(WELLKNOWN_REALM).unwrap())),
        cname: ExplicitContextTag4::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x80])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_str("AzureAD\\s7@dataans.com").unwrap()),
            ])),
        }),
        ticket: ExplicitContextTag5::from(get_bad_ticket()),
        enc_part: ExplicitContextTag6::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x12])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(enc_encrypted)),
        }),
    }))
}

pub fn generate_ap_rep(session_key: &[u8], new_key: &[u8]) -> ApRep {
    let now = Utc::now();

    let ap_rep_enc_part = EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(now))),
        cusec: ExplicitContextTag1::from(IntegerAsn1::from(vec![8])),
        subkey: Optional::from(Some(ExplicitContextTag2::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(new_key.to_vec())),
        }))),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(vec![49, 95, 171, 251])))),
    });
    let encoded_ap_rep_enc_part = picky_asn1_der::to_vec(&ap_rep_enc_part).unwrap();
    println!("encoded_ap_rep_enc_part: {:?}", encoded_ap_rep_enc_part);
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let cipher_data = cipher.encrypt(session_key, AP_REP_ENC, &encoded_ap_rep_enc_part).unwrap();

    ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![15])),
        enc_part: ExplicitContextTag2::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher_data)),
        }),
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
        let data = [
            48, 22, 6, 9, 42, 134, 72, 134, 247, 13, 1, 9, 3, 49, 9, 6, 7, 43, 6, 1, 5, 2, 3, 1, 48, 35, 6, 9, 42, 134,
            72, 134, 247, 13, 1, 9, 4, 49, 22, 4, 20, 37, 144, 68, 78, 210, 60, 230, 236, 125, 249, 8, 246, 201, 77,
            20, 197, 108, 52, 75, 76,
        ];

        let mut sha1 = Sha1::new();

        sha1.update(&data);

        let hash = sha1.finalize().to_vec();

        println!("hash: {:?}", hash);

        // assert_eq!(
        //     &[214, 215, 210, 143, 189, 21, 220, 123, 16, 202, 62, 239, 143, 239, 72, 75, 129, 19, 192, 25],
        //     hash.as_slice(),
        // );
    }
}
