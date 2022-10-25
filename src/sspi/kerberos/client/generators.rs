use std::convert::TryFrom;
use std::str::FromStr;

use chrono::{Duration, Utc};
use md5::{Digest, Md5};
use oid::ObjectIdentifier;
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag11, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7,
    ExplicitContextTag8, ExplicitContextTag9, GeneralizedTimeAsn1, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1,
    Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::oids::{KRB5, KRB5_USER_TO_USER, MS_KRB5, SPNEGO};
use picky_krb::constants::gss_api::{
    ACCEPT_COMPLETE, ACCEPT_INCOMPLETE, AP_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE, TGT_REQ_TOKEN_ID,
};
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR};
use picky_krb::constants::types::{
    AD_AUTH_DATA_AP_OPTION_TYPE, AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, KERB_AP_OPTIONS_CBT, KRB_PRIV, NET_BIOS_ADDR_TYPE,
    NT_ENTERPRISE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP, PA_ENC_TIMESTAMP_KEY_USAGE, PA_PAC_OPTIONS_TYPE,
    PA_PAC_REQUEST_TYPE, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE, TGT_REQ_MSG_TYPE,
};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner, Checksum, EncKrbPrivPart,
    EncKrbPrivPartInner, EncryptedData, EncryptionKey, HostAddress, KerbPaPacRequest, KerberosFlags,
    KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc, PaPacOptions, PrincipalName, Realm, Ticket,
};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{
    ApMessage, ApReq, ApReqInner, AsReq, KdcRep, KdcReq, KdcReqBody, KrbPriv, KrbPrivInner, KrbPrivMessage, TgsReq,
    TgtReq,
};
use rand::rngs::OsRng;
use rand::Rng;

use crate::crypto::compute_md5_channel_bindings_hash;
use crate::kerberos::DEFAULT_ENCRYPTION_TYPE;
use crate::sspi::channel_bindings::ChannelBindings;
use crate::sspi::kerberos::{EncryptionParams, KERBEROS_VERSION, SERVICE_NAME};
use crate::sspi::Result;
use crate::{Error, ErrorKind};

const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;
pub const MAX_MICROSECONDS_IN_SECOND: u32 = 999_999;
const MD5_CHECKSUM_TYPE: [u8; 1] = [0x07];

pub const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x10];
const DEFAULT_TGS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x08];
const DEFAULT_PA_PAC_OPTIONS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

// AP-REQ toggled options:
// * mutual required
// * use session key
// other options are disabled
pub const DEFAULT_AP_REQ_OPTIONS: [u8; 4] = [0x60, 0x00, 0x00, 0x00];
pub const EMPTY_AP_REQ_OPTIONS: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
pub const AUTHENTICATOR_DEFAULT_CHECKSUM: [u8; 24] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x3E, 0x00, 0x00, 0x00,
];

// [MS-KILE] 3.3.5.6.1 Client Principal Lookup
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6435d3fb-8cf6-4df5-a156-1277690ed59c
pub fn get_client_principal_name_type(username: &str, _domain: &str) -> u8 {
    if username.contains('@') {
        NT_ENTERPRISE
    } else {
        NT_PRINCIPAL
    }
}

pub fn get_client_principal_realm(username: &str, domain: &str) -> String {
    if domain.is_empty() {
        if let Some((_left, right)) = username.split_once('@') {
            return right.to_string();
        }
    }
    domain.to_string()
}

pub struct GenerateAsPaDataOptions<'a> {
    pub password: &'a str,
    pub salt: Vec<u8>,
    pub enc_params: EncryptionParams,
    pub with_pre_auth: bool,
}

pub fn generate_pa_datas_for_as_req(options: &GenerateAsPaDataOptions) -> Result<Vec<PaData>> {
    let GenerateAsPaDataOptions {
        password,
        salt,
        enc_params,
        with_pre_auth,
    } = options;

    let mut pa_datas = if *with_pre_auth {
        let current_date = Utc::now();
        let mut microseconds = current_date.timestamp_subsec_micros();
        if microseconds > MAX_MICROSECONDS_IN_SECOND {
            microseconds = MAX_MICROSECONDS_IN_SECOND;
        }

        let timestamp = PaEncTsEnc {
            patimestamp: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            pausec: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(
                microseconds.to_be_bytes().to_vec(),
            )))),
        };
        let timestamp_bytes = picky_asn1_der::to_vec(&timestamp)?;

        let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
        let cipher = encryption_type.cipher();
        let key = cipher.generate_key_from_password(password.as_bytes(), salt)?;
        let encrypted_timestamp = cipher.encrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &timestamp_bytes)?;

        vec![PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_timestamp)),
            })?)),
        }]
    } else {
        Vec::new()
    };

    pa_datas.push(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&KerbPaPacRequest {
            include_pac: ExplicitContextTag0::from(true),
        })?)),
    });

    Ok(pa_datas)
}

pub struct GenerateAsReqOptions<'a> {
    pub realm: &'a str,
    pub username: &'a str,
    pub cname_type: u8,
    pub snames: &'a [&'a str],
}

pub fn generate_as_req_kdc_body(options: &GenerateAsReqOptions) -> Result<KdcReqBody> {
    let GenerateAsReqOptions {
        realm,
        username,
        cname_type,
        snames,
    } = options;

    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let address = Some(ExplicitContextTag9::from(Asn1SequenceOf::from(vec![HostAddress {
        addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
        // address: ExplicitContextTag1::from(OctetStringAsn1::from(whoami::hostname().as_bytes().to_vec())),
        address: ExplicitContextTag1::from(OctetStringAsn1::from("DESKTOP-8F33RFH\x20".as_bytes().to_vec())),
    }])));

    let mut service_names = Vec::with_capacity(snames.len());
    for sname in *snames {
        service_names.push(KerberosStringAsn1::from(IA5String::from_string((*sname).to_owned())?));
    }

    Ok(KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            DEFAULT_AS_REQ_OPTIONS.to_vec(),
        ))),
        cname: Optional::from(Some(ExplicitContextTag1::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![*cname_type])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                IA5String::from_string((*username).into())?,
            )])),
        }))),
        realm: ExplicitContextTag2::from(Realm::from(IA5String::from_string((*realm).into())?)),
        sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(service_names)),
        }))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
        rtime: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
            GeneralizedTime::from(expiration_date),
        )))),
        // nonce: ExplicitContextTag7::from(IntegerAsn1::from(OsRng::default().gen::<[u8; NONCE_LEN]>().to_vec())),
        // we don't need a nonce in pku2u
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(vec![0])),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()]),
            IntegerAsn1::from(vec![CipherSuite::Aes128CtsHmacSha196.into()]),
            IntegerAsn1::from(vec![0x17]),
            IntegerAsn1::from(vec![0x18]),
            IntegerAsn1::from(vec![0xff, 0x79]),
        ])),
        addresses: Optional::from(address),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    })
}

pub fn generate_as_req(pa_datas: &Vec<PaData>, kdc_req_body: KdcReqBody) -> AsReq {
    AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(pa_datas.clone())))),
        req_body: ExplicitContextTag4::from(kdc_req_body),
    })
}

pub fn generate_tgs_req(
    realm: &str,
    service_principal: &str,
    session_key: &[u8],
    ticket: Ticket,
    mut authenticator: &mut Authenticator,
    additional_tickets: Option<Vec<Ticket>>,
    enc_params: &EncryptionParams,
) -> Result<TgsReq> {
    let divider = service_principal.find('/').ok_or_else(|| Error {
        error_type: ErrorKind::InvalidParameter,
        description: "Invalid service principal name: missing '/'".into(),
    })?;

    if divider == 0 || divider == service_principal.len() - 1 {
        return Err(Error {
            error_type: ErrorKind::InvalidParameter,
            description: "Invalid service principal name".into(),
        });
    }

    let service_name = &service_principal[0..divider];
    // `divider + 1` - do not include '/' char
    let service_principal_name = &service_principal[(divider + 1)..];

    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let req_body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            DEFAULT_TGS_REQ_OPTIONS.to_vec(),
        ))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(Realm::from(IA5String::from_str(realm)?)),
        sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_string(service_name.into())?),
                KerberosStringAsn1::from(IA5String::from_string(service_principal_name.into())?),
            ])),
        }))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(OsRng::default().gen::<[u8; NONCE_LEN]>().to_vec())),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()]),
            IntegerAsn1::from(vec![CipherSuite::Aes128CtsHmacSha196.into()]),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(
            additional_tickets.map(|tickets| ExplicitContextTag11::from(Asn1SequenceOf::from(tickets))),
        ),
    };

    let mut md5 = Md5::new();
    md5.update(&picky_asn1_der::to_vec(&req_body)?);
    let checksum = md5.finalize();

    authenticator.0.cksum = Optional::from(Some(ExplicitContextTag3::from(Checksum {
        cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(MD5_CHECKSUM_TYPE.to_vec())),
        checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum.to_vec())),
    })));

    let pa_tgs_req =
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_TGS_REQ_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                &generate_tgs_ap_req(ticket, session_key, authenticator, enc_params)?,
            )?)),
        };

    let pa_pac_options = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_OPTIONS_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&PaPacOptions {
            flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
                DEFAULT_PA_PAC_OPTIONS.to_vec(),
            ))),
        })?)),
    };

    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_tgs_req,
            pa_pac_options,
        ])))),
        req_body: ExplicitContextTag4::from(req_body),
    }))
}

pub struct ChecksumOptions {
    pub checksum_type: Vec<u8>,
    pub checksum_value: Vec<u8>,
}

pub struct AuthenticatorChecksumExtension {
    pub extension_type: u32,
    pub extension_value: Vec<u8>,
}

pub struct GenerateAuthenticatorOptions<'a> {
    pub kdc_rep: &'a KdcRep,
    pub seq_num: Option<u32>,
    pub sub_key: Option<Vec<u8>>,
    pub checksum: Option<ChecksumOptions>,
    pub channel_bindings: Option<&'a ChannelBindings>,
    pub extensions: Vec<AuthenticatorChecksumExtension>,
}

pub fn generate_authenticator(options: GenerateAuthenticatorOptions) -> Result<Authenticator> {
    let GenerateAuthenticatorOptions {
        kdc_rep,
        seq_num,
        sub_key,
        checksum,
        channel_bindings,
        ..
    } = options;

    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    let authorization_data = Optional::from(channel_bindings.as_ref().map(|_| {
        ExplicitContextTag8::from(AuthorizationData::from(vec![AuthorizationDataInner {
            ad_type: ExplicitContextTag0::from(IntegerAsn1::from(AD_AUTH_DATA_AP_OPTION_TYPE.to_vec())),
            ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(KERB_AP_OPTIONS_CBT.to_vec())),
        }]))
    }));

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
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(sub_key.map(|sub_key| {
            ExplicitContextTag6::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(sub_key)),
            })
        })),
        seq_number: Optional::from(seq_num.map(|seq_num| {
            ExplicitContextTag7::from(IntegerAsn1::from_bytes_be_unsigned(seq_num.to_be_bytes().to_vec()))
        })),
        authorization_data,
    }))
}

pub fn generate_tgs_ap_req(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &picky_asn1_der::to_vec(&authenticator)?,
    )?;

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![
            // do not need any options when ap_req uses in tgs_req pa_data
            0x00, 0x00, 0x00, 0x00,
        ]))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    }))
}

pub fn generate_ap_req(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
    options: &[u8; 4],
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encoded_authenticator = picky_asn1_der::to_vec(&authenticator)?;
    println!("encoded authenticator: {:?} {}", encoded_authenticator, encoded_authenticator.len());

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        AP_REQ_AUTHENTICATOR,
        &encoded_authenticator,
    )?;
    // let encrypted_authenticator = vec![80, 58, 178, 30, 181, 48, 100, 50, 91, 8, 248, 83, 53, 188, 200, 102, 243, 158, 83, 177, 114, 25, 52, 239, 62, 75, 30, 27, 36, 28, 89, 25, 245, 73, 139, 74, 148, 218, 247, 99, 184, 143, 51, 70, 243, 20, 101, 219, 128, 55, 188, 223, 241, 26, 161, 134, 42, 224, 42, 71, 37, 6, 8, 126, 244, 71, 108, 57, 43, 198, 18, 79, 134, 236, 3, 44, 47, 126, 8, 31, 138, 167, 110, 190, 74, 2, 67, 240, 102, 227, 87, 148, 113, 230, 206, 156, 133, 116, 179, 151, 234, 27, 46, 3, 156, 89, 138, 49, 9, 191, 81, 78, 20, 229, 204, 148, 29, 246, 108, 161, 126, 173, 237, 116, 50, 189, 133, 89, 161, 156, 144, 228, 215, 254, 152, 133, 240, 154, 17, 242, 0, 5, 77, 249, 61, 171, 226, 114, 6, 220, 162, 247, 108, 14, 249, 30, 46, 81, 226, 239, 2, 131, 64, 220, 63, 44, 119, 17, 55, 197, 60, 83, 218, 165, 66, 185, 96, 154, 144, 37, 155, 243, 48, 104, 170, 28, 198, 61, 210, 91, 110, 19, 32, 7, 211, 1, 29, 40, 222, 231, 246, 102, 131, 90, 174, 60, 104, 87, 185, 216, 160, 250, 147, 206, 185, 140, 222, 162, 79, 249, 249, 206, 171, 15, 181, 200, 161, 10, 82, 52, 253, 242, 14, 85, 96, 198, 20, 105, 241, 1, 231, 132, 92, 240, 125, 25, 70, 159, 183, 181, 232, 135, 144, 112, 177, 168, 192, 205, 8, 123, 94, 139, 75, 12, 182, 20, 197, 235, 109, 41, 254, 14, 109, 118, 84, 178, 27, 134, 164, 121, 81, 126, 167, 5, 61, 223, 187, 149, 210, 146, 44, 96, 144, 224, 239, 55, 28, 247, 29, 159, 36, 235, 107, 213, 24, 79, 212, 193, 139, 187, 35, 157, 160, 135, 102, 181, 156, 123, 23, 203, 70, 184, 59, 20, 67, 253, 105, 147, 213, 54];

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(options.to_vec()))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    }))
}

// returns supported authentication types
pub fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![
        MechType::from(ObjectIdentifier::try_from(MS_KRB5).unwrap()),
        MechType::from(ObjectIdentifier::try_from(KRB5).unwrap()),
    ])
}

pub fn generate_neg_token_init(username: &str) -> Result<ApplicationTag0<GssApiNegInit>> {
    let krb5_neg_token_init: ApplicationTag<_, 0> = ApplicationTag::from(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(KRB5_USER_TO_USER).unwrap()),
        krb5_token_id: TGT_REQ_TOKEN_ID,
        krb_msg: TgtReq {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGT_REQ_MSG_TYPE])),
            server_name: ExplicitContextTag2::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(SERVICE_NAME.into())?),
                    KerberosStringAsn1::from(IA5String::from_string(username.into())?),
                ])),
            }),
        },
    });

    Ok(ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(SPNEGO).unwrap()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(get_mech_list()))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&krb5_neg_token_init)?,
            )))),
            mech_list_mic: Optional::from(None),
        }),
    }))
}

pub fn generate_neg_ap_req(ap_req: ApReq) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    let krb_blob: ApplicationTag<_, 0> = ApplicationTag(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(KRB5_USER_TO_USER).unwrap()),
        krb5_token_id: AP_REQ_TOKEN_ID,
        krb_msg: ap_req,
    });

    Ok(ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&krb_blob)?,
        )))),
        mech_list_mic: Optional::from(None),
    }))
}

pub fn generate_final_neg_token_targ(mech_list_mic: Option<Vec<u8>>) -> NegTokenTarg1 {
    NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_COMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(None),
        mech_list_mic: Optional::from(mech_list_mic.map(|v| ExplicitContextTag3::from(OctetStringAsn1::from(v)))),
    })
}

pub fn generate_krb_priv_request(
    ticket: Ticket,
    session_key: &[u8],
    new_password: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
    seq_num: u32,
) -> Result<KrbPrivMessage> {
    let ap_req = generate_ap_req(ticket, session_key, authenticator, enc_params, &EMPTY_AP_REQ_OPTIONS)?;

    let enc_part = EncKrbPrivPart::from(EncKrbPrivPartInner {
        user_data: ExplicitContextTag0::from(OctetStringAsn1::from(new_password.to_vec())),
        timestamp: Optional::from(None),
        usec: Optional::from(None),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from_bytes_be_unsigned(
            seq_num.to_be_bytes().to_vec(),
        )))),
        s_address: ExplicitContextTag4::from(HostAddress {
            addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
            address: ExplicitContextTag1::from(OctetStringAsn1::from(whoami::hostname().as_bytes().to_vec())),
        }),
        r_address: Optional::from(None),
    });

    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let enc_part = cipher.encrypt(
        &authenticator.0.subkey.0.as_ref().unwrap().key_value.0,
        13,
        &picky_asn1_der::to_vec(&enc_part)?,
    )?;

    let krb_priv = KrbPriv::from(KrbPrivInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![KRB_PRIV])),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(enc_part)),
        }),
    });

    Ok(KrbPrivMessage {
        ap_message: ApMessage::ApReq(ap_req),
        krb_priv,
    })
}
