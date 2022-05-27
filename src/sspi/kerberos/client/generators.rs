use std::convert::TryFrom;
use std::str::FromStr;

use chrono::{Duration, Utc};
use kerberos_constants::key_usages::{KEY_USAGE_AP_REQ_AUTHEN, KEY_USAGE_TGS_REQ_AUTHEN};
use kerberos_crypto::new_kerberos_cipher;
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
use picky_krb::constants::gss_api::{ACCEPT_COMPLETE, ACCEPT_INCOMPLETE, AP_REQ_TOKEN_ID, TGT_REQ_TOKEN_ID};
use picky_krb::constants::types::{
    AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, NET_BIOS_ADDR_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP,
    PA_ENC_TIMESTAMP_KEY_USAGE, PA_PAC_OPTIONS_TYPE, PA_PAC_REQUEST_TYPE, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE,
    TGT_REQ_MSG_TYPE,
};
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, Checksum, EncryptedData, EncryptionKey, HostAddress,
    KerbPaPacRequest, KerberosFlags, KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc, PaPacOptions, PrincipalName,
    Realm, Ticket,
};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{ApReq, ApReqInner, AsReq, KdcRep, KdcReq, KdcReqBody, TgsReq, TgtReq};
use rand::rngs::OsRng;
use rand::Rng;

use super::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96};
use crate::sspi::kerberos::{EncryptionParams, KERBEROS_VERSION, SERVICE_NAME, TGT_SERVICE_NAME};
use crate::sspi::Result;
use crate::{Error, ErrorKind};

const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;
const MAX_MICROSECONDS_IN_SECOND: u32 = 999_999;
const MD5_CHECSUM_TYPE: [u8; 1] = [0x07];

const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x10];
const DEFAULT_TGS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x08];
const DEFAULT_PA_PAC_OPTIONS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

// AP-REQ toggled options:
// * mutual required
// * use session key
// other options are disabled
const DEFAULT_AP_REQ_OPTIONS: [u8; 4] = [0x60, 0x00, 0x00, 0x00];

pub fn generate_as_req_without_pre_auth(username: &str, realm: &str) -> Result<AsReq> {
    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let pa_pac_request = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&KerbPaPacRequest {
            include_pac: ExplicitContextTag0::from(true),
        })?)),
    };

    let address = sys_info::hostname().ok().map(|hostname| {
        ExplicitContextTag9::from(Asn1SequenceOf::from(vec![HostAddress {
            addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
            address: ExplicitContextTag1::from(OctetStringAsn1::from(hostname.as_bytes().to_vec())),
        }]))
    });

    Ok(AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_pac_request,
        ])))),
        req_body: ExplicitContextTag4::from(KdcReqBody {
            kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
                DEFAULT_AS_REQ_OPTIONS.to_vec(),
            ))),
            cname: Optional::from(Some(ExplicitContextTag1::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_PRINCIPAL])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                    IA5String::from_string(username.into())?,
                )])),
            }))),
            realm: ExplicitContextTag2::from(Realm::from(IA5String::from_string(realm.into())?)),
            sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(TGT_SERVICE_NAME.into())?),
                    KerberosStringAsn1::from(IA5String::from_string(realm.into())?),
                ])),
            }))),
            from: Optional::from(None),
            till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
            rtime: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
                GeneralizedTime::from(expiration_date),
            )))),
            nonce: ExplicitContextTag7::from(IntegerAsn1::from(OsRng::new()?.gen::<[u8; NONCE_LEN]>().to_vec())),
            etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
                IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8]),
                IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96 as u8]),
            ])),
            addresses: Optional::from(address),
            enc_authorization_data: Optional::from(None),
            additional_tickets: Optional::from(None),
        }),
    }))
}

pub fn generate_as_req(
    username: &str,
    salt: &[u8],
    password: &str,
    realm: &str,
    enc_params: &EncryptionParams,
) -> Result<AsReq> {
    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

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

    let cipher = new_kerberos_cipher(enc_params.encryption_type.unwrap_or(AES256_CTS_HMAC_SHA1_96))?;
    let key = cipher.generate_key_from_string(password, salt);

    let encrypted_timestamp = cipher.encrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &timestamp_bytes);

    let pa_enc_timestamp = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_timestamp)),
        })?)),
    };

    let pa_pac_request = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&KerbPaPacRequest {
            include_pac: ExplicitContextTag0::from(true),
        })?)),
    };

    let address = sys_info::hostname().ok().map(|hostname| {
        ExplicitContextTag9::from(Asn1SequenceOf::from(vec![HostAddress {
            addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
            address: ExplicitContextTag1::from(OctetStringAsn1::from(hostname.as_bytes().to_vec())),
        }]))
    });

    Ok(AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_enc_timestamp,
            pa_pac_request,
        ])))),
        req_body: ExplicitContextTag4::from(KdcReqBody {
            kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
                DEFAULT_AS_REQ_OPTIONS.to_vec(),
            ))),
            cname: Optional::from(Some(ExplicitContextTag1::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_PRINCIPAL])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                    IA5String::from_string(username.into())?,
                )])),
            }))),
            realm: ExplicitContextTag2::from(Realm::from(IA5String::from_string(realm.into())?)),
            sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(TGT_SERVICE_NAME.into())?),
                    KerberosStringAsn1::from(IA5String::from_string(realm.into())?),
                ])),
            }))),
            from: Optional::from(None),
            till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
            rtime: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
                GeneralizedTime::from(expiration_date),
            )))),
            nonce: ExplicitContextTag7::from(IntegerAsn1::from(OsRng::new()?.gen::<[u8; NONCE_LEN]>().to_vec())),
            etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
                IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8]),
                IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96 as u8]),
            ])),
            addresses: Optional::from(address),
            enc_authorization_data: Optional::from(None),
            additional_tickets: Optional::from(None),
        }),
    }))
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

    if divider == 0 || divider == service_principal.len() - 2 {
        return Err(Error {
            error_type: ErrorKind::InvalidParameter,
            description: "Invalid service principal name".into(),
        });
    }

    let service_name = &service_principal[0..divider];
    // `divider + 1` - do not include '/' char
    // `service_principal.len() - 1` - do not include NULL char
    let service_principal_name = &service_principal[(divider + 1)..(service_principal.len() - 1)];

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
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(OsRng::new()?.gen::<[u8; NONCE_LEN]>().to_vec())),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8]),
            IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96 as u8]),
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
        cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(MD5_CHECSUM_TYPE.to_vec())),
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

pub fn generate_authenticator_for_tgs_ap_req(kdc_rep: &KdcRep) -> Result<Authenticator> {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    Ok(Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(None),
        seq_number: Optional::from(Some(ExplicitContextTag7::from(IntegerAsn1::from(
            OsRng::new()?.gen::<u32>().to_be_bytes().to_vec(),
        )))),
        authorization_data: Optional::from(None),
    }))
}

pub fn generate_authenticator_for_ap_req(kdc_rep: &KdcRep, seq_num: u32) -> Result<Authenticator> {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    Ok(Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x00, 0x80, 0x03])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00,
            ])),
        }))),
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(Some(ExplicitContextTag6::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(OsRng::new()?.gen::<[u8; 32]>().to_vec())),
        }))),
        seq_number: Optional::from(Some(ExplicitContextTag7::from(IntegerAsn1::from_bytes_be_unsigned(
            seq_num.to_be_bytes().to_vec(),
        )))),
        authorization_data: Optional::from(None),
    }))
}

pub fn generate_tgs_ap_req(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.unwrap_or(AES256_CTS_HMAC_SHA1_96);
    let cipher = new_kerberos_cipher(encryption_type)?;

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_TGS_REQ_AUTHEN,
        &picky_asn1_der::to_vec(&authenticator)?,
    );

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![
            // do not need any options when ap_req uses in tgs_req pa_data
            0x00, 0x00, 0x00, 0x00,
        ]))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type as u8])),
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
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.unwrap_or(AES256_CTS_HMAC_SHA1_96);
    let cipher = new_kerberos_cipher(encryption_type)?;

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_AP_REQ_AUTHEN,
        &picky_asn1_der::to_vec(&authenticator)?,
    );

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(DEFAULT_AP_REQ_OPTIONS.to_vec()))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type as u8])),
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
