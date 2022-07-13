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
    AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, KRB_PRIV, NET_BIOS_ADDR_TYPE, NT_ENTERPRISE, NT_PRINCIPAL, NT_SRV_INST,
    PA_ENC_TIMESTAMP, PA_ENC_TIMESTAMP_KEY_USAGE, PA_PAC_OPTIONS_TYPE, PA_PAC_REQUEST_TYPE, PA_TGS_REQ_TYPE,
    TGS_REQ_MSG_TYPE, TGT_REQ_MSG_TYPE,
};
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, Checksum, EncKrbPrivPart, EncKrbPrivPartInner, EncryptedData,
    EncryptionKey, HostAddress, KerbPaPacRequest, KerberosFlags, KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc,
    PaPacOptions, PrincipalName, Realm, Ticket,
};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{
    ApReq, ApReqInner, AsReq, KdcRep, KdcReq, KdcReqBody, KrbPriv, KrbPrivInner, KrbPrivRequest, TgsReq, TgtReq,
};
use rand::rngs::OsRng;
use rand::Rng;

use super::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96};
use crate::kerberos::{CHANGE_PASSWORD_SERVICE_NAME, KADMIN};
use crate::sspi::kerberos::{EncryptionParams, KERBEROS_VERSION, SERVICE_NAME, TGT_SERVICE_NAME};
use crate::sspi::Result;
use crate::{Error, ErrorKind};

const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;
const MAX_MICROSECONDS_IN_SECOND: u32 = 999_999;
const MD5_CHECSUM_TYPE: [u8; 1] = [0x07];

pub const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x10];
const DEFAULT_TGS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x08];
const DEFAULT_PA_PAC_OPTIONS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

// AP-REQ toggled options:
// * mutual required
// * use session key
// other options are disabled
pub const DEFAULT_AP_REQ_OPTIONS: [u8; 4] = [0x60, 0x00, 0x00, 0x00];

// [MS-KILE] 3.3.5.6.1 Client Principal Lookup
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6435d3fb-8cf6-4df5-a156-1277690ed59c
fn get_client_principal_name_type(username: &str, _domain: &str) -> u8 {
    if username.contains('@') {
        NT_ENTERPRISE
    } else {
        NT_PRINCIPAL
    }
}

fn get_client_principal_realm(username: &str, domain: &str) -> String {
    if domain.is_empty() {
        if let Some((_left, right)) = username.split_once('@') {
            return right.to_string();
        }
    }
    domain.to_string()
}

pub fn generate_as_req_without_pre_auth(username: &str, domain: &str) -> Result<AsReq> {
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

    let name_type = get_client_principal_name_type(username, domain);
    let realm = &get_client_principal_realm(username, domain);

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
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
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

pub fn generate_passwd_as_req(
    username: &str,
    salt: &[u8],
    password: &str,
    domain: &str,
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

    println!("passwd key: {:?}", key);

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

    let name_type = get_client_principal_name_type(username, domain);
    let realm = &get_client_principal_realm(username, domain);

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
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                    IA5String::from_string(username.into())?,
                )])),
            }))),
            realm: ExplicitContextTag2::from(Realm::from(IA5String::from_string(realm.into())?)),
            sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(KADMIN.into())?),
                    KerberosStringAsn1::from(IA5String::from_string(CHANGE_PASSWORD_SERVICE_NAME.into())?),
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
            // addresses: Optional::from(address),
            addresses: Optional::from(None),
            enc_authorization_data: Optional::from(None),
            additional_tickets: Optional::from(None),
        }),
    }))
}

pub fn generate_as_req(
    username: &str,
    salt: &[u8],
    password: &str,
    domain: &str,
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

    let name_type = get_client_principal_name_type(username, domain);
    let realm = &get_client_principal_realm(username, domain);

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
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
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

pub fn generate_authenticator_for_krb_priv(kdc_rep: &KdcRep, seq_num: u32) -> Result<Authenticator> {
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
    options: &[u8; 4],
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
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(options.to_vec()))),
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

pub fn generate_krb_priv_request(
    ticket: Ticket,
    session_key: &[u8],
    new_password: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
    seq_num: u32,
) -> Result<KrbPrivRequest> {
    let ap_req = generate_ap_req(ticket, session_key, authenticator, enc_params, &[0, 0, 0, 0])?;

    let enc_part = EncKrbPrivPart::from(EncKrbPrivPartInner {
        user_data: ExplicitContextTag0::from(OctetStringAsn1::from(new_password.to_vec())),
        timestamp: Optional::from(None),
        usec: Optional::from(None),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from_bytes_be_unsigned(
            seq_num.to_be_bytes().to_vec(),
        )))),
        s_address: ExplicitContextTag4::from(HostAddress {
            addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
            address: ExplicitContextTag1::from(OctetStringAsn1::from(
                sys_info::hostname().unwrap().as_bytes().to_vec(),
            )),
        }),
        r_address: Optional::from(None),
    });

    println!("enc: {:?}", enc_part);
    println!("enc: {:?}", &picky_asn1_der::to_vec(&enc_part)?);

    let encryption_type = enc_params.encryption_type.unwrap_or(AES256_CTS_HMAC_SHA1_96);
    let cipher = new_kerberos_cipher(encryption_type)?;

    let enc_part = cipher.encrypt(
        &authenticator.0.subkey.0.as_ref().unwrap().key_value.0,
        13,
        &picky_asn1_der::to_vec(&enc_part)?,
    );

    let krb_priv = KrbPriv::from(KrbPrivInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![KRB_PRIV])),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type as u8])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(enc_part)),
        }),
    });

    Ok(KrbPrivRequest { ap_req, krb_priv })
}

#[cfg(test)]
mod tests {
    use kerberos_constants::key_usages::KEY_USAGE_AS_REP_ENC_PART;
    use kerberos_crypto::new_kerberos_cipher;
    use picky_krb::data_types::Authenticator;
    use picky_krb::messages::EncAsRepPart;

    use crate::kerberos::config::KdcType;
    use crate::kerberos::DEFAULT_ENCRYPTION_TYPE;
    use crate::{Kerberos, KerberosConfig};

    #[test]
    fn decrypt_priv_enc_part() {
        let username = "p5";
        // let password = "qweQWE123!@#";
        let password = "qqqQQQ111!!!";
        let salt = "QKATION.COMp5";
        let domain = "QKATION";
        let realm = "QKATION.COM";

        //
        let cipher = new_kerberos_cipher(DEFAULT_ENCRYPTION_TYPE).unwrap();

        let key = cipher.generate_key_from_string(password, salt.as_bytes());

        let enc_data = cipher
            .decrypt(
                &key,
                KEY_USAGE_AS_REP_ENC_PART,
                &[
                    235, 134, 58, 45, 254, 112, 168, 45, 180, 212, 191, 16, 49, 68, 204, 174, 93, 105, 47, 254, 18, 11,
                    58, 253, 122, 29, 18, 64, 150, 173, 54, 60, 235, 179, 25, 0, 120, 11, 112, 216, 91, 216, 226, 68,
                    156, 95, 57, 82, 88, 252, 56, 1, 140, 50, 167, 217, 192, 208, 18, 84, 149, 107, 98, 35, 145, 8,
                    141, 160, 183, 158, 109, 94, 64, 42, 191, 59, 151, 252, 89, 248, 8, 24, 76, 124, 195, 109, 81, 49,
                    16, 128, 174, 203, 161, 165, 244, 150, 253, 21, 74, 217, 108, 193, 229, 206, 120, 2, 166, 59, 64,
                    201, 36, 203, 57, 18, 42, 95, 177, 217, 192, 107, 220, 177, 73, 160, 87, 157, 212, 22, 206, 54, 73,
                    92, 142, 206, 22, 112, 126, 56, 43, 13, 202, 47, 84, 69, 71, 4, 81, 160, 158, 246, 86, 210, 31,
                    166, 11, 3, 105, 163, 248, 98, 72, 44, 204, 139, 44, 87, 124, 98, 121, 40, 141, 212, 248, 219, 143,
                    251, 17, 11, 128, 233, 59, 140, 224, 244, 116, 167, 88, 187, 97, 87, 27, 88, 49, 61, 124, 49, 120,
                    68, 107, 27, 43, 248, 66, 198, 200, 255, 237, 44, 197, 20, 19, 138, 174, 205, 7, 205, 247, 121, 40,
                    31, 216, 202, 169, 158, 162, 212, 89, 53, 81, 210, 255, 198, 180, 254, 247, 198, 183, 96, 242, 198,
                    173, 251, 100, 199, 104, 180, 94, 27, 204, 108, 203, 241, 23, 5, 155, 19, 22, 215, 71, 4, 130, 118,
                    142, 84, 2, 160, 146, 44, 187, 167, 85, 13, 76, 173, 33, 119, 9, 208, 141, 68, 13, 166, 248, 241,
                    25, 222, 180, 45, 53, 118, 130, 146, 76, 52, 1, 145, 165, 188, 21, 110, 32, 183, 61, 139, 25, 147,
                    229, 75, 111, 116, 167, 229, 59, 143, 203, 114, 75, 49, 237, 102,
                ],
            )
            .unwrap();

        println!("{:?}", enc_data);

        let enc_as_rep_part: EncAsRepPart = picky_asn1_der::from_bytes(&enc_data).unwrap();

        println!("{:?}", enc_as_rep_part);
        println!("{:?}", enc_as_rep_part.0.key.key_value.0);
    }

    #[test]
    fn test_decrypt_priv() {
        let session_key = [
            32, 251, 161, 43, 63, 249, 41, 36, 33, 29, 2, 41, 171, 16, 156, 116, 236, 31, 202, 103, 90, 38, 42, 95, 91,
            33, 150, 23, 73, 128, 43, 79,
        ];

        let enc_data = [
            251, 203, 165, 65, 153, 175, 145, 139, 228, 247, 183, 60, 132, 84, 138, 176, 207, 39, 144, 229, 155, 61,
            235, 203, 48, 225, 81, 200, 141, 154, 169, 86, 173, 136, 255, 17, 200, 185, 164, 233, 123, 86, 147, 182, 0,
            66, 194, 77, 248, 33, 51, 10, 48, 206, 216, 214, 47, 12, 39, 238, 115, 28, 137, 254, 178, 188, 52, 173,
            216, 110, 145, 49, 159,
        ];
        // priv ap_req authenticator
        let authenticator = [
            90, 166, 167, 142, 169, 235, 19, 170, 76, 205, 171, 40, 64, 12, 143, 135, 71, 73, 14, 96, 195, 162, 246,
            230, 85, 140, 39, 30, 9, 52, 131, 245, 101, 73, 138, 126, 219, 118, 5, 124, 107, 163, 52, 55, 158, 56, 102,
            190, 51, 87, 39, 34, 138, 125, 67, 208, 4, 99, 208, 29, 154, 243, 69, 93, 178, 233, 175, 232, 139, 133,
            186, 106, 29, 105, 5, 71, 188, 181, 141, 140, 220, 31, 11, 19, 153, 53, 144, 159, 12, 59, 26, 29, 4, 30,
            180, 32, 152, 198, 203, 144, 77, 149, 29, 141, 66, 223, 190, 6, 247, 162, 40, 15, 96, 127, 117, 230, 60,
            37, 53, 169, 156, 179, 9, 161, 154, 4, 245, 236, 76, 93, 132, 236, 29, 64, 66, 99, 239, 20, 245, 115, 173,
            214, 16, 19, 44, 74,
        ];

        let cipher = new_kerberos_cipher(18).unwrap();

        let key_1 = session_key;

        let password = "qqqQQQ111!!!";
        let salt = "QKATION.COMp5";
        let key_2 = cipher.generate_key_from_string(password, salt.as_bytes());

        // let enc_data = cipher
        //     .decrypt(&key, 13, &enc_data)
        //     .unwrap();
        let bytes = cipher.decrypt(&key_1, 11, &authenticator).unwrap();
        println!("11 - {:?}", bytes);
        let a: Authenticator = picky_asn1_der::from_bytes(&bytes).unwrap();
        println!("{:?}", a);
        println!("{:?}", a.0.subkey);

        let auth_key = [
            43, 172, 86, 104, 137, 175, 171, 8, 83, 38, 5, 81, 242, 178, 236, 246, 24, 225, 154, 189, 234, 147, 212,
            73, 210, 160, 177, 153, 123, 15, 140, 246,
        ];

        println!("13 - {:?}", cipher.decrypt(&auth_key, 13, &enc_data));

        // println!("{:?}", enc_data);
        let ap_rep_enc = [
            218, 123, 236, 220, 101, 47, 45, 70, 106, 25, 67, 106, 10, 200, 237, 233, 168, 230, 209, 134, 210, 70, 15,
            179, 21, 129, 41, 72, 205, 206, 37, 58, 143, 60, 37, 48, 137, 187, 89, 131, 16, 52, 68, 37, 60, 28, 215,
            252, 225, 97, 29, 147, 62, 127, 19, 216,
        ];
        let priv_enc = [
            244, 180, 210, 36, 82, 20, 173, 202, 122, 213, 65, 87, 59, 79, 72, 138, 41, 183, 39, 148, 25, 196, 189,
            182, 26, 48, 252, 101, 54, 24, 238, 24, 228, 212, 69, 37, 151, 225, 49, 193, 172, 32, 236, 245, 125, 139,
            33, 149, 71, 31, 65, 220, 230, 121, 86,
        ];

        let cipher = new_kerberos_cipher(18).unwrap();

        let data = cipher.decrypt(&session_key, 12, &ap_rep_enc).unwrap();
        println!("data: {:?}", data);

        let data = cipher.decrypt(&auth_key, 13, &priv_enc).unwrap();
        println!("data: {:?}", data);
    }

    #[cfg(feature = "network_client")]
    #[test]
    fn test_password_changing() {
        use std::str::FromStr;

        use reqwest::Url;

        use crate::builders::ChangePasswordBuilder;
        use crate::kerberos::network_client::reqwest_network_client::ReqwestNetworkClient;
        use crate::Sspi;

        let domain = "QKATION";
        let username = "p6";
        let password = "qweQWE123!@#";

        let mut kerberos = Kerberos::new_client_from_config(KerberosConfig {
            url: Url::from_str("tcp://192.168.0.108:88").unwrap(),
            kdc_type: KdcType::Kdc,
            network_client: Box::new(ReqwestNetworkClient::new()),
        })
        .unwrap();

        let mut output = [];

        let change_password = ChangePasswordBuilder::new()
            .with_account_name(username.into())
            .with_domain_name(domain.into())
            .with_old_password(password.into())
            .with_new_password("asdASD456$%^".into())
            .with_output(&mut output)
            .build()
            .unwrap();

        kerberos.change_password(change_password).unwrap();
    }

    #[test]
    fn just_decryption() {
        let priv_ap_req_auth = [
            87, 123, 80, 209, 27, 22, 225, 218, 169, 58, 110, 54, 14, 187, 224, 18, 232, 118, 204, 166, 76, 116, 115,
            146, 111, 138, 218, 30, 197, 120, 1, 174, 58, 56, 24, 81, 60, 88, 206, 125, 168, 129, 85, 97, 66, 213, 13,
            247, 231, 86, 64, 72, 145, 34, 4, 7, 95, 124, 102, 38, 143, 184, 65, 211, 189, 99, 157, 192, 76, 194, 12,
            66, 84, 201, 29, 201, 35, 254, 26, 227, 192, 184, 83, 2, 171, 171, 171, 143, 52, 236, 154, 158, 150, 136,
            240, 183, 252, 26, 225, 109, 223, 251, 217, 104, 116, 142, 171, 190, 5, 231, 125, 84, 210, 252, 226, 68,
            15, 109, 56, 103, 221, 9, 204, 90, 126, 119, 17, 62, 90, 215, 148, 102, 123, 163, 22, 207, 16, 223, 156,
            233, 132, 198, 212, 31, 21, 62, 166, 152, 17,
        ];
        let req_priv_enc = [
            227, 153, 23, 92, 116, 208, 149, 167, 133, 156, 83, 120, 61, 244, 208, 71, 148, 226, 67, 12, 203, 159, 64,
            52, 3, 77, 106, 55, 244, 129, 63, 221, 126, 27, 139, 59, 90, 98, 152, 123, 237, 212, 151, 87, 204, 28, 135,
            185, 236, 145, 182, 24, 28, 30, 58,
        ];

        let cipher = new_kerberos_cipher(18).unwrap();

        println!(
            "{:?}",
            cipher.decrypt(
                &[
                    250, 155, 199, 119, 68, 61, 253, 106, 96, 113, 154, 40, 26, 111, 218, 96, 229, 76, 67, 228, 184,
                    62, 228, 115, 67, 188, 139, 196, 101, 70, 220, 199
                ],
                11,
                &priv_ap_req_auth
            )
        );

        println!(
            "{:?}",
            cipher.decrypt(
                &[
                    181, 92, 42, 214, 110, 66, 70, 16, 48, 7, 231, 228, 79, 63, 158, 113, 222, 119, 246, 102, 12, 199,
                    143, 116, 6, 94, 148, 74, 37, 75, 223, 166
                ],
                13,
                &req_priv_enc,
            )
        );
    }

    #[test]
    fn decrypt_response() {
        let ap_rep_enc = [
            27, 166, 4, 252, 25, 171, 28, 84, 135, 203, 53, 34, 40, 71, 174, 171, 157, 110, 74, 243, 201, 133, 30, 42,
            100, 20, 23, 56, 123, 154, 4, 58, 111, 51, 50, 156, 145, 218, 213, 108, 197, 8, 156, 17, 194, 131, 155, 70,
            248, 66, 184, 163, 149, 105, 210, 152, 85, 178,
        ];

        let priv_enc = [
            110, 93, 233, 53, 121, 177, 70, 64, 164, 21, 248, 221, 202, 167, 84, 234, 181, 57, 69, 184, 56, 152, 242,
            218, 16, 205, 97, 89, 128, 72, 105, 142, 28, 79, 179, 126, 218, 186, 59, 21, 77, 130, 241, 105, 170, 184,
            163, 154, 61, 150, 165, 224, 174, 67, 253,
        ];

        let pass_key = [
            77, 226, 183, 212, 227, 37, 14, 222, 50, 88, 104, 176, 56, 96, 55, 91, 56, 255, 46, 97, 3, 197, 52, 219,
            64, 114, 174, 178, 56, 189, 67, 51,
        ];
        let session_key = [
            51, 173, 150, 217, 175, 85, 199, 80, 157, 106, 229, 1, 146, 158, 251, 237, 33, 197, 214, 220, 132, 221, 13,
            105, 244, 87, 161, 247, 82, 14, 109, 248,
        ];
        let auth_key = [
            79, 82, 141, 77, 42, 171, 103, 122, 130, 201, 188, 7, 136, 24, 26, 200, 35, 24, 99, 99, 134, 241, 138, 168,
            88, 209, 229, 156, 99, 60, 123, 195,
        ];

        let cipher = new_kerberos_cipher(18).unwrap();

        let data = cipher.decrypt(&session_key, 12, &ap_rep_enc).unwrap();
        println!("data: {:?}", data);

        let data = cipher.decrypt(&auth_key, 13, &priv_enc).unwrap();
        println!("data: {:?}", data);

        // for i in 0..50 {
        //     println!("{} {:?}", i, cipher.decrypt(&auth_key, i, &priv_enc));
        //     println!("{} {:?}", i, cipher.decrypt(&session_key, i, &priv_enc));
        // }
    }
}
