use chrono::{Duration, Utc};
use kerberos_crypto::new_kerberos_cipher;
use picky_asn1::{
    bit_string::BitString,
    date::GeneralizedTime,
    restricted_string::IA5String,
    wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
        ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
        ExplicitContextTag7, ExplicitContextTag8, GeneralizedTimeAsn1, IntegerAsn1,
        OctetStringAsn1, Optional,
    },
};
use picky_krb::{
    data_types::{
        ApOptions, Authenticator, AuthenticatorInner, EncryptedData, EtypeInfo2, KerbPaPacRequest,
        KerberosFlags, KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc, PaPacOptions,
        PrincipalName, Realm, Ticket,
    },
    messages::{
        ApReq, ApReqInner, AsRep, AsReq, EncAsRepPart, EncTgsRepPart, KdcRep, KdcReq, KdcReqBody,
        TgsRep, TgsReq,
    },
};
use rand::{rngs::OsRng, Rng};

use crate::sspi::{
    kerberos::{KERBEROS_VERSION, SERVICE_NAME},
    Error, ErrorKind, Result,
};

const AS_REQ_MSG_TYPE: u8 = 0x0a;
const TGS_REQ_MSG_TYPE: u8 = 0x0c;
const AP_REQ_MSG_TYPE: u8 = 0x0e;

const NT_PRINCIPAL: u8 = 0x01;
const NT_SRV_INST: u8 = 0x02;
const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;

const AES128_CTS_HMAC_SHA1_96: u8 = 0x11;
const AES256_CTS_HMAC_SHA1_96: u8 = 0x12;

const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x10];
const DEFAULT_TGS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x00];

const PA_ENC_TIMESTAMP: [u8; 1] = [0x02];
const PA_ENC_TIMESTAMP_KEY_USAGE: i32 = 1;
const PA_PAC_REQUEST_TYPE: [u8; 2] = [0x00, 0x80];
const PA_ETYPE_INFO2_TYPE: [u8; 1] = [0x13];
const PA_TGS_REQ_TYPE: [u8; 1] = [0x01];
const PA_PAC_OPTIONS_TYPE: [u8; 2] = [0x00, 0xa7];

const MAX_MICROSECONDS_IN_SECOND: u32 = 999_999;

pub fn generate_as_req(username: &str, password: &str, realm: &str) -> AsReq {
    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    let timestamp = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(
            current_date,
        ))),
        pausec: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(
            microseconds.to_be_bytes().to_vec(),
        )))),
    };
    let timestamp_bytes = picky_asn1_der::to_vec(&timestamp).unwrap();

    let cipher = new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
    let salt = cipher.generate_salt(realm, username);
    let key = cipher.generate_key_from_string(password, &salt);

    let encrypted_timestamp = cipher.encrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &timestamp_bytes);

    let pa_enc_timestamp = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_timestamp)),
            })
            .unwrap(),
        )),
    };

    let pa_pac_request = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&KerbPaPacRequest {
                include_pac: ExplicitContextTag0::from(true),
            })
            .unwrap(),
        )),
    };

    AsReq::from(KdcReq {
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
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(username.into()).unwrap()),
                ])),
            }))),
            realm: ExplicitContextTag2::from(Realm::from(
                IA5String::from_string(realm.into()).unwrap(),
            )),
            sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(SERVICE_NAME.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(realm.into()).unwrap()),
                ])),
            }))),
            from: Optional::from(None),
            till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
                expiration_date,
            ))),
            rtime: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
                GeneralizedTime::from(expiration_date),
            )))),
            nonce: ExplicitContextTag7::from(IntegerAsn1::from(
                OsRng::new().unwrap().gen::<[u8; NONCE_LEN]>().to_vec(),
            )),
            etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
                IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96]),
                IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96]),
            ])),
            addresses: Optional::from(None),
            enc_authorization_data: Optional::from(None),
            additional_tickets: Optional::from(None),
        }),
    })
}

pub fn generate_tgs_req(
    username: &str,
    realm: &str,
    session_key: &[u8],
    ticket: Ticket,
    authenticator: &Authenticator,
) -> TgsReq {
    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let pa_tgs_req = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_TGS_REQ_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&generate_ap_req(ticket, session_key, authenticator)).unwrap(),
        )),
    };

    let pa_pac_options = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_OPTIONS_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&PaPacOptions {
                flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(vec![
                    0x40, 0x00, 0x00, 0x00,
                ]))),
            })
            .unwrap(),
        )),
    };

    TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_tgs_req,
            pa_pac_options,
        ])))),
        req_body: ExplicitContextTag4::from(KdcReqBody {
            kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
                DEFAULT_TGS_REQ_OPTIONS.to_vec(),
            ))),
            cname: Optional::from(None),
            realm: ExplicitContextTag2::from(Realm::from(
                IA5String::from_string(realm.into()).unwrap(),
            )),
            sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string("TERMSRV".into()).unwrap()),
                    KerberosStringAsn1::from(
                        IA5String::from_string(format!("{}.{}", username, realm.to_lowercase()))
                            .unwrap(),
                    ),
                ])),
            }))),
            from: Optional::from(None),
            till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(
                expiration_date,
            ))),
            rtime: Optional::from(None),
            nonce: ExplicitContextTag7::from(IntegerAsn1::from(
                OsRng::new().unwrap().gen::<[u8; NONCE_LEN]>().to_vec(),
            )),
            etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
                IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96]),
                IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96]),
            ])),
            addresses: Optional::from(None),
            enc_authorization_data: Optional::from(None),
            additional_tickets: Optional::from(None),
        }),
    })
}

pub fn generate_authenticator_from_kdc_rep(kdc_rep: &KdcRep) -> Authenticator {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    })
}

pub fn generate_ap_req(ticket: Ticket, session_key: &[u8], authenticator: &Authenticator) -> ApReq {
    let cipher = new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        7,
        &picky_asn1_der::to_vec(&authenticator).unwrap(),
    );

    ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![
            0x60, 0x00, 0x00, 0x00,
        ]))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    })
}

pub fn generate_ap_req_2(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
) -> ApReq {
    let cipher = new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        11,
        &picky_asn1_der::to_vec(&authenticator).unwrap(),
    );

    ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![
            0x00, 0x00, 0x00, 0x00,
        ]))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    })
}

pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    salt: &str,
    password: &str,
) -> Result<Vec<u8>> {
    let cipher = new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

    let key = cipher.generate_key_from_string(password, salt.as_bytes());

    let enc_data = cipher
        .decrypt(&key, 3, &as_rep.0.enc_part.0.cipher.0 .0)
        .map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    let enc_as_rep_part: EncAsRepPart =
        picky_asn1_der::from_bytes(&enc_data).map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

pub fn extract_session_key_from_tgs_rep(tgs_rep: &TgsRep, session_key: &[u8]) -> Result<Vec<u8>> {
    let cipher = new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

    let enc_data = cipher
        .decrypt(session_key, 8, &tgs_rep.0.enc_part.0.cipher.0 .0)
        .map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    let enc_as_rep_part: EncTgsRepPart =
        picky_asn1_der::from_bytes(&enc_data).map_err(|e| Error {
            error_type: ErrorKind::DecryptFailure,
            description: format!("{:?}", e),
        })?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec())
}

pub fn extract_encryption_params_from_as_rep(as_rep: &AsRep) -> Result<(u8, String)> {
    match as_rep
        .0
        .padata
        .0
        .as_ref()
        .map(|v| {
            v.0 .0
                .iter()
                .find(|e| e.padata_type.0 .0 == PA_ETYPE_INFO2_TYPE)
                .map(|pa_data| pa_data.padata_data.0 .0.clone())
        })
        .unwrap_or_default()
    {
        Some(data) => {
            let pa_etype_into2: EtypeInfo2 =
                picky_asn1_der::from_bytes(&data).map_err(|e| Error {
                    error_type: ErrorKind::DecryptFailure,
                    description: format!("{:?}", e),
                })?;
            let pa_etype_into2 = pa_etype_into2.0.get(0).ok_or(Error {
                error_type: ErrorKind::InvalidParameter,
                description: "Missing EtypeInto2Entry in EtypeInfo2".into(),
            })?;
            Ok((
                pa_etype_into2.etype.0 .0.get(0).copied().unwrap(),
                pa_etype_into2
                    .salt
                    .0
                    .as_ref()
                    .map(|salt| salt.0.to_string())
                    .ok_or(Error {
                        error_type: ErrorKind::InvalidParameter,
                        description: "Missing salt in EtypeInto2Entry".into(),
                    })?,
            ))
        }
        None => Err(Error {
            error_type: ErrorKind::NoPaData,
            description: format!(
                "Missing PaData: PA_ETYPE_INFO2 ({:0x?})",
                PA_ETYPE_INFO2_TYPE
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use kerberos_crypto::new_kerberos_cipher;
    use picky_krb::data_types::EtypeInfo2;
    use picky_krb::messages::{ApReq, AsRep, EncAsRepPart, EncTgsRepPart, TgsRep};

    use crate::sspi::kerberos::client::extract_session_key_from_tgs_rep;

    use super::super::reqwest_client::ReqwestNetworkClient;
    use super::super::NetworkClient;
    use super::{
        extract_encryption_params_from_as_rep, extract_session_key_from_as_rep, generate_as_req,
    };
    use super::{AES256_CTS_HMAC_SHA1_96, PA_ETYPE_INFO2_TYPE};

    #[test]
    fn test_as_req_generation() {
        let network_client = ReqwestNetworkClient::new();

        let as_req = generate_as_req("p2", "qweQWE123!@#", "QKATION.COM");

        let as_req = picky_asn1_der::to_vec(&as_req).unwrap();

        let mut data = vec![0; 4 + as_req.len()];
        data[0..4].copy_from_slice(&((as_req.len() as u32).to_be_bytes()));
        data[4..].copy_from_slice(&as_req);

        let response = network_client
            .send(
                &url::Url::from_str("tcp://192.168.0.109:88").unwrap(),
                &data,
            )
            .unwrap();

        println!("rep data: {:?}", response);

        let as_rep: AsRep = picky_asn1_der::from_bytes(&response[4..]).unwrap();
        println!("{:?}", as_rep);
    }

    #[test]
    fn test_as_rep_parsing() {
        let as_rep_bytes = [
            107, 130, 5, 155, 48, 130, 5, 151, 160, 3, 2, 1, 5, 161, 3, 2, 1, 11, 162, 39, 48, 37,
            48, 35, 161, 3, 2, 1, 19, 162, 28, 4, 26, 48, 24, 48, 22, 160, 3, 2, 1, 18, 161, 15,
            27, 13, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 112, 50, 163, 13, 27, 11, 81, 75,
            65, 84, 73, 79, 78, 46, 67, 79, 77, 164, 15, 48, 13, 160, 3, 2, 1, 1, 161, 6, 48, 4,
            27, 2, 112, 50, 165, 130, 4, 2, 97, 130, 3, 254, 48, 130, 3, 250, 160, 3, 2, 1, 5, 161,
            13, 27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 32, 48, 30, 160, 3, 2, 1,
            2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 81, 75, 65, 84, 73, 79,
            78, 46, 67, 79, 77, 163, 130, 3, 192, 48, 130, 3, 188, 160, 3, 2, 1, 18, 161, 3, 2, 1,
            2, 162, 130, 3, 174, 4, 130, 3, 170, 172, 80, 13, 221, 63, 5, 24, 199, 252, 158, 153,
            98, 47, 131, 120, 237, 130, 203, 84, 247, 222, 229, 137, 84, 116, 17, 248, 226, 82,
            100, 145, 103, 141, 14, 211, 166, 107, 3, 53, 54, 92, 84, 17, 130, 136, 71, 26, 130,
            125, 248, 99, 61, 246, 170, 85, 41, 248, 12, 228, 188, 190, 63, 140, 129, 45, 36, 94,
            49, 188, 255, 188, 194, 232, 107, 205, 33, 53, 163, 181, 228, 192, 197, 112, 227, 74,
            108, 176, 174, 64, 181, 37, 87, 38, 254, 158, 62, 255, 149, 121, 32, 86, 138, 85, 68,
            142, 93, 114, 252, 102, 60, 49, 51, 109, 80, 255, 50, 90, 66, 155, 248, 90, 187, 225,
            15, 87, 100, 187, 83, 116, 141, 72, 1, 188, 25, 44, 22, 219, 174, 94, 80, 119, 124,
            115, 66, 29, 184, 202, 106, 40, 181, 81, 60, 19, 247, 152, 154, 49, 119, 106, 36, 196,
            161, 1, 255, 195, 175, 183, 226, 28, 166, 21, 93, 63, 136, 28, 44, 187, 181, 46, 47,
            156, 208, 196, 138, 218, 191, 154, 247, 251, 86, 135, 0, 40, 70, 46, 255, 226, 131,
            115, 18, 242, 8, 158, 64, 155, 138, 187, 164, 121, 247, 90, 25, 30, 2, 189, 219, 121,
            168, 140, 68, 40, 22, 81, 172, 6, 193, 142, 90, 55, 11, 245, 114, 165, 64, 59, 17, 156,
            242, 177, 245, 218, 137, 140, 221, 202, 32, 67, 38, 255, 164, 208, 235, 81, 244, 226,
            142, 48, 56, 82, 166, 104, 70, 110, 232, 235, 232, 37, 11, 8, 191, 34, 18, 82, 114, 44,
            254, 165, 209, 36, 220, 220, 155, 97, 142, 253, 217, 91, 151, 225, 75, 135, 107, 141,
            250, 252, 174, 94, 74, 105, 144, 154, 237, 104, 47, 138, 92, 66, 33, 112, 165, 49, 9,
            184, 156, 38, 45, 36, 6, 210, 85, 47, 166, 110, 232, 137, 204, 3, 181, 209, 112, 2,
            213, 226, 35, 115, 225, 0, 181, 177, 158, 41, 30, 7, 5, 45, 127, 171, 243, 187, 108,
            231, 248, 194, 48, 84, 76, 0, 104, 244, 34, 235, 87, 23, 167, 5, 21, 95, 31, 225, 142,
            186, 152, 119, 181, 71, 171, 13, 219, 142, 70, 12, 143, 208, 131, 216, 177, 99, 43, 33,
            48, 205, 54, 15, 237, 29, 27, 199, 142, 175, 218, 231, 15, 46, 113, 170, 41, 141, 155,
            107, 67, 168, 203, 115, 54, 218, 231, 74, 153, 111, 3, 172, 174, 255, 216, 250, 31,
            207, 226, 70, 87, 251, 160, 20, 82, 90, 32, 57, 114, 135, 21, 104, 111, 200, 11, 14,
            132, 95, 233, 209, 196, 210, 203, 174, 212, 247, 210, 130, 178, 199, 58, 122, 8, 214,
            135, 142, 133, 78, 44, 184, 141, 58, 230, 188, 222, 150, 77, 228, 66, 3, 125, 53, 158,
            161, 73, 147, 172, 169, 26, 146, 97, 249, 199, 115, 122, 192, 172, 214, 251, 68, 247,
            149, 213, 224, 201, 139, 224, 254, 23, 86, 116, 58, 93, 233, 188, 11, 97, 209, 204, 18,
            164, 39, 75, 183, 195, 10, 144, 37, 55, 222, 127, 23, 48, 172, 17, 1, 56, 153, 221,
            107, 244, 142, 131, 66, 76, 140, 57, 85, 141, 236, 182, 223, 227, 104, 53, 30, 33, 145,
            162, 79, 78, 53, 127, 160, 155, 254, 61, 34, 68, 195, 160, 176, 69, 102, 180, 45, 246,
            200, 70, 21, 62, 83, 205, 129, 195, 53, 73, 59, 205, 186, 157, 178, 83, 187, 35, 21,
            160, 213, 161, 155, 121, 60, 89, 88, 90, 39, 168, 144, 58, 102, 12, 117, 28, 171, 93,
            144, 212, 12, 112, 176, 174, 132, 28, 215, 174, 37, 138, 113, 87, 37, 137, 218, 138,
            31, 135, 252, 57, 116, 115, 254, 190, 110, 125, 90, 138, 110, 18, 174, 101, 165, 130,
            99, 13, 189, 237, 131, 15, 184, 50, 58, 208, 136, 181, 82, 208, 134, 147, 176, 135,
            238, 165, 122, 77, 169, 229, 78, 191, 26, 93, 190, 141, 111, 1, 225, 204, 11, 148, 199,
            185, 43, 161, 135, 126, 79, 64, 229, 44, 161, 247, 30, 94, 118, 134, 63, 143, 74, 45,
            64, 20, 215, 130, 81, 144, 60, 94, 218, 140, 6, 33, 112, 146, 55, 89, 160, 116, 105,
            16, 26, 155, 16, 48, 7, 86, 237, 82, 136, 130, 163, 62, 11, 199, 116, 172, 149, 147,
            47, 165, 53, 245, 236, 67, 25, 34, 11, 241, 201, 103, 138, 64, 71, 175, 85, 211, 6,
            138, 190, 135, 215, 226, 126, 61, 135, 34, 77, 218, 49, 33, 43, 187, 117, 18, 16, 100,
            255, 196, 130, 241, 172, 154, 174, 188, 149, 30, 157, 105, 54, 125, 138, 170, 117, 30,
            65, 196, 218, 101, 95, 233, 203, 129, 186, 115, 169, 209, 222, 242, 10, 236, 154, 99,
            87, 212, 11, 176, 41, 92, 103, 17, 251, 104, 190, 244, 172, 107, 21, 9, 147, 150, 67,
            170, 70, 154, 190, 235, 220, 70, 20, 16, 191, 119, 21, 29, 37, 156, 167, 41, 33, 240,
            177, 192, 31, 210, 28, 85, 64, 239, 120, 115, 110, 165, 12, 253, 222, 188, 17, 41, 128,
            148, 224, 62, 80, 17, 252, 224, 123, 54, 128, 88, 44, 102, 36, 85, 11, 185, 241, 233,
            153, 25, 213, 22, 146, 43, 2, 73, 60, 113, 249, 159, 174, 242, 139, 111, 59, 189, 177,
            94, 174, 249, 32, 158, 186, 151, 48, 213, 194, 146, 142, 53, 224, 146, 181, 219, 75,
            200, 115, 22, 186, 136, 143, 50, 166, 130, 1, 58, 48, 130, 1, 54, 160, 3, 2, 1, 18,
            161, 3, 2, 1, 2, 162, 130, 1, 40, 4, 130, 1, 36, 28, 251, 89, 218, 42, 234, 125, 220,
            20, 55, 226, 156, 149, 40, 79, 48, 51, 37, 224, 149, 132, 68, 117, 226, 201, 143, 12,
            71, 10, 50, 126, 106, 197, 216, 223, 9, 104, 180, 132, 39, 187, 83, 107, 175, 253, 209,
            131, 112, 28, 139, 238, 161, 218, 230, 167, 19, 10, 105, 177, 225, 47, 143, 165, 126,
            87, 230, 99, 196, 134, 198, 122, 206, 247, 138, 208, 193, 184, 96, 15, 207, 221, 164,
            254, 74, 196, 77, 210, 143, 154, 199, 234, 235, 196, 182, 100, 221, 207, 26, 105, 91,
            77, 63, 209, 96, 178, 184, 182, 227, 188, 43, 68, 239, 243, 172, 182, 195, 46, 164, 16,
            122, 138, 16, 12, 146, 238, 7, 138, 223, 205, 148, 154, 14, 156, 246, 220, 7, 243, 134,
            159, 203, 170, 118, 211, 78, 219, 134, 91, 249, 202, 169, 46, 179, 149, 127, 137, 82,
            109, 82, 82, 60, 118, 205, 110, 164, 72, 5, 197, 213, 145, 134, 188, 118, 66, 71, 163,
            224, 23, 138, 158, 83, 28, 220, 205, 143, 27, 86, 96, 143, 84, 128, 160, 197, 180, 100,
            37, 135, 56, 97, 113, 217, 152, 150, 142, 12, 69, 164, 233, 215, 133, 63, 58, 152, 186,
            67, 65, 215, 67, 178, 211, 78, 122, 253, 10, 114, 129, 241, 5, 21, 59, 232, 36, 236,
            86, 189, 77, 203, 36, 172, 170, 90, 249, 68, 40, 73, 168, 229, 229, 77, 226, 49, 196,
            168, 139, 127, 112, 38, 240, 135, 24, 147, 176, 231, 171, 53, 155, 167, 206, 174, 151,
            19, 170, 103, 187, 107, 117, 182, 243, 200, 241, 117, 137, 15, 32, 92, 2, 21, 4, 228,
            199, 51, 194, 18,
        ];
        let as_rep: AsRep = picky_asn1_der::from_bytes(&as_rep_bytes).unwrap();
        // println!("{:?}", as_rep);

        let default_encryption_params = (AES256_CTS_HMAC_SHA1_96, "default_salt".to_owned());
        let (encryption_type, salt) = match as_rep
            .0
            .padata
            .0
            .map(|v| {
                v.0 .0
                    .iter()
                    .find(|e| e.padata_type.0 .0 == PA_ETYPE_INFO2_TYPE)
                    .map(|pa_data| pa_data.padata_data.0 .0.clone())
            })
            .unwrap_or_default()
        {
            Some(data) => {
                let pa_etype_into2: EtypeInfo2 = picky_asn1_der::from_bytes(&data).unwrap();
                let pa_etype_into2 = &pa_etype_into2.0[0];
                (
                    pa_etype_into2
                        .etype
                        .0
                         .0
                        .get(0)
                        .copied()
                        .unwrap_or(default_encryption_params.0),
                    pa_etype_into2
                        .salt
                        .0
                        .as_ref()
                        .map(|salt| salt.0.to_string())
                        .unwrap_or(default_encryption_params.1),
                )
            }
            None => default_encryption_params,
        };

        println!("{:?}", (encryption_type, &salt));

        let encrypted_data = as_rep.0.enc_part.0;
        let encrypted_bytes = encrypted_data.cipher.0 .0.to_vec();
        println!("{:?}", encrypted_data);

        let password = "qweQWE123!@#";

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        let salt = salt.as_bytes().to_vec();
        let key = cipher.generate_key_from_string(password, &salt);

        let enc_data = cipher.decrypt(&key, 3, &encrypted_bytes).unwrap();
        let enc_as_rep_part: EncAsRepPart = picky_asn1_der::from_bytes(&enc_data).unwrap();
        println!("{:?}", enc_as_rep_part);

        let key = enc_as_rep_part.0.key.0.key_value.0.to_vec();
        println!("key: {:?}", key);

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        // let key = cipher.generate_key(&key, &[]);
        // let key = cipher.generate_key_from_string(password, &salt);

        let bytes_to_decrypt = as_rep.0.ticket.0 .0.enc_part.0.cipher.0.to_vec();
        let res = cipher.decrypt(&key, 2, &bytes_to_decrypt);
        println!("{:?}", res);
    }

    #[test]
    fn test_decrypt() {
        let data = [
            // 222, 78, 54, 106, 163, 99, 116, 34, 62, 165, 147, 233, 243, 229, 153, 163, 53, 120, 94,
            // 84, 22, 147, 149, 69, 183, 85, 217, 65, 44, 191, 20, 199, 131, 58, 65, 125, 23, 180,
            // 245, 77, 236, 204, 237, 241, 213, 182, 169, 79, 224, 125, 116, 77, 160, 94, 182, 58,
            // 23, 41, 132, 248, 51, 119, 198, 13, 215, 224, 216, 181, 216, 246, 180, 252, 177, 188,
            // 168, 94, 210, 128, 54, 51, 87, 0, 122, 81, 97, 175, 9, 115, 182, 254, 170, 99, 99, 82,
            // 81, 126, 29, 134, 50, 159, 225, 200, 238, 165, 169, 208, 104, 109,
            137, 225, 150, 154, 3, 231, 152, 153, 52, 26, 171, 190, 130, 78, 140, 54, 135, 6, 88,
            30, 19, 180, 175, 254, 194, 145, 161, 97, 219, 48, 199, 113, 127, 93, 9, 247, 128, 174,
            136, 17, 42, 251, 10, 54, 217, 220, 90, 191, 27, 222, 17, 62, 25, 123, 54, 118, 8, 186,
            188, 59, 91, 44, 37, 251, 25, 158, 192, 45, 201, 100, 164, 90, 199, 213, 130, 248, 105,
            112, 164, 39, 151, 191, 0, 186, 132, 224, 251, 247, 197, 224, 211, 15, 19, 149, 193,
            228, 217, 178, 115, 187, 192, 22, 196, 89, 93, 42, 122, 91, 75, 195, 92, 94, 201, 98,
            24, 75, 221, 214, 140, 51, 105, 92, 204, 63, 81, 17, 80, 44, 220, 55, 240,
        ];

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        let key = [
            123, 1, 199, 50, 69, 191, 115, 74, 78, 170, 106, 186, 85, 77, 161, 84, 2, 117, 197, 70,
            227, 117, 54, 40, 188, 195, 0, 27, 84, 147, 205, 116,
        ];

        // 4
        let res = cipher.decrypt(&key, 7, &data).unwrap();
        println!("res: {:?}", res);
    }

    #[test]
    fn _test_decrypt_2() {
        let data = [
            22, 99, 28, 26, 178, 166, 166, 53, 171, 245, 198, 178, 94, 168, 21, 60, 76, 178, 62,
            181, 0, 96, 235, 118, 249, 79, 142, 243, 95, 225, 44, 43, 17, 165, 26, 185, 25, 233,
            190, 236, 168, 211, 70, 222, 203, 114, 33, 251, 232, 242, 160, 224, 189, 204, 10, 216,
            10, 39, 51, 145, 177, 219, 107, 182, 124, 145, 157, 78, 142, 118, 240, 250, 247, 195,
            5, 117, 35, 34, 47, 106, 110, 139, 16, 178, 4, 225, 154, 9, 10, 183, 138, 230, 47, 169,
            16, 199, 99, 24, 213, 119, 163, 75, 158, 233, 214, 0, 231, 37, 244, 101, 154, 37, 142,
            206, 231, 28, 76, 57, 232, 140, 51, 105, 190, 139, 133, 159, 148, 241, 255, 20, 109,
            52, 27, 58, 98, 231, 210, 124, 36, 58, 122, 173, 130, 119, 16, 55, 129, 144, 11, 127,
            31, 114, 174, 135, 101, 35, 17, 128, 218, 184, 32, 159, 209, 58, 223, 166, 190, 113,
            223, 45, 218, 48, 154, 119, 20, 145, 189, 94, 1, 140, 186, 15, 80, 41, 148, 170, 144,
            40, 207, 17, 111, 240, 191, 48, 22, 221, 149, 6, 110, 97, 183, 102, 213, 27, 206, 82,
            205, 187, 163, 225, 226, 84, 234, 209, 59, 149, 217, 113, 160, 210, 76, 50, 203, 75,
            197, 151, 47, 230, 19, 29, 75, 147, 56, 220, 213, 110, 206, 243, 11, 168, 90, 38, 210,
            57, 7, 90, 184, 77, 221, 38, 143, 31, 78, 92, 159, 139, 48, 88, 82, 12, 77, 203, 72,
            196, 15, 4, 181, 152, 26, 184, 114, 84, 185, 73, 206, 1, 109, 99, 11, 40, 238, 188,
            248, 131, 42, 98, 251, 52, 170, 61, 107, 112, 0, 199, 50, 19, 85, 134, 22, 253, 99,
            133, 185, 255, 70, 201, 132, 98, 178, 148, 220, 34, 111, 33, 209, 52, 53, 185, 181,
            241, 212, 26, 76,
        ];

        let password = "qweQWE123!@#";

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        let key = cipher.generate_key_from_string(password, "QKATION.COMw82".as_bytes());

        let enc_data = cipher.decrypt(&key, 3, &data).unwrap();

        let enc_as_rep_part: EncAsRepPart = picky_asn1_der::from_bytes(&enc_data).unwrap();
        println!("{:?}", enc_as_rep_part);

        let key = enc_as_rep_part.0.key.0.key_value.0.to_vec();
        println!("key: {:?}", key);
    }

    #[test]
    fn sk() {
        let data = [
            107, 130, 5, 150, 48, 130, 5, 146, 160, 3, 2, 1, 5, 161, 3, 2, 1, 11, 162, 40, 48, 38,
            48, 36, 161, 3, 2, 1, 19, 162, 29, 4, 27, 48, 25, 48, 23, 160, 3, 2, 1, 18, 161, 16,
            27, 14, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 119, 56, 51, 163, 13, 27, 11, 81,
            75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 164, 16, 48, 14, 160, 3, 2, 1, 1, 161, 7, 48,
            5, 27, 3, 119, 56, 51, 165, 130, 3, 251, 97, 130, 3, 247, 48, 130, 3, 243, 160, 3, 2,
            1, 5, 161, 13, 27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 32, 48, 30,
            160, 3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 81, 75,
            65, 84, 73, 79, 78, 46, 67, 79, 77, 163, 130, 3, 185, 48, 130, 3, 181, 160, 3, 2, 1,
            18, 161, 3, 2, 1, 2, 162, 130, 3, 167, 4, 130, 3, 163, 87, 248, 168, 212, 222, 83, 202,
            90, 84, 108, 187, 135, 214, 116, 68, 184, 161, 141, 47, 234, 3, 170, 89, 95, 88, 41,
            217, 71, 197, 208, 84, 216, 240, 229, 90, 146, 234, 102, 255, 56, 144, 228, 35, 30,
            151, 167, 157, 183, 191, 52, 144, 1, 179, 110, 207, 176, 30, 228, 40, 94, 216, 74, 186,
            136, 43, 6, 219, 160, 208, 192, 184, 60, 68, 128, 122, 203, 213, 149, 21, 45, 47, 171,
            180, 33, 250, 189, 0, 255, 22, 118, 24, 228, 144, 167, 111, 120, 54, 204, 93, 224, 61,
            197, 75, 20, 237, 104, 16, 164, 178, 120, 157, 33, 213, 214, 0, 253, 100, 65, 83, 38,
            193, 66, 139, 216, 250, 128, 251, 56, 194, 197, 169, 180, 240, 40, 127, 221, 99, 231,
            30, 201, 190, 99, 41, 132, 16, 65, 45, 200, 153, 80, 246, 136, 118, 125, 36, 250, 20,
            39, 52, 226, 57, 184, 46, 22, 34, 168, 69, 216, 29, 197, 71, 118, 228, 3, 30, 170, 65,
            191, 24, 37, 228, 241, 242, 176, 113, 15, 185, 232, 246, 222, 230, 6, 154, 100, 61,
            232, 160, 152, 254, 12, 249, 251, 77, 140, 83, 242, 99, 30, 77, 95, 123, 191, 55, 0,
            118, 200, 145, 210, 163, 138, 248, 7, 38, 229, 234, 191, 124, 23, 248, 221, 131, 211,
            48, 64, 235, 94, 217, 212, 66, 26, 171, 205, 123, 210, 82, 180, 98, 96, 197, 197, 92,
            178, 111, 133, 146, 118, 63, 224, 15, 230, 0, 6, 23, 240, 96, 113, 114, 143, 233, 208,
            182, 216, 42, 210, 96, 17, 32, 213, 58, 195, 250, 69, 90, 243, 119, 64, 22, 30, 184,
            117, 218, 200, 130, 101, 65, 194, 57, 163, 125, 250, 10, 147, 72, 97, 153, 98, 117,
            103, 47, 240, 249, 221, 102, 115, 250, 33, 29, 122, 214, 244, 93, 151, 120, 111, 95,
            185, 217, 48, 5, 201, 230, 7, 195, 40, 17, 172, 81, 208, 197, 202, 102, 186, 19, 143,
            150, 147, 140, 96, 10, 64, 98, 112, 28, 4, 107, 254, 176, 116, 89, 36, 109, 19, 34,
            244, 57, 70, 77, 92, 162, 180, 27, 226, 232, 7, 119, 210, 221, 224, 161, 106, 77, 55,
            175, 30, 166, 251, 179, 92, 109, 39, 165, 104, 154, 251, 226, 134, 60, 20, 108, 233,
            220, 103, 221, 50, 46, 140, 95, 223, 10, 32, 244, 187, 17, 18, 186, 241, 67, 235, 99,
            14, 6, 239, 202, 183, 124, 120, 155, 255, 128, 62, 32, 194, 196, 11, 217, 129, 218, 49,
            243, 105, 34, 213, 13, 177, 95, 90, 156, 144, 90, 65, 34, 217, 186, 242, 37, 139, 2,
            109, 53, 112, 23, 86, 165, 214, 203, 99, 146, 84, 117, 240, 11, 208, 50, 158, 203, 247,
            232, 205, 246, 95, 111, 35, 155, 112, 199, 53, 168, 173, 198, 160, 85, 113, 243, 242,
            8, 158, 27, 30, 189, 223, 156, 1, 74, 106, 151, 86, 177, 78, 16, 36, 210, 217, 68, 98,
            100, 166, 250, 243, 13, 169, 27, 227, 44, 206, 41, 232, 25, 194, 248, 186, 88, 82, 84,
            196, 156, 77, 158, 233, 13, 170, 147, 173, 75, 190, 68, 105, 87, 162, 241, 104, 18,
            139, 149, 243, 131, 188, 63, 162, 66, 147, 76, 209, 153, 65, 8, 206, 40, 106, 72, 197,
            37, 185, 9, 44, 21, 31, 182, 23, 208, 57, 175, 21, 47, 128, 72, 196, 226, 233, 219,
            190, 248, 233, 68, 169, 181, 201, 235, 83, 37, 210, 254, 109, 159, 57, 99, 106, 119,
            21, 215, 43, 124, 222, 207, 109, 94, 254, 139, 137, 154, 26, 243, 66, 180, 138, 91, 5,
            192, 48, 180, 196, 168, 20, 234, 140, 46, 206, 147, 254, 235, 174, 145, 79, 26, 58,
            206, 76, 92, 56, 22, 114, 37, 68, 167, 232, 89, 53, 25, 147, 145, 153, 51, 38, 154,
            255, 178, 209, 33, 13, 179, 94, 68, 61, 193, 110, 250, 36, 226, 17, 125, 119, 219, 197,
            251, 19, 118, 243, 147, 161, 251, 221, 130, 234, 35, 136, 19, 94, 84, 94, 239, 136,
            140, 224, 32, 234, 57, 42, 228, 146, 4, 177, 47, 221, 50, 36, 251, 96, 175, 154, 91,
            84, 135, 235, 52, 202, 205, 55, 42, 247, 189, 86, 160, 134, 98, 135, 65, 3, 48, 31,
            125, 190, 246, 152, 149, 137, 108, 76, 12, 131, 125, 190, 250, 212, 177, 188, 167, 198,
            175, 35, 20, 30, 107, 219, 201, 7, 185, 223, 203, 164, 56, 185, 75, 4, 239, 76, 74,
            239, 161, 102, 160, 129, 24, 203, 189, 224, 173, 129, 197, 137, 144, 154, 236, 208,
            114, 200, 240, 110, 71, 238, 205, 82, 142, 172, 170, 134, 145, 107, 199, 195, 253, 74,
            173, 138, 51, 94, 122, 128, 26, 68, 251, 177, 51, 14, 77, 74, 40, 236, 135, 176, 59,
            72, 14, 133, 85, 11, 189, 241, 132, 48, 102, 9, 4, 105, 78, 129, 105, 60, 85, 216, 164,
            13, 148, 175, 80, 62, 179, 64, 214, 76, 81, 129, 250, 140, 211, 98, 35, 2, 25, 204,
            108, 71, 200, 129, 130, 171, 201, 178, 152, 245, 28, 52, 40, 221, 41, 90, 227, 4, 90,
            25, 49, 206, 155, 166, 100, 127, 169, 120, 48, 192, 223, 244, 161, 248, 165, 66, 118,
            190, 171, 137, 135, 181, 4, 52, 234, 205, 208, 165, 202, 6, 172, 248, 210, 126, 254,
            45, 51, 132, 22, 133, 115, 70, 134, 166, 130, 1, 58, 48, 130, 1, 54, 160, 3, 2, 1, 18,
            161, 3, 2, 1, 2, 162, 130, 1, 40, 4, 130, 1, 36, 222, 191, 15, 102, 145, 49, 150, 76,
            132, 200, 228, 243, 237, 136, 172, 101, 196, 143, 19, 0, 37, 51, 62, 5, 135, 76, 24,
            39, 17, 184, 233, 197, 121, 164, 152, 49, 78, 252, 168, 112, 79, 154, 149, 109, 153,
            59, 178, 196, 110, 62, 217, 232, 158, 207, 118, 145, 236, 39, 5, 14, 248, 225, 50, 177,
            153, 206, 182, 74, 139, 251, 221, 141, 77, 253, 149, 28, 178, 34, 120, 12, 240, 215,
            44, 127, 238, 216, 95, 170, 100, 220, 32, 194, 149, 49, 174, 90, 114, 189, 19, 237, 87,
            7, 229, 212, 104, 238, 9, 139, 158, 88, 26, 151, 196, 102, 157, 156, 187, 71, 121, 216,
            145, 169, 191, 146, 96, 72, 73, 43, 135, 183, 65, 150, 130, 169, 53, 241, 60, 38, 93,
            171, 228, 188, 72, 29, 31, 34, 205, 138, 188, 31, 57, 223, 29, 173, 226, 51, 69, 186,
            84, 101, 153, 44, 224, 39, 80, 92, 86, 3, 26, 62, 62, 239, 105, 110, 255, 41, 79, 158,
            90, 119, 18, 5, 138, 247, 176, 51, 227, 13, 76, 181, 219, 112, 130, 216, 167, 226, 231,
            186, 225, 145, 144, 129, 109, 122, 217, 239, 65, 131, 38, 177, 142, 116, 139, 109, 139,
            133, 241, 18, 134, 53, 243, 191, 184, 149, 108, 199, 15, 209, 225, 2, 76, 49, 221, 165,
            18, 54, 0, 54, 137, 75, 124, 159, 95, 106, 123, 118, 175, 113, 158, 252, 176, 26, 105,
            254, 178, 116, 80, 24, 46, 3, 182, 139, 223, 75, 46, 34, 104, 1, 227, 143, 32, 83, 30,
            129, 201, 194, 243, 125, 83, 168, 213, 160, 206, 113, 131, 137, 5, 92, 6, 131, 238, 1,
        ];

        let as_rep: AsRep = picky_asn1_der::from_bytes(&data).unwrap();
        let (_, salt) = extract_encryption_params_from_as_rep(&as_rep).unwrap();
        let session_key = extract_session_key_from_as_rep(&as_rep, &salt, "qweQWE123!@#");
        println!("{:?}", session_key);
    }

    #[test]
    fn test_tgs_rep_parsing() {
        let data = [
            109, 130, 5, 109, 48, 130, 5, 105, 160, 3, 2, 1, 5, 161, 3, 2, 1, 13, 163, 13, 27, 11,
            81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 164, 16, 48, 14, 160, 3, 2, 1, 1, 161, 7,
            48, 5, 27, 3, 119, 56, 51, 165, 130, 4, 13, 97, 130, 4, 9, 48, 130, 4, 5, 160, 3, 2, 1,
            5, 161, 13, 27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 37, 48, 35, 160,
            3, 2, 1, 2, 161, 28, 48, 26, 27, 7, 84, 69, 82, 77, 83, 82, 86, 27, 15, 119, 56, 51,
            46, 113, 107, 97, 116, 105, 111, 110, 46, 99, 111, 109, 163, 130, 3, 198, 48, 130, 3,
            194, 160, 3, 2, 1, 18, 161, 3, 2, 1, 2, 162, 130, 3, 180, 4, 130, 3, 176, 161, 51, 98,
            59, 16, 238, 224, 38, 4, 97, 205, 94, 135, 112, 52, 7, 157, 77, 2, 227, 215, 69, 62,
            131, 115, 218, 179, 227, 88, 105, 3, 196, 234, 37, 217, 67, 109, 154, 9, 252, 142, 29,
            101, 219, 103, 82, 84, 129, 32, 27, 12, 233, 3, 164, 217, 20, 82, 225, 209, 88, 20, 89,
            38, 200, 245, 12, 3, 212, 232, 67, 102, 207, 2, 181, 192, 240, 77, 214, 92, 122, 155,
            195, 84, 52, 5, 100, 65, 12, 140, 225, 77, 133, 209, 252, 166, 247, 71, 123, 42, 46,
            81, 35, 134, 219, 60, 19, 54, 69, 16, 199, 76, 58, 222, 68, 35, 70, 39, 163, 156, 144,
            35, 196, 200, 1, 223, 202, 131, 4, 13, 162, 212, 32, 1, 118, 18, 81, 39, 40, 232, 194,
            214, 146, 0, 70, 214, 205, 183, 218, 95, 171, 255, 70, 80, 224, 147, 153, 123, 148,
            229, 149, 133, 26, 110, 48, 110, 153, 198, 125, 108, 87, 234, 28, 10, 102, 192, 232,
            43, 196, 47, 171, 169, 56, 176, 16, 92, 212, 234, 51, 114, 164, 51, 39, 58, 165, 201,
            173, 110, 184, 54, 152, 66, 69, 32, 29, 200, 178, 204, 36, 41, 134, 182, 56, 56, 234,
            1, 199, 112, 60, 190, 97, 32, 117, 163, 206, 56, 160, 212, 4, 138, 187, 245, 112, 212,
            242, 38, 39, 96, 217, 220, 76, 153, 154, 38, 91, 239, 109, 73, 107, 197, 245, 224, 189,
            250, 170, 247, 11, 147, 23, 232, 200, 12, 234, 143, 236, 55, 86, 96, 193, 44, 19, 40,
            54, 170, 94, 150, 227, 113, 160, 89, 15, 69, 11, 137, 243, 51, 176, 101, 106, 111, 156,
            28, 89, 42, 181, 95, 60, 8, 62, 114, 97, 84, 103, 69, 104, 247, 99, 164, 254, 17, 159,
            230, 79, 242, 163, 165, 179, 4, 207, 80, 26, 43, 202, 69, 48, 74, 155, 22, 58, 40, 87,
            147, 253, 197, 104, 195, 3, 0, 30, 191, 62, 97, 123, 101, 33, 49, 7, 69, 214, 21, 125,
            37, 78, 158, 122, 43, 69, 177, 137, 180, 95, 32, 158, 71, 253, 217, 15, 209, 67, 200,
            86, 242, 197, 16, 180, 63, 191, 137, 156, 2, 121, 243, 121, 75, 170, 83, 120, 54, 148,
            54, 69, 60, 48, 12, 182, 17, 129, 9, 49, 56, 116, 14, 84, 177, 142, 75, 194, 85, 163,
            231, 74, 124, 255, 231, 150, 224, 0, 241, 83, 41, 228, 10, 20, 158, 206, 101, 250, 225,
            161, 37, 216, 127, 92, 75, 132, 176, 219, 217, 248, 28, 162, 226, 165, 245, 82, 103,
            255, 115, 107, 190, 88, 98, 52, 127, 1, 40, 184, 31, 29, 186, 150, 179, 126, 190, 6,
            148, 202, 25, 54, 63, 104, 182, 103, 36, 119, 200, 133, 148, 12, 49, 17, 141, 41, 68,
            5, 41, 159, 201, 166, 252, 127, 204, 115, 193, 244, 114, 143, 130, 217, 0, 192, 239,
            129, 211, 35, 150, 98, 14, 22, 115, 245, 107, 9, 135, 226, 238, 41, 88, 4, 177, 147, 9,
            97, 207, 125, 189, 22, 138, 13, 132, 150, 114, 205, 79, 66, 247, 123, 109, 156, 161,
            113, 170, 11, 224, 214, 193, 197, 49, 57, 158, 113, 36, 90, 236, 226, 250, 229, 86, 73,
            246, 2, 40, 28, 84, 208, 140, 251, 11, 66, 123, 129, 90, 49, 120, 58, 111, 163, 51,
            108, 206, 146, 246, 198, 96, 200, 117, 110, 15, 49, 226, 72, 241, 164, 10, 177, 17,
            126, 49, 223, 162, 140, 130, 55, 210, 84, 17, 168, 158, 209, 25, 38, 134, 148, 79, 200,
            61, 179, 18, 118, 126, 112, 170, 230, 247, 252, 76, 74, 14, 226, 119, 61, 152, 174,
            144, 62, 170, 10, 9, 139, 28, 28, 224, 174, 240, 248, 191, 21, 95, 109, 150, 218, 250,
            180, 93, 39, 134, 131, 199, 83, 244, 93, 164, 119, 209, 25, 39, 3, 54, 24, 74, 8, 146,
            166, 22, 72, 67, 168, 84, 167, 175, 132, 243, 150, 139, 99, 63, 242, 218, 27, 173, 8,
            15, 37, 54, 150, 30, 25, 86, 178, 105, 231, 106, 25, 16, 253, 2, 130, 216, 60, 50, 235,
            215, 46, 40, 3, 196, 215, 61, 217, 251, 91, 131, 118, 22, 215, 175, 83, 207, 78, 94,
            39, 0, 229, 21, 100, 120, 117, 102, 250, 115, 114, 50, 211, 246, 145, 247, 163, 254,
            180, 204, 191, 64, 96, 130, 95, 44, 190, 108, 44, 173, 210, 89, 90, 184, 121, 70, 139,
            144, 90, 191, 25, 92, 127, 50, 155, 169, 141, 33, 169, 27, 111, 52, 94, 198, 56, 234,
            81, 81, 50, 145, 157, 215, 95, 192, 152, 74, 116, 215, 164, 76, 16, 108, 137, 245, 101,
            30, 255, 93, 245, 81, 118, 155, 37, 84, 233, 83, 245, 15, 113, 45, 197, 206, 136, 25,
            54, 242, 134, 118, 197, 17, 224, 121, 115, 73, 146, 248, 142, 161, 139, 198, 14, 203,
            73, 204, 91, 153, 143, 17, 142, 235, 84, 45, 96, 127, 150, 45, 124, 90, 210, 61, 11,
            192, 53, 235, 94, 21, 6, 193, 109, 34, 222, 19, 226, 1, 158, 242, 249, 139, 95, 48, 32,
            138, 226, 232, 214, 179, 37, 215, 229, 252, 232, 36, 67, 13, 24, 168, 124, 98, 155,
            252, 89, 91, 240, 181, 156, 92, 172, 36, 183, 204, 143, 241, 183, 244, 51, 36, 104,
            111, 30, 254, 78, 163, 243, 129, 121, 241, 146, 194, 16, 104, 0, 243, 116, 87, 70, 76,
            234, 181, 62, 245, 41, 159, 6, 132, 130, 166, 130, 1, 41, 48, 130, 1, 37, 160, 3, 2, 1,
            18, 162, 130, 1, 28, 4, 130, 1, 24, 43, 39, 37, 183, 52, 176, 30, 146, 25, 227, 195,
            111, 50, 65, 50, 109, 55, 184, 66, 38, 207, 77, 153, 117, 142, 42, 1, 66, 204, 235,
            147, 204, 3, 160, 237, 153, 189, 247, 98, 240, 154, 59, 27, 168, 18, 173, 189, 24, 159,
            147, 235, 242, 133, 144, 231, 220, 96, 129, 98, 35, 247, 173, 121, 10, 249, 150, 159,
            76, 176, 139, 196, 29, 224, 147, 14, 127, 103, 12, 38, 123, 252, 197, 198, 11, 174,
            150, 67, 19, 106, 15, 234, 45, 104, 166, 110, 186, 58, 65, 89, 59, 49, 195, 173, 153,
            33, 50, 252, 82, 240, 65, 181, 90, 184, 33, 251, 241, 97, 255, 122, 31, 38, 62, 182,
            127, 188, 135, 104, 37, 82, 61, 24, 120, 208, 177, 182, 60, 253, 130, 80, 49, 192, 246,
            216, 167, 93, 255, 43, 253, 138, 161, 86, 195, 67, 154, 101, 21, 53, 68, 177, 175, 177,
            247, 146, 189, 85, 102, 174, 32, 33, 53, 199, 114, 229, 153, 181, 82, 161, 42, 3, 175,
            234, 54, 2, 104, 32, 31, 61, 65, 130, 169, 80, 79, 42, 120, 133, 50, 83, 81, 120, 130,
            45, 218, 98, 143, 29, 255, 136, 130, 35, 21, 80, 13, 196, 87, 110, 86, 6, 207, 169, 59,
            141, 54, 252, 66, 92, 85, 245, 124, 100, 26, 1, 168, 145, 213, 1, 22, 45, 72, 57, 180,
            86, 98, 230, 251, 165, 41, 3, 78, 205, 145, 30, 50, 232, 79, 8, 151, 233, 201, 6, 80,
            235, 221, 237, 120, 115, 206, 192, 119, 245, 197, 124, 129, 22, 178, 204, 6, 244, 187,
            164, 232,
        ];

        let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&data).unwrap();
        println!("{:?}", tgs_rep);

        let cipher_data = tgs_rep.0.enc_part.cipher.0.to_vec();

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        let sk1 = [
            46, 172, 198, 208, 166, 243, 55, 242, 10, 31, 89, 135, 247, 246, 74, 38, 226, 51, 128,
            15, 91, 33, 70, 62, 165, 91, 20, 51, 133, 39, 203, 27,
        ];

        let res = cipher.decrypt(&sk1, 8, &cipher_data).unwrap();
        let enc_part: EncTgsRepPart = picky_asn1_der::from_bytes(&res).unwrap();
        println!("res: {:?}", res);
        println!("res: {:?}", enc_part);

        let sk2 = enc_part.0.key.0.key_value.0.to_vec();
        println!("session key 2: {:?}", sk2);

        let cipher_data = tgs_rep.0.ticket.0 .0.enc_part.0.cipher.0.to_vec();
        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

        for i in 1..100 {
            println!("{:?}", cipher.decrypt(&sk1, i, &cipher_data));
        }

        // let res = cipher.decrypt(&sk2, 2, &cipher_data).unwrap();
        // println!("unencrypted ticket: {:?}", res);
    }

    #[test]
    fn try_decrypt_ap_req_auth() {
        let password = "qweQWE123!@#";

        let as_rep = [
            107, 130, 5, 170, 48, 130, 5, 166, 160, 3, 2, 1, 5, 161, 3, 2, 1, 11, 162, 39, 48, 37,
            48, 35, 161, 3, 2, 1, 19, 162, 28, 4, 26, 48, 24, 48, 22, 160, 3, 2, 1, 18, 161, 15,
            27, 13, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 112, 51, 163, 13, 27, 11, 81, 75,
            65, 84, 73, 79, 78, 46, 67, 79, 77, 164, 15, 48, 13, 160, 3, 2, 1, 1, 161, 6, 48, 4,
            27, 2, 112, 51, 165, 130, 3, 242, 97, 130, 3, 238, 48, 130, 3, 234, 160, 3, 2, 1, 5,
            161, 13, 27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 32, 48, 30, 160, 3,
            2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 81, 75, 65, 84,
            73, 79, 78, 46, 67, 79, 77, 163, 130, 3, 176, 48, 130, 3, 172, 160, 3, 2, 1, 18, 161,
            3, 2, 1, 2, 162, 130, 3, 158, 4, 130, 3, 154, 132, 189, 201, 154, 32, 228, 131, 69, 86,
            62, 215, 104, 2, 54, 44, 242, 75, 159, 6, 237, 140, 0, 223, 0, 97, 58, 26, 130, 127,
            68, 152, 19, 28, 210, 11, 131, 204, 89, 51, 128, 136, 60, 132, 148, 188, 225, 255, 36,
            209, 11, 165, 103, 155, 194, 103, 206, 168, 131, 32, 196, 208, 29, 38, 55, 11, 147,
            115, 5, 8, 100, 157, 191, 204, 170, 131, 143, 7, 31, 143, 195, 116, 233, 235, 85, 251,
            123, 100, 245, 90, 108, 253, 81, 44, 97, 249, 178, 56, 232, 89, 249, 90, 30, 105, 29,
            220, 35, 147, 119, 65, 39, 250, 9, 227, 185, 186, 87, 5, 31, 90, 237, 29, 199, 176,
            210, 218, 225, 57, 211, 171, 69, 119, 223, 248, 185, 191, 237, 141, 152, 34, 118, 4,
            202, 188, 20, 18, 208, 1, 19, 4, 91, 22, 14, 33, 208, 203, 26, 143, 159, 77, 156, 161,
            108, 52, 131, 219, 133, 47, 23, 181, 7, 200, 161, 244, 137, 8, 145, 75, 244, 239, 132,
            240, 182, 135, 14, 252, 121, 126, 221, 21, 165, 175, 167, 88, 239, 50, 154, 148, 140,
            177, 110, 1, 192, 189, 212, 174, 26, 87, 148, 233, 237, 90, 49, 242, 14, 24, 33, 113,
            130, 131, 166, 4, 12, 151, 149, 51, 226, 250, 86, 119, 101, 243, 227, 220, 50, 221,
            229, 85, 135, 102, 111, 97, 159, 146, 35, 131, 253, 89, 239, 124, 185, 224, 133, 152,
            197, 199, 79, 201, 51, 39, 74, 46, 182, 23, 17, 92, 71, 122, 110, 44, 181, 79, 230,
            148, 71, 81, 163, 74, 154, 123, 158, 243, 149, 22, 121, 156, 128, 192, 24, 34, 147, 10,
            180, 0, 254, 69, 49, 197, 214, 178, 221, 3, 176, 242, 223, 123, 162, 172, 202, 89, 151,
            253, 78, 91, 83, 21, 19, 48, 95, 238, 59, 226, 109, 229, 102, 214, 125, 180, 36, 88,
            179, 2, 171, 126, 225, 235, 193, 251, 96, 100, 183, 25, 123, 129, 83, 43, 233, 231, 45,
            4, 64, 125, 54, 221, 226, 204, 49, 232, 52, 153, 6, 200, 65, 162, 154, 208, 227, 209,
            227, 23, 177, 90, 255, 126, 239, 35, 115, 52, 251, 130, 86, 26, 236, 206, 176, 200, 5,
            135, 85, 148, 192, 64, 229, 220, 22, 86, 52, 144, 187, 130, 35, 149, 236, 126, 245,
            224, 170, 34, 112, 9, 13, 37, 200, 91, 232, 81, 240, 166, 242, 98, 231, 28, 222, 69,
            138, 3, 231, 129, 147, 129, 51, 146, 74, 238, 158, 185, 135, 190, 73, 149, 15, 207, 82,
            153, 17, 52, 110, 113, 165, 32, 0, 195, 220, 233, 121, 240, 160, 216, 242, 5, 17, 173,
            25, 233, 238, 188, 1, 109, 7, 180, 167, 252, 225, 115, 230, 142, 68, 66, 68, 180, 121,
            190, 238, 65, 137, 116, 95, 29, 226, 52, 100, 76, 0, 135, 73, 166, 27, 114, 115, 124,
            232, 169, 141, 116, 25, 175, 195, 122, 209, 229, 49, 113, 212, 171, 13, 231, 237, 246,
            253, 158, 16, 75, 248, 50, 95, 214, 146, 100, 251, 2, 6, 234, 96, 94, 74, 129, 4, 204,
            104, 186, 34, 96, 158, 16, 156, 133, 252, 30, 243, 83, 51, 165, 96, 203, 36, 245, 145,
            130, 197, 139, 136, 134, 235, 30, 72, 180, 209, 5, 75, 206, 254, 233, 116, 243, 2, 202,
            227, 114, 156, 197, 246, 77, 240, 80, 90, 168, 169, 236, 207, 71, 216, 228, 219, 211,
            102, 36, 10, 30, 97, 164, 29, 70, 190, 160, 64, 123, 104, 131, 68, 92, 116, 173, 52,
            193, 89, 55, 222, 231, 99, 24, 9, 123, 177, 16, 130, 21, 175, 198, 241, 70, 26, 47,
            160, 215, 178, 98, 102, 108, 164, 102, 87, 27, 51, 105, 206, 170, 51, 20, 229, 170, 30,
            123, 42, 48, 133, 185, 201, 65, 224, 201, 1, 61, 167, 45, 125, 207, 53, 37, 123, 199,
            31, 35, 86, 82, 67, 98, 74, 132, 71, 241, 30, 102, 104, 121, 215, 135, 12, 100, 31,
            141, 230, 109, 252, 83, 77, 197, 155, 54, 98, 9, 116, 55, 162, 154, 42, 151, 98, 111,
            247, 161, 239, 226, 18, 73, 79, 230, 5, 133, 56, 52, 181, 154, 249, 27, 48, 8, 39, 182,
            77, 220, 15, 22, 154, 60, 182, 171, 172, 241, 188, 190, 237, 150, 148, 233, 181, 246,
            69, 215, 209, 105, 74, 231, 176, 8, 120, 189, 165, 231, 170, 10, 255, 32, 132, 2, 177,
            166, 180, 102, 106, 66, 144, 125, 200, 1, 87, 19, 98, 69, 138, 111, 85, 5, 244, 170,
            180, 74, 38, 26, 139, 110, 104, 143, 3, 243, 6, 103, 143, 146, 45, 6, 106, 138, 144,
            58, 147, 246, 3, 123, 210, 118, 206, 146, 25, 205, 153, 53, 192, 217, 8, 104, 130, 110,
            114, 76, 64, 227, 231, 15, 121, 231, 75, 8, 209, 174, 114, 242, 120, 140, 99, 109, 42,
            139, 140, 213, 153, 183, 228, 97, 189, 206, 64, 224, 53, 18, 188, 198, 133, 60, 113,
            137, 61, 103, 210, 109, 12, 18, 185, 96, 141, 96, 141, 214, 183, 70, 144, 61, 47, 131,
            160, 94, 56, 156, 11, 30, 252, 121, 113, 105, 76, 184, 173, 4, 135, 40, 40, 99, 106,
            71, 226, 58, 250, 140, 133, 164, 203, 110, 208, 62, 35, 84, 26, 78, 23, 237, 210, 193,
            108, 79, 17, 226, 15, 67, 151, 166, 130, 1, 89, 48, 130, 1, 85, 160, 3, 2, 1, 18, 161,
            3, 2, 1, 2, 162, 130, 1, 71, 4, 130, 1, 67, 137, 58, 103, 127, 148, 2, 39, 13, 141,
            206, 157, 126, 193, 223, 97, 104, 150, 34, 209, 154, 222, 177, 234, 215, 233, 230, 32,
            243, 37, 235, 72, 94, 239, 250, 44, 200, 18, 123, 36, 122, 253, 175, 161, 247, 141, 40,
            74, 236, 201, 117, 43, 74, 203, 100, 76, 119, 251, 179, 21, 140, 189, 50, 51, 164, 58,
            18, 230, 53, 154, 5, 92, 198, 159, 9, 120, 171, 251, 125, 198, 143, 226, 203, 204, 211,
            8, 101, 34, 114, 143, 214, 177, 9, 76, 51, 149, 99, 126, 215, 245, 23, 144, 70, 33, 34,
            77, 70, 156, 125, 207, 78, 189, 73, 105, 104, 175, 191, 106, 153, 122, 50, 36, 64, 244,
            1, 42, 123, 47, 37, 100, 242, 194, 145, 49, 150, 58, 46, 220, 103, 79, 85, 51, 245, 17,
            53, 87, 134, 117, 23, 49, 154, 13, 165, 247, 174, 184, 68, 210, 221, 134, 179, 2, 117,
            127, 154, 252, 9, 165, 157, 148, 149, 53, 247, 154, 138, 232, 72, 231, 185, 173, 132,
            110, 190, 65, 221, 148, 119, 117, 5, 77, 46, 131, 204, 47, 241, 216, 20, 51, 66, 42,
            43, 149, 111, 32, 36, 180, 109, 192, 134, 52, 183, 65, 207, 39, 20, 191, 223, 234, 28,
            54, 38, 230, 84, 37, 81, 131, 109, 162, 205, 63, 48, 206, 251, 51, 249, 211, 94, 223,
            65, 226, 198, 198, 169, 29, 91, 143, 101, 138, 71, 133, 36, 186, 197, 132, 36, 117, 88,
            68, 13, 235, 38, 66, 170, 55, 48, 38, 139, 142, 63, 233, 45, 60, 179, 197, 242, 71,
            215, 36, 185, 134, 79, 142, 15, 150, 163, 68, 194, 90, 150, 42, 253, 85, 180, 162, 14,
            62, 9, 11, 243, 8, 92, 242, 200, 50, 214, 48, 110, 175, 163, 72, 130, 6, 200, 249, 232,
            173, 101, 205, 5, 170, 170, 187, 175, 67,
        ];
        let tgs_rep_1 = [
            109, 130, 5, 175, 48, 130, 5, 171, 160, 3, 2, 1, 5, 161, 3, 2, 1, 13, 163, 13, 27, 11,
            81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 164, 15, 48, 13, 160, 3, 2, 1, 1, 161, 6,
            48, 4, 27, 2, 112, 51, 165, 130, 4, 81, 97, 130, 4, 77, 48, 130, 4, 73, 160, 3, 2, 1,
            5, 161, 13, 27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 36, 48, 34, 160,
            3, 2, 1, 2, 161, 27, 48, 25, 27, 7, 84, 69, 82, 77, 83, 82, 86, 27, 14, 112, 51, 46,
            113, 107, 97, 116, 105, 111, 110, 46, 99, 111, 109, 163, 130, 4, 11, 48, 130, 4, 7,
            160, 3, 2, 1, 18, 161, 3, 2, 1, 1, 162, 130, 3, 249, 4, 130, 3, 245, 170, 183, 210, 80,
            132, 103, 250, 88, 31, 244, 146, 43, 225, 119, 56, 250, 193, 110, 168, 186, 134, 215,
            26, 36, 39, 19, 158, 36, 108, 62, 122, 63, 235, 102, 135, 43, 53, 84, 250, 12, 188,
            210, 95, 100, 105, 47, 137, 187, 68, 8, 66, 76, 146, 89, 238, 217, 183, 42, 33, 93,
            236, 106, 221, 61, 13, 84, 129, 236, 242, 153, 210, 119, 183, 7, 91, 72, 57, 100, 97,
            147, 193, 232, 7, 100, 219, 3, 3, 169, 229, 188, 61, 4, 178, 237, 238, 98, 49, 28, 164,
            107, 217, 110, 43, 150, 214, 150, 248, 225, 111, 76, 69, 64, 240, 54, 184, 194, 142,
            70, 107, 151, 189, 165, 5, 84, 240, 244, 8, 106, 89, 142, 80, 151, 147, 2, 8, 1, 193,
            192, 185, 113, 104, 174, 63, 37, 137, 38, 226, 160, 188, 194, 202, 96, 150, 219, 215,
            7, 190, 241, 33, 81, 83, 118, 39, 162, 72, 160, 212, 99, 145, 32, 239, 48, 228, 252,
            74, 24, 18, 31, 22, 35, 4, 195, 49, 159, 231, 208, 116, 170, 34, 192, 158, 186, 239,
            223, 247, 163, 232, 71, 80, 6, 183, 20, 160, 53, 182, 75, 192, 227, 241, 4, 211, 86,
            105, 233, 86, 77, 28, 57, 154, 250, 141, 43, 254, 199, 175, 8, 186, 216, 228, 23, 154,
            64, 216, 227, 191, 27, 13, 203, 176, 161, 54, 185, 116, 109, 136, 95, 64, 108, 229, 95,
            241, 164, 243, 247, 15, 108, 4, 11, 193, 158, 188, 5, 206, 91, 60, 63, 238, 89, 69,
            131, 224, 136, 10, 221, 22, 74, 9, 99, 76, 104, 190, 216, 83, 237, 75, 123, 124, 254,
            27, 76, 9, 62, 218, 63, 252, 213, 170, 136, 180, 49, 140, 48, 60, 63, 187, 148, 186,
            24, 37, 237, 41, 121, 164, 170, 185, 116, 89, 69, 57, 215, 212, 29, 209, 177, 177, 143,
            144, 200, 184, 87, 12, 202, 14, 142, 206, 76, 190, 14, 156, 214, 73, 222, 255, 68, 156,
            139, 44, 250, 52, 168, 144, 69, 225, 248, 22, 34, 156, 46, 198, 84, 133, 234, 217, 58,
            235, 168, 160, 61, 35, 48, 56, 177, 226, 159, 82, 131, 195, 83, 185, 137, 21, 190, 119,
            186, 29, 211, 201, 63, 132, 167, 77, 56, 131, 203, 162, 194, 250, 62, 197, 187, 206,
            235, 238, 216, 185, 22, 232, 93, 195, 121, 57, 232, 178, 213, 142, 96, 184, 124, 255,
            232, 110, 75, 76, 204, 67, 201, 208, 192, 125, 144, 75, 151, 48, 239, 233, 219, 205,
            19, 88, 221, 190, 124, 138, 7, 125, 10, 5, 93, 129, 247, 3, 239, 17, 206, 20, 51, 145,
            124, 4, 247, 158, 12, 217, 84, 184, 34, 189, 252, 89, 208, 17, 157, 237, 137, 152, 116,
            239, 155, 90, 73, 181, 223, 100, 111, 59, 51, 111, 37, 235, 218, 14, 54, 20, 6, 34, 27,
            59, 84, 254, 123, 182, 119, 90, 189, 75, 163, 8, 86, 115, 190, 3, 215, 184, 11, 70,
            101, 21, 23, 138, 199, 237, 190, 151, 50, 146, 37, 167, 92, 142, 12, 62, 237, 43, 3,
            232, 47, 167, 178, 115, 191, 84, 35, 224, 88, 126, 233, 177, 16, 234, 206, 147, 150,
            26, 174, 38, 150, 103, 235, 80, 233, 250, 135, 156, 37, 6, 214, 152, 180, 64, 137, 72,
            224, 50, 153, 79, 24, 235, 210, 190, 27, 181, 254, 4, 10, 179, 173, 18, 228, 226, 132,
            12, 107, 146, 219, 154, 37, 72, 171, 211, 144, 165, 122, 172, 222, 92, 242, 18, 48,
            203, 60, 57, 77, 17, 119, 24, 22, 87, 114, 170, 195, 169, 111, 194, 52, 225, 122, 14,
            48, 182, 228, 65, 110, 160, 111, 29, 163, 76, 158, 66, 173, 171, 107, 11, 141, 207, 74,
            81, 192, 45, 68, 135, 21, 20, 84, 214, 153, 52, 116, 73, 253, 159, 159, 250, 182, 237,
            174, 34, 104, 197, 219, 58, 52, 117, 184, 201, 59, 8, 210, 21, 240, 105, 233, 236, 207,
            210, 87, 219, 162, 18, 148, 147, 152, 63, 145, 59, 48, 78, 109, 182, 155, 166, 34, 59,
            227, 36, 87, 59, 140, 0, 169, 153, 96, 9, 197, 218, 31, 196, 46, 79, 56, 101, 210, 202,
            94, 151, 244, 101, 146, 208, 213, 121, 249, 17, 7, 84, 250, 193, 176, 55, 252, 132, 87,
            218, 100, 112, 13, 93, 54, 77, 32, 164, 34, 136, 7, 48, 82, 180, 80, 63, 164, 180, 73,
            244, 10, 3, 6, 86, 155, 227, 246, 111, 213, 53, 240, 205, 74, 136, 35, 155, 84, 137,
            39, 42, 172, 73, 55, 130, 195, 154, 40, 197, 247, 98, 117, 126, 131, 212, 152, 223,
            168, 129, 137, 47, 103, 38, 208, 197, 146, 148, 176, 169, 225, 219, 168, 79, 139, 159,
            27, 57, 227, 22, 198, 232, 51, 40, 23, 79, 115, 31, 11, 42, 146, 3, 253, 152, 246, 42,
            248, 20, 116, 112, 127, 154, 100, 122, 36, 100, 182, 112, 201, 141, 20, 29, 63, 84, 13,
            23, 131, 155, 148, 144, 81, 124, 174, 187, 255, 45, 186, 173, 172, 86, 159, 189, 20,
            88, 16, 182, 200, 47, 129, 130, 243, 66, 252, 2, 209, 187, 20, 244, 17, 149, 219, 1,
            249, 25, 172, 88, 170, 52, 68, 211, 49, 215, 119, 7, 191, 252, 198, 52, 236, 127, 251,
            182, 83, 211, 115, 172, 115, 155, 157, 227, 182, 218, 119, 167, 135, 12, 158, 148, 47,
            52, 104, 124, 145, 13, 6, 224, 196, 140, 111, 81, 117, 73, 67, 195, 160, 169, 152, 90,
            68, 17, 166, 238, 190, 114, 92, 148, 19, 255, 242, 213, 214, 208, 210, 51, 56, 48, 78,
            253, 165, 206, 233, 62, 24, 117, 99, 248, 141, 182, 205, 75, 108, 248, 87, 202, 25,
            198, 124, 112, 182, 90, 25, 86, 226, 13, 240, 0, 57, 208, 228, 45, 75, 175, 219, 100,
            206, 136, 174, 15, 245, 36, 71, 101, 166, 130, 1, 40, 48, 130, 1, 36, 160, 3, 2, 1, 18,
            162, 130, 1, 27, 4, 130, 1, 23, 91, 68, 94, 38, 221, 179, 226, 245, 104, 117, 22, 45,
            235, 236, 249, 60, 16, 77, 80, 203, 255, 235, 249, 223, 61, 16, 151, 48, 125, 98, 219,
            76, 113, 125, 252, 18, 210, 103, 41, 184, 69, 192, 220, 141, 240, 102, 29, 2, 225, 101,
            252, 145, 252, 38, 148, 191, 220, 236, 104, 207, 116, 120, 115, 75, 66, 108, 36, 216,
            234, 73, 227, 155, 1, 229, 71, 210, 206, 212, 250, 34, 234, 118, 104, 189, 226, 207,
            176, 59, 199, 148, 230, 11, 197, 245, 201, 35, 164, 125, 71, 62, 155, 26, 199, 201,
            171, 177, 22, 8, 71, 9, 253, 185, 61, 61, 239, 13, 153, 68, 114, 239, 143, 7, 236, 219,
            65, 38, 83, 52, 67, 101, 7, 181, 181, 32, 145, 28, 76, 117, 23, 208, 61, 10, 145, 216,
            153, 2, 244, 158, 132, 160, 247, 27, 126, 164, 140, 139, 113, 129, 110, 151, 158, 121,
            58, 109, 145, 194, 142, 148, 128, 131, 85, 251, 61, 209, 213, 9, 97, 185, 245, 77, 165,
            245, 217, 50, 164, 174, 106, 157, 196, 158, 146, 56, 245, 58, 197, 150, 118, 235, 150,
            42, 194, 246, 98, 200, 43, 24, 104, 152, 62, 242, 107, 97, 126, 33, 116, 122, 21, 46,
            219, 177, 36, 156, 77, 186, 170, 27, 106, 104, 101, 44, 217, 245, 117, 71, 217, 144,
            16, 252, 247, 98, 199, 85, 163, 35, 81, 41, 212, 230, 80, 125, 18, 2, 17, 53, 88, 224,
            9, 76, 106, 133, 89, 211, 207, 138, 8, 197, 235, 218, 64, 148, 233, 154, 81, 119, 150,
            4, 125, 84, 97,
        ];
        let tgs_rep_2 = [
            109, 130, 5, 170, 48, 130, 5, 166, 160, 3, 2, 1, 5, 161, 3, 2, 1, 13, 163, 13, 27, 11,
            81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 164, 15, 48, 13, 160, 3, 2, 1, 1, 161, 6,
            48, 4, 27, 2, 112, 51, 165, 130, 4, 76, 97, 130, 4, 72, 48, 130, 4, 68, 160, 3, 2, 1,
            5, 161, 13, 27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 36, 48, 34, 160,
            3, 2, 1, 2, 161, 27, 48, 25, 27, 7, 84, 69, 82, 77, 83, 82, 86, 27, 14, 112, 51, 46,
            113, 107, 97, 116, 105, 111, 110, 46, 99, 111, 109, 163, 130, 4, 6, 48, 130, 4, 2, 160,
            3, 2, 1, 18, 162, 130, 3, 249, 4, 130, 3, 245, 206, 172, 134, 33, 57, 94, 64, 1, 148,
            97, 204, 72, 95, 247, 41, 77, 14, 75, 183, 58, 50, 58, 101, 1, 115, 88, 183, 176, 9,
            234, 36, 29, 117, 211, 34, 63, 81, 163, 212, 237, 249, 93, 103, 216, 61, 241, 250, 223,
            68, 167, 84, 155, 220, 112, 107, 181, 215, 67, 44, 81, 30, 104, 184, 192, 194, 17, 123,
            139, 63, 20, 67, 183, 213, 64, 94, 108, 159, 143, 34, 87, 138, 204, 48, 69, 202, 130,
            236, 146, 12, 254, 67, 182, 76, 152, 109, 85, 73, 216, 107, 154, 138, 211, 166, 141,
            180, 76, 146, 144, 167, 115, 105, 135, 145, 175, 215, 160, 127, 177, 180, 205, 63, 91,
            113, 160, 34, 15, 61, 79, 96, 232, 227, 106, 98, 151, 251, 106, 38, 32, 135, 194, 191,
            83, 149, 57, 37, 98, 84, 79, 242, 2, 149, 177, 117, 127, 133, 192, 238, 243, 53, 1,
            155, 156, 185, 66, 245, 53, 166, 12, 203, 202, 168, 142, 246, 242, 154, 251, 131, 42,
            14, 57, 221, 21, 86, 183, 192, 120, 191, 87, 77, 130, 156, 4, 56, 12, 159, 187, 181,
            85, 200, 243, 117, 45, 140, 113, 169, 124, 198, 213, 241, 254, 136, 110, 164, 218, 66,
            17, 92, 28, 76, 184, 106, 38, 237, 239, 2, 138, 77, 19, 253, 238, 182, 33, 238, 185,
            237, 121, 82, 131, 79, 99, 204, 73, 167, 13, 87, 198, 251, 85, 28, 121, 56, 42, 118,
            35, 15, 108, 170, 108, 189, 156, 101, 145, 24, 248, 146, 70, 246, 128, 164, 21, 169,
            154, 93, 27, 71, 70, 34, 24, 232, 35, 43, 19, 129, 57, 187, 80, 48, 44, 61, 61, 50,
            114, 225, 90, 12, 237, 122, 238, 107, 194, 168, 39, 184, 192, 17, 99, 208, 41, 169,
            222, 118, 55, 10, 81, 87, 251, 79, 69, 247, 174, 170, 124, 141, 125, 136, 69, 79, 15,
            34, 180, 1, 78, 216, 59, 91, 162, 66, 50, 152, 123, 37, 216, 82, 228, 151, 146, 11, 69,
            149, 207, 226, 45, 244, 102, 76, 76, 214, 110, 239, 106, 105, 230, 249, 246, 231, 89,
            110, 131, 146, 52, 135, 24, 7, 124, 37, 117, 82, 0, 147, 18, 180, 4, 34, 60, 59, 213,
            224, 65, 62, 64, 72, 0, 218, 131, 49, 211, 8, 7, 125, 216, 17, 59, 252, 252, 228, 53,
            162, 216, 163, 66, 197, 165, 86, 89, 137, 196, 7, 231, 142, 45, 194, 69, 137, 194, 33,
            74, 184, 80, 176, 54, 224, 189, 209, 156, 253, 144, 238, 68, 98, 231, 126, 22, 249,
            193, 232, 48, 134, 228, 229, 147, 198, 248, 202, 29, 103, 87, 241, 41, 46, 215, 203,
            137, 204, 244, 244, 141, 158, 131, 185, 164, 68, 147, 75, 15, 252, 82, 32, 131, 195,
            248, 125, 57, 65, 90, 38, 250, 236, 107, 126, 148, 119, 136, 230, 199, 81, 176, 26,
            183, 250, 40, 71, 20, 102, 240, 128, 95, 118, 41, 51, 100, 135, 21, 29, 45, 59, 32, 57,
            4, 246, 196, 15, 98, 10, 70, 171, 217, 222, 156, 252, 219, 54, 208, 94, 177, 159, 167,
            50, 169, 226, 76, 187, 43, 173, 50, 221, 234, 150, 10, 228, 154, 185, 171, 200, 137, 4,
            164, 167, 115, 184, 189, 161, 181, 114, 236, 133, 245, 45, 32, 145, 121, 88, 124, 162,
            13, 197, 21, 235, 114, 233, 87, 28, 185, 44, 132, 126, 8, 180, 183, 168, 207, 101, 161,
            5, 133, 88, 152, 171, 239, 5, 23, 176, 29, 86, 179, 94, 192, 78, 64, 227, 183, 221,
            248, 3, 22, 91, 13, 59, 48, 68, 123, 120, 142, 86, 89, 239, 39, 226, 59, 190, 153, 54,
            188, 46, 19, 16, 51, 4, 210, 198, 57, 76, 238, 141, 89, 87, 139, 63, 246, 157, 85, 116,
            223, 200, 19, 235, 215, 25, 165, 64, 198, 52, 18, 127, 207, 226, 38, 104, 139, 8, 217,
            216, 105, 126, 99, 8, 32, 38, 13, 151, 104, 38, 194, 3, 99, 72, 198, 117, 219, 12, 112,
            87, 75, 238, 115, 145, 166, 218, 9, 225, 110, 167, 144, 169, 174, 116, 175, 33, 67, 14,
            36, 74, 146, 27, 22, 61, 240, 96, 184, 37, 151, 153, 191, 138, 236, 139, 163, 26, 180,
            18, 91, 207, 178, 204, 214, 134, 247, 74, 184, 86, 0, 4, 80, 127, 152, 221, 111, 89,
            36, 13, 152, 167, 4, 71, 200, 53, 39, 126, 205, 33, 215, 216, 157, 58, 149, 161, 14,
            106, 213, 220, 164, 104, 30, 218, 123, 152, 55, 216, 151, 149, 118, 187, 9, 60, 26,
            117, 220, 4, 64, 176, 172, 223, 108, 59, 134, 97, 24, 35, 163, 58, 1, 156, 2, 223, 0,
            93, 18, 220, 32, 189, 241, 246, 14, 79, 120, 69, 165, 171, 114, 88, 56, 60, 254, 22,
            251, 136, 247, 220, 183, 20, 214, 50, 51, 48, 112, 75, 106, 209, 189, 71, 106, 249,
            232, 225, 99, 229, 217, 230, 85, 218, 134, 88, 247, 32, 104, 118, 75, 25, 189, 79, 4,
            200, 54, 47, 55, 226, 246, 1, 164, 63, 182, 141, 179, 219, 88, 55, 0, 52, 39, 61, 184,
            111, 155, 111, 15, 216, 217, 192, 14, 254, 163, 195, 115, 91, 109, 138, 103, 239, 48,
            17, 79, 149, 116, 141, 141, 60, 246, 70, 96, 12, 225, 239, 131, 253, 24, 86, 188, 0, 5,
            6, 213, 83, 216, 91, 50, 240, 232, 45, 184, 83, 127, 88, 173, 126, 232, 47, 52, 215,
            84, 68, 33, 18, 93, 104, 180, 13, 66, 211, 26, 99, 240, 25, 163, 110, 159, 31, 207, 71,
            245, 8, 201, 180, 205, 5, 236, 234, 234, 231, 68, 65, 5, 85, 207, 228, 59, 249, 13, 53,
            170, 43, 50, 78, 36, 86, 161, 231, 21, 192, 207, 251, 142, 246, 134, 148, 117, 167,
            128, 137, 226, 190, 207, 223, 125, 30, 102, 72, 88, 159, 213, 102, 137, 87, 240, 95,
            166, 130, 1, 40, 48, 130, 1, 36, 160, 3, 2, 1, 18, 162, 130, 1, 27, 4, 130, 1, 23, 60,
            75, 141, 36, 125, 156, 253, 171, 206, 208, 144, 1, 161, 151, 211, 0, 181, 203, 161,
            150, 105, 116, 239, 21, 73, 206, 196, 44, 90, 156, 109, 122, 116, 231, 243, 193, 11, 5,
            113, 43, 103, 178, 145, 15, 167, 182, 138, 131, 44, 97, 185, 243, 218, 175, 167, 76,
            166, 61, 220, 77, 212, 124, 30, 134, 206, 173, 6, 203, 117, 218, 233, 10, 153, 227, 41,
            97, 128, 82, 140, 53, 85, 176, 45, 9, 79, 108, 74, 173, 24, 55, 42, 157, 124, 174, 252,
            79, 24, 226, 229, 38, 228, 156, 64, 17, 131, 178, 114, 123, 52, 30, 241, 6, 107, 160,
            35, 126, 175, 19, 234, 90, 69, 97, 23, 137, 253, 87, 129, 130, 25, 44, 153, 158, 49,
            240, 255, 122, 148, 94, 37, 157, 148, 19, 148, 217, 58, 70, 126, 174, 187, 9, 129, 35,
            84, 183, 238, 251, 163, 110, 247, 51, 255, 124, 229, 78, 197, 182, 24, 81, 175, 125,
            126, 253, 154, 91, 156, 135, 175, 138, 226, 139, 237, 200, 34, 35, 4, 253, 178, 249,
            105, 218, 139, 173, 217, 17, 30, 147, 247, 149, 219, 151, 126, 197, 97, 143, 124, 225,
            217, 191, 80, 211, 178, 125, 135, 21, 148, 7, 28, 176, 81, 20, 53, 139, 128, 54, 141,
            138, 34, 126, 67, 87, 188, 238, 123, 87, 65, 155, 75, 56, 219, 135, 33, 137, 87, 162,
            35, 156, 234, 236, 36, 166, 97, 179, 68, 21, 217, 34, 166, 234, 125, 236, 185, 64, 134,
            135, 236, 98, 87, 251, 65, 61, 133, 167, 205, 23, 0, 70, 35, 153, 165,
        ];
        let ap_req = [
            110, 130, 5, 170, 48, 130, 5, 166, 160, 3, 2, 1, 5, 161, 3, 2, 1, 14, 162, 7, 3, 5, 0,
            96, 0, 0, 0, 163, 130, 4, 76, 97, 130, 4, 72, 48, 130, 4, 68, 160, 3, 2, 1, 5, 161, 13,
            27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 36, 48, 34, 160, 3, 2, 1, 2,
            161, 27, 48, 25, 27, 7, 84, 69, 82, 77, 83, 82, 86, 27, 14, 112, 51, 46, 113, 107, 97,
            116, 105, 111, 110, 46, 99, 111, 109, 163, 130, 4, 6, 48, 130, 4, 2, 160, 3, 2, 1, 18,
            162, 130, 3, 249, 4, 130, 3, 245, 206, 172, 134, 33, 57, 94, 64, 1, 148, 97, 204, 72,
            95, 247, 41, 77, 14, 75, 183, 58, 50, 58, 101, 1, 115, 88, 183, 176, 9, 234, 36, 29,
            117, 211, 34, 63, 81, 163, 212, 237, 249, 93, 103, 216, 61, 241, 250, 223, 68, 167, 84,
            155, 220, 112, 107, 181, 215, 67, 44, 81, 30, 104, 184, 192, 194, 17, 123, 139, 63, 20,
            67, 183, 213, 64, 94, 108, 159, 143, 34, 87, 138, 204, 48, 69, 202, 130, 236, 146, 12,
            254, 67, 182, 76, 152, 109, 85, 73, 216, 107, 154, 138, 211, 166, 141, 180, 76, 146,
            144, 167, 115, 105, 135, 145, 175, 215, 160, 127, 177, 180, 205, 63, 91, 113, 160, 34,
            15, 61, 79, 96, 232, 227, 106, 98, 151, 251, 106, 38, 32, 135, 194, 191, 83, 149, 57,
            37, 98, 84, 79, 242, 2, 149, 177, 117, 127, 133, 192, 238, 243, 53, 1, 155, 156, 185,
            66, 245, 53, 166, 12, 203, 202, 168, 142, 246, 242, 154, 251, 131, 42, 14, 57, 221, 21,
            86, 183, 192, 120, 191, 87, 77, 130, 156, 4, 56, 12, 159, 187, 181, 85, 200, 243, 117,
            45, 140, 113, 169, 124, 198, 213, 241, 254, 136, 110, 164, 218, 66, 17, 92, 28, 76,
            184, 106, 38, 237, 239, 2, 138, 77, 19, 253, 238, 182, 33, 238, 185, 237, 121, 82, 131,
            79, 99, 204, 73, 167, 13, 87, 198, 251, 85, 28, 121, 56, 42, 118, 35, 15, 108, 170,
            108, 189, 156, 101, 145, 24, 248, 146, 70, 246, 128, 164, 21, 169, 154, 93, 27, 71, 70,
            34, 24, 232, 35, 43, 19, 129, 57, 187, 80, 48, 44, 61, 61, 50, 114, 225, 90, 12, 237,
            122, 238, 107, 194, 168, 39, 184, 192, 17, 99, 208, 41, 169, 222, 118, 55, 10, 81, 87,
            251, 79, 69, 247, 174, 170, 124, 141, 125, 136, 69, 79, 15, 34, 180, 1, 78, 216, 59,
            91, 162, 66, 50, 152, 123, 37, 216, 82, 228, 151, 146, 11, 69, 149, 207, 226, 45, 244,
            102, 76, 76, 214, 110, 239, 106, 105, 230, 249, 246, 231, 89, 110, 131, 146, 52, 135,
            24, 7, 124, 37, 117, 82, 0, 147, 18, 180, 4, 34, 60, 59, 213, 224, 65, 62, 64, 72, 0,
            218, 131, 49, 211, 8, 7, 125, 216, 17, 59, 252, 252, 228, 53, 162, 216, 163, 66, 197,
            165, 86, 89, 137, 196, 7, 231, 142, 45, 194, 69, 137, 194, 33, 74, 184, 80, 176, 54,
            224, 189, 209, 156, 253, 144, 238, 68, 98, 231, 126, 22, 249, 193, 232, 48, 134, 228,
            229, 147, 198, 248, 202, 29, 103, 87, 241, 41, 46, 215, 203, 137, 204, 244, 244, 141,
            158, 131, 185, 164, 68, 147, 75, 15, 252, 82, 32, 131, 195, 248, 125, 57, 65, 90, 38,
            250, 236, 107, 126, 148, 119, 136, 230, 199, 81, 176, 26, 183, 250, 40, 71, 20, 102,
            240, 128, 95, 118, 41, 51, 100, 135, 21, 29, 45, 59, 32, 57, 4, 246, 196, 15, 98, 10,
            70, 171, 217, 222, 156, 252, 219, 54, 208, 94, 177, 159, 167, 50, 169, 226, 76, 187,
            43, 173, 50, 221, 234, 150, 10, 228, 154, 185, 171, 200, 137, 4, 164, 167, 115, 184,
            189, 161, 181, 114, 236, 133, 245, 45, 32, 145, 121, 88, 124, 162, 13, 197, 21, 235,
            114, 233, 87, 28, 185, 44, 132, 126, 8, 180, 183, 168, 207, 101, 161, 5, 133, 88, 152,
            171, 239, 5, 23, 176, 29, 86, 179, 94, 192, 78, 64, 227, 183, 221, 248, 3, 22, 91, 13,
            59, 48, 68, 123, 120, 142, 86, 89, 239, 39, 226, 59, 190, 153, 54, 188, 46, 19, 16, 51,
            4, 210, 198, 57, 76, 238, 141, 89, 87, 139, 63, 246, 157, 85, 116, 223, 200, 19, 235,
            215, 25, 165, 64, 198, 52, 18, 127, 207, 226, 38, 104, 139, 8, 217, 216, 105, 126, 99,
            8, 32, 38, 13, 151, 104, 38, 194, 3, 99, 72, 198, 117, 219, 12, 112, 87, 75, 238, 115,
            145, 166, 218, 9, 225, 110, 167, 144, 169, 174, 116, 175, 33, 67, 14, 36, 74, 146, 27,
            22, 61, 240, 96, 184, 37, 151, 153, 191, 138, 236, 139, 163, 26, 180, 18, 91, 207, 178,
            204, 214, 134, 247, 74, 184, 86, 0, 4, 80, 127, 152, 221, 111, 89, 36, 13, 152, 167, 4,
            71, 200, 53, 39, 126, 205, 33, 215, 216, 157, 58, 149, 161, 14, 106, 213, 220, 164,
            104, 30, 218, 123, 152, 55, 216, 151, 149, 118, 187, 9, 60, 26, 117, 220, 4, 64, 176,
            172, 223, 108, 59, 134, 97, 24, 35, 163, 58, 1, 156, 2, 223, 0, 93, 18, 220, 32, 189,
            241, 246, 14, 79, 120, 69, 165, 171, 114, 88, 56, 60, 254, 22, 251, 136, 247, 220, 183,
            20, 214, 50, 51, 48, 112, 75, 106, 209, 189, 71, 106, 249, 232, 225, 99, 229, 217, 230,
            85, 218, 134, 88, 247, 32, 104, 118, 75, 25, 189, 79, 4, 200, 54, 47, 55, 226, 246, 1,
            164, 63, 182, 141, 179, 219, 88, 55, 0, 52, 39, 61, 184, 111, 155, 111, 15, 216, 217,
            192, 14, 254, 163, 195, 115, 91, 109, 138, 103, 239, 48, 17, 79, 149, 116, 141, 141,
            60, 246, 70, 96, 12, 225, 239, 131, 253, 24, 86, 188, 0, 5, 6, 213, 83, 216, 91, 50,
            240, 232, 45, 184, 83, 127, 88, 173, 126, 232, 47, 52, 215, 84, 68, 33, 18, 93, 104,
            180, 13, 66, 211, 26, 99, 240, 25, 163, 110, 159, 31, 207, 71, 245, 8, 201, 180, 205,
            5, 236, 234, 234, 231, 68, 65, 5, 85, 207, 228, 59, 249, 13, 53, 170, 43, 50, 78, 36,
            86, 161, 231, 21, 192, 207, 251, 142, 246, 134, 148, 117, 167, 128, 137, 226, 190, 207,
            223, 125, 30, 102, 72, 88, 159, 213, 102, 137, 87, 240, 95, 164, 130, 1, 63, 48, 130,
            1, 59, 160, 3, 2, 1, 18, 162, 130, 1, 50, 4, 130, 1, 46, 32, 128, 189, 31, 133, 73,
            211, 231, 171, 224, 176, 106, 46, 117, 5, 170, 35, 144, 73, 204, 81, 236, 96, 38, 150,
            27, 8, 214, 164, 132, 244, 254, 15, 11, 51, 35, 236, 141, 198, 7, 95, 50, 184, 164, 4,
            188, 4, 90, 106, 59, 124, 192, 244, 207, 123, 41, 30, 192, 128, 201, 19, 219, 191, 111,
            185, 36, 136, 99, 155, 20, 27, 156, 53, 68, 52, 185, 44, 125, 67, 170, 146, 29, 120,
            58, 244, 37, 64, 161, 201, 79, 116, 148, 10, 171, 53, 114, 229, 54, 15, 52, 37, 2, 240,
            54, 114, 158, 141, 62, 209, 151, 52, 164, 193, 181, 3, 200, 91, 148, 54, 243, 146, 61,
            91, 54, 137, 182, 86, 167, 225, 83, 249, 97, 125, 255, 16, 1, 11, 139, 121, 218, 225,
            57, 221, 96, 45, 31, 59, 157, 158, 165, 157, 210, 7, 179, 5, 154, 44, 160, 90, 147,
            163, 202, 235, 207, 98, 90, 224, 242, 54, 57, 89, 78, 16, 32, 157, 116, 109, 110, 180,
            112, 239, 3, 61, 27, 244, 239, 127, 150, 164, 231, 28, 142, 159, 184, 87, 102, 219,
            155, 132, 151, 239, 38, 88, 71, 201, 1, 130, 67, 36, 222, 204, 11, 113, 242, 172, 252,
            239, 182, 115, 106, 111, 248, 103, 53, 252, 79, 34, 27, 137, 119, 47, 118, 113, 10,
            193, 116, 156, 50, 93, 131, 98, 56, 168, 216, 250, 221, 23, 251, 20, 82, 45, 95, 183,
            161, 179, 174, 143, 210, 125, 101, 178, 28, 165, 120, 212, 209, 60, 191, 197, 241, 196,
            110, 187, 93, 231, 238, 238, 219, 10, 43, 176, 60, 241, 165, 70, 205, 37, 80, 120, 210,
            223, 58, 6, 248, 205, 166, 221, 13, 97, 53, 130, 81,
        ];

        let as_rep: AsRep = picky_asn1_der::from_bytes(&as_rep).unwrap();
        let tgs_rep_1: TgsRep = picky_asn1_der::from_bytes(&tgs_rep_1).unwrap();
        let tgs_rep_2: TgsRep = picky_asn1_der::from_bytes(&tgs_rep_2).unwrap();
        let ap_req: ApReq = picky_asn1_der::from_bytes(&ap_req).unwrap();

        let (_encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep).unwrap();
        let session_key_1 = extract_session_key_from_as_rep(&as_rep, &salt, &password).unwrap();

        println!("session_key1: {:?}", session_key_1);

        let session_key_2_1 = extract_session_key_from_tgs_rep(&tgs_rep_1, &session_key_1).unwrap();
        let session_key_2_2 = extract_session_key_from_tgs_rep(&tgs_rep_2, &session_key_1).unwrap();

        println!("session_key_2_1: {:?}", session_key_2_1);
        println!("session_key_2_2: {:?}", session_key_2_2);

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

        // 7 || 11
        println!(
            "{:?}",
            cipher.decrypt(&session_key_2_1, 3, &ap_req.0.authenticator.cipher.0 .0)
        );
        println!(
            "{:?}",
            cipher.decrypt(&session_key_2_2, 3, &ap_req.0.authenticator.cipher.0 .0)
        );
        println!(
            "{:?}",
            cipher.decrypt(&session_key_2_1, 11, &ap_req.0.authenticator.cipher.0 .0)
        );
        println!(
            "{:?}",
            cipher.decrypt(&session_key_2_2, 11, &ap_req.0.authenticator.cipher.0 .0)
        );
    }
}
