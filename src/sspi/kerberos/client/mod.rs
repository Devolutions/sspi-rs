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
    messages::{ApReq, ApReqInner, AsRep, AsReq, EncAsRepPart, KdcReq, KdcReqBody, TgsReq},
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
    let salt = cipher.generate_salt(&realm, &username);
    let key = cipher.generate_key_from_string(&password, &salt);

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
                expiration_date.clone(),
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
                expiration_date.clone(),
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

pub fn generate_authenticator_from_as_rep(as_rep: &AsRep) -> Authenticator {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(as_rep.0.crealm.0.clone()),
        cname: ExplicitContextTag2::from(as_rep.0.cname.0.clone()),
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
                pa_etype_into2.etype.0 .0.get(0).map(|t| *t).unwrap(),
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
    use picky_krb::messages::{AsRep, EncAsRepPart, EncTgsRepPart, TgsRep};

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
                        .map(|t| *t)
                        .unwrap_or(default_encryption_params.0),
                    pa_etype_into2
                        .salt
                        .0
                        .as_ref()
                        .map(|salt| salt.0.to_string())
                        .unwrap_or(default_encryption_params.1.clone()),
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
            18, 161, 3, 2, 1, 2, 162, 130, 3, 167, 4, 130, 3, 163, 108, 136, 232, 234, 240, 95,
            193, 107, 236, 66, 211, 97, 135, 162, 158, 131, 44, 42, 254, 157, 166, 143, 124, 38,
            202, 122, 63, 239, 210, 163, 245, 149, 147, 4, 24, 154, 3, 8, 224, 124, 159, 132, 75,
            5, 115, 158, 113, 83, 113, 16, 213, 236, 184, 103, 18, 91, 81, 208, 233, 88, 47, 112,
            202, 141, 22, 183, 67, 32, 90, 220, 107, 34, 242, 244, 235, 183, 49, 255, 95, 186, 168,
            223, 156, 237, 221, 123, 122, 59, 10, 68, 196, 109, 220, 229, 230, 197, 198, 132, 47,
            241, 220, 187, 252, 90, 127, 170, 212, 113, 159, 49, 152, 11, 65, 19, 134, 90, 133,
            185, 12, 19, 18, 109, 3, 113, 50, 120, 94, 62, 87, 97, 77, 48, 93, 21, 161, 32, 135,
            121, 205, 66, 251, 79, 255, 102, 113, 54, 7, 15, 166, 55, 103, 241, 165, 6, 213, 117,
            53, 219, 2, 21, 28, 93, 197, 135, 48, 81, 42, 231, 41, 36, 172, 62, 238, 247, 60, 84,
            188, 20, 100, 250, 81, 158, 134, 46, 191, 132, 157, 221, 245, 183, 208, 171, 145, 49,
            69, 129, 166, 136, 46, 14, 245, 0, 181, 135, 83, 230, 216, 233, 121, 114, 175, 168, 74,
            114, 126, 195, 160, 247, 207, 157, 192, 239, 70, 112, 56, 9, 202, 105, 122, 231, 194,
            4, 32, 241, 215, 193, 48, 166, 9, 118, 198, 208, 51, 10, 91, 106, 117, 228, 246, 106,
            194, 123, 183, 52, 12, 210, 224, 86, 141, 245, 82, 71, 144, 71, 161, 44, 162, 231, 247,
            207, 218, 174, 245, 71, 189, 170, 99, 28, 133, 174, 198, 29, 188, 9, 252, 171, 101,
            194, 36, 125, 167, 252, 52, 111, 121, 163, 68, 137, 61, 239, 74, 43, 96, 240, 7, 152,
            28, 241, 97, 30, 164, 77, 81, 178, 116, 107, 103, 53, 96, 121, 101, 217, 147, 81, 57,
            187, 161, 79, 155, 126, 196, 127, 177, 118, 95, 162, 154, 76, 35, 165, 188, 114, 35,
            204, 229, 15, 239, 189, 169, 148, 92, 30, 45, 53, 181, 79, 238, 7, 132, 241, 167, 77,
            135, 248, 205, 188, 26, 170, 67, 216, 185, 226, 42, 128, 4, 89, 105, 84, 150, 28, 68,
            128, 249, 79, 207, 4, 74, 202, 24, 6, 63, 134, 223, 47, 64, 144, 200, 87, 222, 199,
            245, 95, 189, 99, 95, 85, 123, 146, 4, 169, 59, 215, 168, 171, 183, 140, 92, 144, 48,
            220, 236, 54, 163, 7, 15, 76, 23, 183, 107, 165, 140, 157, 210, 110, 245, 252, 44, 254,
            254, 109, 176, 249, 174, 109, 233, 121, 80, 57, 44, 59, 69, 189, 75, 95, 29, 70, 34,
            211, 255, 32, 112, 120, 213, 67, 202, 90, 16, 138, 214, 240, 88, 207, 176, 68, 227,
            227, 227, 208, 214, 198, 145, 93, 235, 174, 75, 162, 240, 30, 98, 55, 201, 212, 232,
            116, 242, 34, 104, 9, 92, 32, 152, 56, 245, 149, 108, 73, 97, 100, 100, 62, 57, 117,
            215, 182, 109, 145, 144, 149, 215, 7, 23, 44, 30, 150, 23, 74, 1, 244, 244, 74, 226,
            56, 193, 226, 35, 14, 171, 175, 203, 101, 173, 152, 157, 132, 183, 58, 198, 174, 152,
            191, 73, 137, 43, 22, 244, 141, 94, 247, 21, 102, 223, 229, 26, 26, 170, 165, 52, 133,
            238, 166, 102, 197, 188, 100, 124, 147, 29, 48, 77, 11, 151, 50, 185, 148, 72, 98, 177,
            50, 79, 181, 13, 232, 8, 77, 117, 15, 215, 245, 161, 242, 79, 254, 154, 55, 70, 214,
            95, 167, 3, 31, 74, 141, 249, 225, 197, 113, 125, 90, 152, 144, 251, 101, 248, 66, 41,
            137, 41, 246, 44, 200, 133, 26, 24, 247, 88, 56, 162, 247, 45, 220, 75, 187, 125, 179,
            174, 86, 225, 185, 117, 88, 40, 127, 106, 40, 178, 122, 218, 252, 244, 68, 69, 141, 46,
            250, 235, 129, 195, 113, 252, 161, 160, 52, 55, 92, 0, 15, 75, 223, 29, 166, 219, 56,
            139, 153, 177, 233, 231, 99, 132, 170, 18, 161, 4, 17, 72, 219, 183, 14, 10, 14, 17,
            131, 30, 142, 18, 66, 159, 152, 208, 48, 109, 237, 103, 28, 153, 102, 216, 3, 121, 251,
            35, 87, 54, 222, 218, 244, 165, 233, 10, 87, 15, 30, 148, 67, 188, 251, 69, 156, 210,
            90, 190, 71, 238, 57, 60, 57, 172, 74, 156, 242, 98, 42, 72, 135, 250, 147, 178, 21,
            191, 242, 19, 141, 150, 146, 189, 78, 196, 134, 103, 61, 193, 66, 58, 109, 92, 229,
            226, 153, 49, 142, 10, 15, 112, 10, 41, 218, 30, 167, 173, 103, 131, 116, 203, 156,
            247, 137, 240, 191, 223, 94, 5, 167, 132, 184, 0, 240, 226, 129, 89, 30, 148, 27, 179,
            26, 153, 20, 46, 36, 192, 147, 222, 109, 32, 109, 203, 23, 27, 244, 157, 183, 199, 153,
            16, 132, 181, 160, 114, 244, 141, 15, 167, 122, 17, 101, 93, 3, 93, 112, 208, 56, 140,
            163, 76, 111, 150, 176, 44, 101, 253, 4, 17, 182, 99, 248, 137, 198, 1, 161, 204, 150,
            205, 14, 89, 121, 244, 52, 243, 240, 211, 249, 238, 7, 146, 21, 191, 28, 76, 189, 196,
            22, 238, 250, 111, 123, 39, 54, 159, 58, 205, 69, 121, 106, 149, 75, 249, 100, 198, 58,
            240, 13, 106, 61, 2, 190, 23, 159, 4, 100, 171, 109, 37, 215, 49, 98, 28, 213, 170,
            121, 222, 142, 174, 166, 130, 1, 58, 48, 130, 1, 54, 160, 3, 2, 1, 18, 161, 3, 2, 1, 2,
            162, 130, 1, 40, 4, 130, 1, 36, 136, 139, 174, 142, 253, 56, 70, 85, 160, 135, 116,
            234, 133, 24, 112, 78, 234, 193, 71, 33, 214, 22, 208, 39, 95, 212, 194, 75, 94, 131,
            115, 250, 43, 106, 106, 206, 130, 120, 99, 206, 174, 211, 126, 201, 46, 117, 206, 72,
            83, 32, 64, 221, 252, 201, 208, 126, 67, 234, 87, 31, 105, 141, 50, 189, 145, 154, 90,
            72, 144, 99, 201, 26, 164, 24, 145, 227, 54, 217, 247, 200, 149, 219, 53, 94, 230, 188,
            79, 7, 187, 227, 31, 87, 155, 106, 142, 14, 168, 208, 73, 245, 33, 135, 111, 119, 24,
            175, 164, 114, 11, 30, 244, 239, 18, 49, 66, 10, 30, 59, 210, 190, 107, 129, 19, 39, 9,
            219, 124, 72, 38, 228, 17, 130, 228, 167, 229, 138, 255, 76, 196, 25, 26, 218, 199,
            234, 61, 23, 40, 228, 65, 64, 63, 245, 199, 89, 48, 21, 185, 178, 70, 253, 159, 250,
            15, 144, 17, 103, 84, 205, 214, 253, 135, 113, 232, 241, 54, 142, 116, 32, 215, 84,
            164, 236, 43, 60, 93, 81, 100, 155, 63, 192, 97, 193, 141, 193, 182, 238, 179, 74, 212,
            133, 26, 102, 179, 98, 220, 37, 66, 228, 110, 79, 219, 43, 45, 166, 131, 65, 96, 21,
            70, 103, 241, 190, 233, 24, 218, 209, 179, 144, 117, 43, 67, 104, 194, 247, 1, 106, 14,
            13, 195, 111, 124, 127, 248, 113, 194, 18, 237, 184, 15, 33, 180, 79, 48, 113, 233,
            194, 105, 23, 17, 72, 74, 95, 230, 127, 30, 171, 93, 40, 121, 127, 43, 236, 200, 175,
            121, 184, 11, 213, 131, 199, 84, 84, 19, 118, 169, 107, 37, 94, 131, 191, 187, 39,
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
            194, 160, 3, 2, 1, 18, 161, 3, 2, 1, 2, 162, 130, 3, 180, 4, 130, 3, 176, 243, 90, 101,
            53, 208, 117, 147, 180, 193, 147, 89, 216, 50, 236, 80, 209, 19, 135, 101, 107, 143,
            47, 120, 124, 209, 180, 13, 162, 25, 198, 187, 220, 129, 203, 223, 218, 178, 225, 155,
            75, 134, 185, 99, 188, 189, 192, 149, 70, 185, 166, 127, 81, 181, 44, 71, 135, 243, 3,
            132, 46, 235, 129, 150, 220, 209, 227, 160, 243, 10, 152, 29, 41, 156, 73, 246, 129,
            194, 192, 10, 38, 164, 126, 201, 205, 26, 115, 18, 172, 14, 74, 194, 26, 243, 213, 155,
            113, 45, 108, 145, 12, 4, 199, 30, 89, 142, 43, 58, 201, 249, 55, 8, 88, 182, 103, 226,
            136, 5, 246, 42, 100, 127, 210, 56, 160, 80, 22, 116, 200, 231, 88, 147, 197, 237, 70,
            173, 254, 86, 135, 11, 161, 37, 79, 188, 238, 120, 126, 60, 120, 207, 209, 249, 82,
            121, 122, 187, 40, 32, 82, 145, 90, 97, 165, 53, 203, 106, 22, 118, 161, 18, 152, 149,
            0, 223, 210, 112, 121, 34, 122, 141, 128, 174, 53, 5, 7, 61, 77, 15, 39, 116, 246, 52,
            80, 58, 86, 201, 181, 24, 193, 255, 203, 190, 137, 99, 137, 106, 136, 42, 185, 46, 16,
            248, 145, 110, 219, 244, 239, 7, 252, 102, 156, 63, 136, 51, 94, 5, 233, 167, 4, 141,
            201, 247, 161, 248, 177, 31, 7, 62, 154, 39, 198, 228, 179, 19, 132, 243, 196, 179, 2,
            97, 135, 253, 157, 180, 211, 46, 166, 225, 70, 43, 2, 174, 236, 172, 106, 197, 86, 174,
            231, 186, 138, 203, 78, 212, 202, 102, 97, 164, 8, 135, 213, 137, 180, 103, 60, 112,
            126, 76, 137, 223, 250, 149, 188, 39, 92, 25, 146, 62, 8, 69, 209, 49, 158, 192, 121,
            74, 222, 184, 79, 164, 35, 1, 56, 19, 191, 86, 106, 106, 116, 23, 109, 235, 75, 224,
            184, 253, 243, 229, 40, 129, 38, 144, 56, 139, 146, 144, 206, 71, 141, 109, 214, 45,
            104, 192, 17, 134, 253, 177, 14, 40, 234, 225, 157, 87, 197, 194, 158, 169, 67, 45,
            139, 22, 21, 79, 201, 53, 133, 212, 8, 19, 124, 36, 93, 249, 139, 197, 124, 223, 106,
            114, 68, 114, 102, 15, 244, 47, 232, 204, 190, 93, 210, 9, 119, 222, 110, 18, 15, 108,
            240, 230, 199, 154, 129, 114, 219, 108, 227, 221, 49, 236, 31, 135, 176, 109, 150, 15,
            209, 6, 118, 96, 160, 130, 221, 152, 148, 95, 167, 129, 3, 101, 89, 206, 144, 222, 121,
            119, 175, 189, 56, 9, 130, 110, 212, 157, 147, 113, 168, 22, 90, 38, 157, 27, 67, 90,
            123, 98, 198, 238, 118, 120, 139, 126, 109, 19, 7, 148, 83, 0, 104, 51, 166, 73, 73,
            252, 168, 173, 210, 14, 129, 125, 253, 232, 1, 247, 17, 155, 8, 131, 239, 236, 128,
            224, 190, 43, 170, 90, 171, 4, 77, 11, 180, 153, 203, 52, 249, 107, 147, 71, 18, 232,
            195, 148, 193, 203, 89, 20, 39, 193, 76, 202, 67, 166, 135, 26, 142, 32, 216, 172, 162,
            67, 55, 128, 212, 117, 107, 211, 234, 62, 172, 111, 157, 155, 114, 177, 73, 158, 99,
            228, 59, 63, 216, 114, 9, 38, 84, 179, 234, 211, 94, 93, 167, 83, 63, 93, 50, 212, 160,
            226, 177, 171, 201, 114, 99, 215, 57, 126, 0, 6, 71, 83, 173, 143, 30, 217, 73, 99,
            203, 35, 176, 134, 98, 63, 57, 217, 188, 203, 13, 233, 15, 128, 217, 114, 77, 29, 172,
            195, 222, 202, 251, 12, 90, 44, 182, 115, 216, 237, 127, 157, 140, 175, 214, 203, 22,
            147, 34, 11, 105, 39, 241, 7, 23, 132, 197, 70, 15, 10, 227, 85, 155, 129, 216, 72, 42,
            252, 169, 43, 177, 254, 106, 253, 202, 254, 185, 212, 121, 201, 151, 112, 90, 229, 226,
            97, 77, 172, 168, 58, 124, 96, 211, 178, 112, 93, 160, 60, 11, 176, 157, 150, 190, 83,
            154, 86, 161, 96, 4, 82, 173, 190, 166, 71, 184, 44, 196, 217, 203, 81, 58, 110, 232,
            71, 151, 124, 116, 56, 37, 152, 210, 49, 242, 100, 107, 173, 103, 198, 0, 62, 95, 53,
            143, 255, 163, 168, 83, 33, 141, 245, 175, 110, 28, 243, 24, 175, 23, 102, 118, 89,
            155, 50, 172, 244, 228, 48, 109, 58, 36, 252, 41, 101, 162, 98, 20, 220, 237, 138, 38,
            157, 142, 10, 199, 183, 25, 226, 39, 94, 159, 147, 112, 248, 108, 11, 72, 81, 204, 82,
            61, 18, 225, 118, 168, 183, 90, 18, 251, 67, 165, 79, 86, 140, 151, 231, 65, 89, 180,
            62, 63, 168, 189, 13, 0, 244, 55, 86, 217, 17, 220, 159, 139, 140, 238, 117, 158, 115,
            225, 245, 101, 201, 103, 125, 138, 175, 34, 76, 36, 30, 249, 146, 169, 246, 117, 95,
            41, 45, 74, 152, 71, 39, 40, 113, 65, 21, 36, 90, 193, 70, 23, 144, 69, 147, 48, 185,
            149, 129, 132, 32, 219, 180, 174, 228, 75, 162, 124, 160, 74, 110, 78, 193, 178, 126,
            131, 166, 150, 34, 197, 208, 32, 167, 143, 94, 77, 88, 151, 9, 243, 176, 197, 200, 96,
            58, 177, 235, 88, 213, 63, 4, 126, 115, 189, 214, 226, 221, 26, 199, 200, 79, 41, 204,
            30, 132, 141, 141, 111, 0, 77, 81, 134, 198, 173, 251, 27, 93, 146, 248, 238, 182, 149,
            73, 7, 143, 18, 210, 165, 32, 191, 229, 159, 89, 77, 6, 217, 212, 219, 96, 134, 173,
            161, 166, 130, 1, 41, 48, 130, 1, 37, 160, 3, 2, 1, 18, 162, 130, 1, 28, 4, 130, 1, 24,
            237, 100, 246, 33, 84, 142, 150, 41, 120, 229, 175, 158, 139, 118, 67, 1, 227, 251,
            195, 93, 252, 80, 182, 175, 76, 179, 238, 165, 66, 107, 21, 168, 127, 11, 51, 19, 214,
            105, 81, 30, 253, 57, 160, 117, 117, 105, 146, 120, 66, 89, 30, 204, 207, 30, 74, 186,
            72, 14, 78, 144, 207, 64, 236, 247, 119, 91, 50, 91, 18, 95, 110, 226, 156, 202, 89,
            194, 163, 6, 120, 204, 149, 149, 82, 12, 64, 164, 54, 122, 168, 138, 105, 65, 38, 148,
            97, 135, 17, 60, 187, 34, 20, 210, 178, 89, 30, 171, 213, 149, 119, 105, 124, 18, 113,
            187, 146, 76, 231, 38, 117, 31, 47, 209, 95, 232, 139, 93, 30, 174, 158, 157, 194, 179,
            251, 231, 202, 69, 173, 61, 57, 132, 119, 162, 82, 64, 246, 154, 198, 203, 226, 3, 140,
            179, 6, 181, 20, 201, 170, 153, 146, 232, 202, 255, 82, 201, 88, 196, 107, 189, 50, 39,
            185, 129, 207, 54, 120, 101, 38, 154, 9, 109, 154, 176, 233, 232, 189, 190, 112, 33,
            200, 247, 42, 22, 243, 206, 208, 174, 214, 193, 68, 72, 17, 48, 228, 221, 228, 128, 10,
            181, 128, 148, 40, 73, 134, 137, 102, 153, 70, 112, 248, 197, 106, 192, 11, 222, 109,
            248, 81, 147, 165, 110, 248, 25, 109, 11, 105, 190, 172, 82, 93, 178, 239, 52, 143,
            167, 165, 16, 94, 43, 39, 60, 154, 197, 95, 235, 131, 161, 132, 237, 114, 103, 89, 227,
            88, 13, 196, 206, 145, 173, 84, 205, 20, 222, 11, 232, 226, 130, 113, 96, 177, 105,
        ];

        let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&data).unwrap();
        println!("{:?}", tgs_rep);

        let cipher_data = tgs_rep.0.enc_part.cipher.0.to_vec();

        let cipher =
            new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();
        let key = [
            237, 215, 110, 30, 216, 80, 62, 19, 255, 197, 118, 23, 171, 27, 54, 171, 77, 129, 32,
            9, 69, 134, 32, 34, 56, 234, 133, 122, 227, 233, 110, 41,
        ];

        let res = cipher.decrypt(&key, 8, &cipher_data).unwrap();
        let enc_part: EncTgsRepPart = picky_asn1_der::from_bytes(&res).unwrap();
        println!("res: {:?}", res);
        println!("res: {:?}", enc_part);
    }
}
