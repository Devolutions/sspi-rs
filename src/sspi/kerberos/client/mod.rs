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

use crate::sspi::kerberos::{KERBEROS_VERSION, SERVICE_NAME};

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

pub fn extract_session_key_from_as_rep(as_rep: &AsRep, salt: &str, password: &str) -> Vec<u8> {
    let cipher = new_kerberos_cipher(kerberos_constants::etypes::AES256_CTS_HMAC_SHA1_96).unwrap();

    let key = cipher.generate_key_from_string(password, salt.as_bytes());

    let enc_data = cipher
        .decrypt(&key, 3, &as_rep.0.enc_part.0.cipher.0 .0)
        .unwrap();

    let enc_as_rep_part: EncAsRepPart = picky_asn1_der::from_bytes(&enc_data).unwrap();

    enc_as_rep_part.0.key.0.key_value.0.to_vec()
}

pub fn extract_encryption_params_from_as_rep(as_rep: &AsRep) -> (u8, String) {
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
            let pa_etype_into2: EtypeInfo2 = picky_asn1_der::from_bytes(&data).unwrap();
            let pa_etype_into2 = &pa_etype_into2.0[0];
            (
                pa_etype_into2.etype.0 .0.get(0).map(|t| *t).unwrap(),
                pa_etype_into2
                    .salt
                    .0
                    .as_ref()
                    .map(|salt| salt.0.to_string())
                    .unwrap(),
            )
        }
        None => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use kerberos_crypto::new_kerberos_cipher;
    use picky_krb::data_types::EtypeInfo2;
    use picky_krb::messages::{AsRep, EncAsRepPart};

    use super::super::reqwest_client::ReqwestNetworkClient;
    use super::super::NetworkClient;
    use super::generate_as_req;
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
}
