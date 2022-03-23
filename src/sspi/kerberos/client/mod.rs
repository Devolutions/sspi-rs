use chrono::{DateTime, Datelike, Duration, Utc};
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
        EncryptedData, KerbPaPacRequest, KerberosFlags, KerberosStringAsn1, KerberosTime, PaData,
        PaEncTsEnc, PrincipalName, Realm,
    },
    messages::{AsReq, KdcReq, KdcReqBody, TgsReq},
};
use rand::{rngs::OsRng, Rng};

use crate::sspi::kerberos::{KERBEROS_VERSION, SERVICE_NAME};

const AP_REQ_MSG_TYPE: u8 = 0x0a;
const NT_PRINCIPAL: u8 = 0x01;
const NT_SRV_INST: u8 = 0x02;
const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;

const AES128_CTS_HMAC_SHA1_96: u8 = 0x11;
const AES256_CTS_HMAC_SHA1_96: u8 = 0x12;

const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x10];

const PA_ENC_TIMESTAMP: [u8; 1] = [0x02];
const PA_ENC_TIMESTAMP_KEY_USAGE: i32 = 1;
const PA_PAC_REQUEST_TYPE: [u8; 2] = [0x00, 0x80];

const MAX_MICROSECONDS_IN_SECOND: u32 = 999_999;

#[allow(dead_code)]
#[allow(unreachable_code)]
pub fn generate_as_req(username: String, password: String, realm: String) -> AsReq {
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
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
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
                    KerberosStringAsn1::from(IA5String::from_string(username).unwrap()),
                ])),
            }))),
            realm: ExplicitContextTag2::from(Realm::from(
                IA5String::from_string(realm.clone()).unwrap(),
            )),
            sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(SERVICE_NAME.into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(realm).unwrap()),
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

pub fn generate_tsg_req() -> TgsReq {
    todo!()
}

pub fn generate_ap_req() -> TgsReq {
    todo!()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::super::reqwest_client::ReqwestNetworkClient;
    use super::super::NetworkClient;
    use super::generate_as_req;

    #[test]
    fn test_as_req_generation() {
        let network_client = ReqwestNetworkClient::new();

        let as_req = generate_as_req("p2".into(), "qweQWE123!@#".into(), "QKATION.COM".into());

        let as_req = picky_asn1_der::to_vec(&as_req).unwrap();

        let mut data = vec![0; 4 + as_req.len()];
        data[0..4].copy_from_slice(&((as_req.len() as u32).to_be_bytes()));
        data[4..].copy_from_slice(&as_req);

        let response = network_client
            .send(url::Url::from_str("tcp://192.168.0.103:88").unwrap(), &data)
            .unwrap();

        println!("rep data: {:?}", response);
    }
}
