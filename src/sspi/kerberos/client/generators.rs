use chrono::{Duration, Utc};
use kerberos_constants::key_usages::{KEY_USAGE_AP_REQ_AUTHEN, KEY_USAGE_TGS_REQ_AUTHEN};
use kerberos_crypto::new_kerberos_cipher;
use md5::{Digest, Md5};
use picky_asn1::{
    bit_string::BitString,
    date::GeneralizedTime,
    restricted_string::IA5String,
    wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
        ExplicitContextTag11, ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4,
        ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
        ExplicitContextTag9, GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
    },
};
use picky_krb::{
    constants::types::{
        AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP,
        PA_ENC_TIMESTAMP_KEY_USAGE, PA_PAC_OPTIONS_TYPE, PA_PAC_REQUEST_TYPE, PA_TGS_REQ_TYPE,
        TGS_REQ_MSG_TYPE,
    },
    data_types::{
        ApOptions, Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner,
        Checksum, EncryptedData, EncryptionKey, HostAddress, KerbPaPacRequest, KerberosFlags,
        KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc, PaPacOptions, PrincipalName, Realm,
        Ticket,
    },
    messages::{ApReq, ApReqInner, AsReq, KdcRep, KdcReq, KdcReqBody, TgsReq},
};
use rand::{rngs::OsRng, Rng};

use crate::sspi::kerberos::{EncryptionParams, KERBEROS_VERSION, SERVICE_NAME};

use super::{AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96};

const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;
const MAX_MICROSECONDS_IN_SECOND: u32 = 999_999;

const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x10];
const DEFAULT_TGS_REQ_OPTIONS: [u8; 4] = [0x40, 0x81, 0x00, 0x08];
const DEFAULT_PA_PAC_OPTIONS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

// AP-REQ toggled options:
// * mutual required
// * use session key
// other options are disabled
const DEFAULT_AP_REQ_OPTIONS: [u8; 4] = [0x60, 0x00, 0x00, 0x00];

pub fn generate_as_req_without_pre_auth(username: &str, realm: &str) -> AsReq {
    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

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
                IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8]),
                IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96 as u8]),
            ])),
            addresses: Optional::from(Some(ExplicitContextTag9::from(Asn1SequenceOf::from(vec![
                HostAddress {
                    addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x14])),
                    address: ExplicitContextTag1::from(OctetStringAsn1::from(vec![
                        68, 69, 83, 75, 84, 79, 80, 45, 70, 82, 67, 67, 86, 68, 80, 32,
                    ])),
                },
            ])))),
            enc_authorization_data: Optional::from(None),
            additional_tickets: Optional::from(None),
        }),
    })
}

pub fn generate_as_req(
    username: &str,
    salt: &[u8],
    password: &str,
    realm: &str,
    enc_params: &EncryptionParams,
) -> AsReq {
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

    let cipher = new_kerberos_cipher(
        enc_params
            .encryption_type
            .unwrap_or(AES256_CTS_HMAC_SHA1_96),
    )
    .unwrap();
    let key = cipher.generate_key_from_string(password, salt);

    let encrypted_timestamp = cipher.encrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &timestamp_bytes);

    let pa_enc_timestamp = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                    AES256_CTS_HMAC_SHA1_96 as u8,
                ])),
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
                IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8]),
                IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96 as u8]),
            ])),
            addresses: Optional::from(Some(ExplicitContextTag9::from(Asn1SequenceOf::from(vec![
                HostAddress {
                    addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x14])),
                    address: ExplicitContextTag1::from(OctetStringAsn1::from(vec![
                        68, 69, 83, 75, 84, 79, 80, 45, 70, 82, 67, 67, 86, 68, 80, 32,
                    ])),
                },
            ])))),
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
    mut authenticator: &mut Authenticator,
    additional_tickets: Option<Vec<Ticket>>,
    enc_params: &EncryptionParams,
) -> TgsReq {
    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let cipher = new_kerberos_cipher(
        enc_params
            .encryption_type
            .unwrap_or(AES256_CTS_HMAC_SHA1_96),
    )
    .unwrap();

    let enc_auth_data_encrypted = cipher.encrypt(
        session_key,
        4,
        &[
            48, 78, 48, 76, 160, 3, 2, 1, 1, 161, 69, 4, 67, 48, 65, 48, 63, 160, 4, 2, 2, 0, 141,
            161, 55, 4, 53, 48, 51, 48, 49, 160, 3, 2, 1, 0, 161, 42, 4, 40, 1, 0, 0, 0, 0, 32, 0,
            0, 241, 245, 67, 156, 37, 105, 241, 189, 203, 24, 218, 1, 196, 107, 27, 254, 109, 30,
            74, 117, 113, 162, 117, 172, 65, 141, 10, 17, 37, 233, 179, 154,
        ],
    );

    let req_body = KdcReqBody {
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
            IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8]),
            IntegerAsn1::from(vec![AES128_CTS_HMAC_SHA1_96 as u8]),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(
            Some(ExplicitContextTag10::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x12])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(enc_auth_data_encrypted)),
            })), // None
        ),
        additional_tickets: Optional::from(
            // None
            additional_tickets
                .map(|tickets| ExplicitContextTag11::from(Asn1SequenceOf::from(tickets))),
        ),
    };

    let mut md5 = Md5::new();
    md5.update(&&picky_asn1_der::to_vec(&req_body).unwrap());
    let checksum = md5.finalize();

    authenticator.0.cksum = Optional::from(Some(ExplicitContextTag3::from(Checksum {
        cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x07])),
        checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum.to_vec())),
    })));

    let raw_tgt_auth = picky_asn1_der::to_vec(&authenticator).unwrap();
    println!("raw_tgt_auth: {:?}", raw_tgt_auth);

    let pa_tgs_req = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_TGS_REQ_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&generate_tgs_ap_req(
                ticket,
                session_key,
                authenticator,
                enc_params,
            ))
            .unwrap(),
        )),
    };

    let pa_pac_options = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_OPTIONS_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&PaPacOptions {
                flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
                    DEFAULT_PA_PAC_OPTIONS.to_vec(),
                ))),
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
        req_body: ExplicitContextTag4::from(req_body),
    })
}

pub fn generate_authenticator_for_tgs_ap_req(kdc_rep: &KdcRep) -> Authenticator {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum: Optional::from(
            // Some(ExplicitContextTag3::from(Checksum {
            //     cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x07])),
            //     checksum: ExplicitContextTag1::from(OctetStringAsn1::from(vec![
            //         0x55, 0xdc, 0xdc, 0xab, 0x9a, 0x29, 0x99, 0xd1, 0x20, 0x5a, 0xe9, 0x8e, 0xc9,
            //         0x98, 0x6c, 0x6e,
            //     ])),
            // })),
            None,
        ),
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(None),
        seq_number: Optional::from(
            Some(ExplicitContextTag7::from(IntegerAsn1::from(
                OsRng::new().unwrap().gen::<u32>().to_be_bytes().to_vec(),
            ))), // None,
        ),
        authorization_data: Optional::from(None),
    })
}

pub fn generate_authenticator_for_ap_req(kdc_rep: &KdcRep, seq_num: u32) -> Authenticator {
    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x00, 0x80, 0x03])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(vec![
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00,
            ])),
        }))),
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(Some(ExplicitContextTag6::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                AES256_CTS_HMAC_SHA1_96 as u8,
            ])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(
                OsRng::new().unwrap().gen::<[u8; 32]>().to_vec(),
            )),
        }))),
        seq_number: Optional::from(Some(ExplicitContextTag7::from(
            IntegerAsn1::from_bytes_be_unsigned(seq_num.to_be_bytes().to_vec()),
        ))),
        authorization_data: Optional::from(Some(ExplicitContextTag8::from(
            AuthorizationData::from(vec![AuthorizationDataInner {
                ad_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x01])),
                ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(vec![
                    48, 96, 48, 14, 160, 4, 2, 2, 0, 143, 161, 6, 4, 4, 0, 64, 0, 0, 48, 78, 160,
                    4, 2, 2, 0, 144, 161, 70, 4, 68, 84, 0, 69, 0, 82, 0, 77, 0, 83, 0, 82, 0, 86,
                    0, 47, 0, 112, 0, 52, 0, 46, 0, 113, 0, 107, 0, 97, 0, 116, 0, 105, 0, 111, 0,
                    110, 0, 46, 0, 99, 0, 111, 0, 109, 0, 64, 0, 81, 0, 75, 0, 65, 0, 84, 0, 73, 0,
                    79, 0, 78, 0, 46, 0, 67, 0, 79, 0, 77, 0,
                ])),
            }]),
        ))),
    })
}

pub fn generate_tgs_ap_req(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
) -> ApReq {
    let cipher = new_kerberos_cipher(
        enc_params
            .encryption_type
            .unwrap_or(AES256_CTS_HMAC_SHA1_96),
    )
    .unwrap();

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_TGS_REQ_AUTHEN,
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
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                AES256_CTS_HMAC_SHA1_96 as u8,
            ])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    })
}

pub fn generate_ap_req(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
) -> ApReq {
    let cipher = new_kerberos_cipher(
        enc_params
            .encryption_type
            .unwrap_or(AES256_CTS_HMAC_SHA1_96),
    )
    .unwrap();

    println!(
        "ap_req_auth_raw: {:?}",
        picky_asn1_der::to_vec(&authenticator).unwrap()
    );

    let encrypted_authenticator = cipher.encrypt(
        session_key,
        KEY_USAGE_AP_REQ_AUTHEN,
        &picky_asn1_der::to_vec(&authenticator).unwrap(),
    );

    ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(
            DEFAULT_AP_REQ_OPTIONS.to_vec(),
        ))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                AES256_CTS_HMAC_SHA1_96 as u8,
            ])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    })
}
