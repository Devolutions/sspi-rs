use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10, ExplicitContextTag12,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6,
    ExplicitContextTag7, ExplicitContextTag9, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::error_codes::{KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED};
use picky_krb::constants::key_usages::{AS_REP_ENC, TICKET_REP};
use picky_krb::constants::types::PA_ENC_TIMESTAMP_KEY_USAGE;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2Entry, KerberosStringAsn1, KerberosTime, LastReq,
    LastReqInner, Microseconds, PaData, PaEncTsEnc, PrincipalName, Realm, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::messages::{
    AsRep, AsReq, EncAsRepPart, EncKdcRepPart, KdcRep, KdcReq, KdcReqBody, KrbError, KrbErrorInner,
};
use rand::rngs::OsRng;
use rand::Rng;
use time::{Duration, OffsetDateTime};

pub struct PasswordCreds {
    pub password: Vec<u8>,
    pub salt: String,
}

/// Represents user name in internal KDC database.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserName(PrincipalName);

impl Hash for UserName {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.name_type.0 .0.hash(state);
        self.0.name_string.0 .0.iter().for_each(|s| s.0.hash(state))
    }
}

/// Simple mock of the KDC server.
///
/// We use it to test our Kerberos implementation.
pub struct KdcMock {
    /// Domain's Kerberos realm.
    realm: String,
    /// Represents Kerberos long-term keys.
    keys: HashMap<UserName, Vec<u8>>,
    /// Represents users credentials.
    users: HashMap<UserName, PasswordCreds>,
}

impl KdcMock {
    pub fn new(realm: String, keys: HashMap<UserName, Vec<u8>>, users: HashMap<UserName, PasswordCreds>) -> Self {
        Self { realm, keys, users }
    }

    fn gen_err<const ErrorCode: u32>(sname: PrincipalName, realm: Realm, salt: String) -> KrbError {
        let current_date = OffsetDateTime::now_utc();
        let microseconds = current_date.microsecond().min(999_999);

        KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![30])), // KRB_ERR
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            susec: ExplicitContextTag5::from(Microseconds::from(microseconds.to_be_bytes().to_vec())),
            error_code: ExplicitContextTag6::from(ErrorCode),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(realm),
            sname: ExplicitContextTag10::from(sname),
            e_text: Optional::from(None),
            e_data: Optional::from(Some(ExplicitContextTag12::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![
                    PaData {
                        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![19])), // ETYPE-INFO2
                        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                            picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![EtypeInfo2Entry {
                                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])), // AES256-CTS-HMAC-SHA1-96
                                salt: Optional::from(Some(ExplicitContextTag1::from(KerberosStringAsn1::from(
                                    IA5String::from_string(salt).unwrap(),
                                )))),
                                s2kparams: Optional::from(None),
                            }]))
                            .unwrap(),
                        )),
                    },
                    PaData {
                        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![2])), // PA-ENC-TIMESTAMP
                        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
                    },
                ]))
                .unwrap(),
            )))),
        })
    }

    fn validate_timestamp(
        creds: &PasswordCreds,
        sname: PrincipalName,
        realm: Realm,
        pa_datas: &Asn1SequenceOf<PaData>,
    ) -> Result<(), KrbError> {
        macro_rules! err_preauth {
            (failed) => {
                Self::gen_err::<{ KDC_ERR_PREAUTH_FAILED }>(sname.clone(), realm.clone(), creds.salt.clone())
            };
            (required) => {
                Self::gen_err::<{ KDC_ERR_PREAUTH_REQUIRED }>(sname.clone(), realm.clone(), creds.salt.clone())
            };
        }

        let enc_data: EncryptedData = picky_asn1_der::from_bytes(
            &pa_datas
                .0
                .iter()
                .find(|pa_data| pa_data.padata_type.0 .0 == &[2]) // PA-ENC-TIMESTAMP
                .ok_or_else(|| err_preauth!(required))?
                .padata_data
                .0
                 .0,
        )
        .map_err(|_| err_preauth!(failed))?;

        let mut cipher = CipherSuite::try_from(enc_data.etype.0 .0.as_slice())
            .map_err(|_| err_preauth!(failed))?
            .cipher();

        let key = cipher
            .generate_key_from_password(&creds.password, creds.salt.as_bytes())
            .unwrap();

        let timestamp: PaEncTsEnc = picky_asn1_der::from_bytes(
            &cipher
                .decrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &enc_data.cipher.0 .0)
                .map_err(|_| err_preauth!(failed))?,
        )
        .map_err(|_| err_preauth!(failed))?;

        let kdc_timestamp = OffsetDateTime::now_utc();
        let client_timestamp = OffsetDateTime::try_from(timestamp.patimestamp.0 .0)
            .map_err(|_| err_preauth!(failed))
            .map_err(|_| err_preauth!(failed))?;

        if client_timestamp > kdc_timestamp || kdc_timestamp - client_timestamp > Duration::minutes(3) {
            return Err(err_preauth!(failed));
        }

        Ok(())
    }

    pub fn as_exchange(&mut self, as_req: AsReq) -> Result<AsRep, KrbError> {
        let KdcReq {
            pvno,
            msg_type,
            padata,
            req_body,
        } = as_req.0;
        let KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etype,
            addresses,
            enc_authorization_data,
            additional_tickets,
        } = req_body.0;

        let sname = sname.0.expect("sname must present in AsReq").0;
        let realm = realm.0;
        let username = UserName(cname.0.expect("cname is missing in AsReq").0);
        let creds = self
            .users
            .get(&username)
            .expect("user's credentials is not found in KDC database");

        KdcMock::validate_timestamp(
            &creds,
            sname.clone(),
            realm.clone(),
            &padata
                .0
                .ok_or_else(|| Self::gen_err::<{ KDC_ERR_PREAUTH_REQUIRED }>(sname.clone(), realm, creds.salt.clone()))?
                .0,
        )?;

        // generate ticket
        let user_key = self
            .keys
            .get(&username)
            .expect("user's long-term key is missing in KDC database");
        let mut rng = OsRng;
        let session_key = rng.gen::<[u8; 32]>();

        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
        let initial_key = cipher
            .generate_key_from_password(&creds.password, creds.salt.as_bytes())
            .unwrap();

        let auth_time = OffsetDateTime::now_utc();
        let end_time = auth_time + Duration::days(1);
        let realm = Realm::from(IA5String::from_string(self.realm.clone()).unwrap());

        let ticket_enc_part = EncTicketPart {
            flags: kdc_options.clone(),
            key: ExplicitContextTag1::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.to_vec())),
            }),
            crealm: ExplicitContextTag2::from(realm.clone()),
            cname: ExplicitContextTag3::from(username.0.clone()),
            transited: ExplicitContextTag4::from(TransitedEncoding {
                // the client is unable to check these fields, so we can put any values we want
                tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
                contents: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1])),
            }),
            auth_time: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(auth_time.clone()))),
            starttime: Optional::from(None),
            endtime: ExplicitContextTag7::from(KerberosTime::from(GeneralizedTime::from(end_time.clone()))),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(None),
        };
        let ticket_enc_data = cipher
            .encrypt(user_key, TICKET_REP, &picky_asn1_der::to_vec(&ticket_enc_part).unwrap())
            .unwrap();

        let as_rep_enc_part = EncAsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.to_vec())),
            }),
            last_req: ExplicitContextTag1::from(LastReq::from(vec![LastReqInner {
                lr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
                lr_value: ExplicitContextTag1::from(KerberosTime::from(GeneralizedTime::from(
                    auth_time - Duration::hours(1),
                ))),
            }])),
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(rng.gen::<u32>().to_be_bytes().to_vec())),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(kdc_options.0),
            auth_time: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(auth_time))),
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(KerberosTime::from(GeneralizedTime::from(end_time))),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(realm.clone()),
            sname: ExplicitContextTag10::from(sname.clone()),
            caadr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        });
        let as_rep_enc_data = cipher
            .encrypt(
                &initial_key,
                AS_REP_ENC,
                &picky_asn1_der::to_vec(&as_rep_enc_part).unwrap(),
            )
            .unwrap();

        Ok(AsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![11])),
            padata: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(vec![PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![19])),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                    picky_asn1_der::to_vec(&EtypeInfo2Entry {
                        etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                        salt: Optional::from(Some(ExplicitContextTag1::from(KerberosStringAsn1::from(
                            IA5String::from_string(creds.salt.clone()).unwrap(),
                        )))),
                        s2kparams: Optional::from(None),
                    })
                    .unwrap(),
                )),
            }])))),
            crealm: ExplicitContextTag3::from(realm.clone()),
            cname: ExplicitContextTag4::from(username.0),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
                realm: ExplicitContextTag1::from(realm),
                sname: ExplicitContextTag2::from(sname),
                enc_part: ExplicitContextTag3::from(EncryptedData {
                    etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                    kvno: Optional::from(None),
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(ticket_enc_data)),
                }),
            })),
            enc_part: ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(as_rep_enc_data)),
            }),
        }))
    }
}
