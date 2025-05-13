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
use picky_krb::constants::etypes::AES256_CTS_HMAC_SHA1_96;
use picky_krb::constants::key_usages::{
    AS_REP_ENC, TGS_REP_ENC_SESSION_KEY, TGS_REP_ENC_SUB_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, TICKET_REP,
};
use picky_krb::constants::types::{
    AS_REP_MSG_TYPE, KRB_ERROR_MSG_TYPE, PA_ENC_TIMESTAMP, PA_ENC_TIMESTAMP_KEY_USAGE, PA_ETYPE_INFO2_TYPE,
    PA_TGS_REQ_TYPE, TGS_REP_MSG_TYPE,
};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2Entry, KerberosStringAsn1, KerberosTime,
    LastReq, LastReqInner, Microseconds, PaData, PaEncTsEnc, PrincipalName, Realm, Ticket, TicketInner,
    TransitedEncoding,
};
use picky_krb::messages::{
    ApReq, ApReqInner, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcRep, KdcReq, KdcReqBody, KrbError,
    KrbErrorInner, TgsRep, TgsReq,
};
use rand::rngs::OsRng;
use rand::Rng;
use sspi::kerberos::KERBEROS_VERSION;
use time::{Duration, OffsetDateTime};

/// Represents user credentials in the internal KDC database.
pub struct PasswordCreds {
    /// User's password.
    pub password: Vec<u8>,
    /// Salt for deriving the encryption key.
    pub salt: String,
}

/// Represents user name in the internal KDC database.
///
/// We created a wrapper type because [PrincipalName] does not
/// implement the [Hash] trait.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserName(pub PrincipalName);

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
/// This KDC implementation performs only small amount of all possible checks on
/// the incoming Kerberos messages: encryption keys + key usage number usage
/// and some mandatory fields like `pa-datas`.
/// All other validations like checking user/service names should be done separately.
pub struct KdcMock {
    /// Domain's Kerberos realm.
    realm: String,
    /// Represents Kerberos long-term keys.
    keys: HashMap<UserName, Vec<u8>>,
    /// Represents users credentials.
    users: HashMap<UserName, PasswordCreds>,
}

impl KdcMock {
    /// Creates a new [KdcMock].
    pub fn new(realm: String, keys: HashMap<UserName, Vec<u8>>, users: HashMap<UserName, PasswordCreds>) -> Self {
        Self { realm, keys, users }
    }

    fn make_err<const ERROR_CODE: u32>(sname: PrincipalName, realm: Realm, salt: Option<String>) -> KrbError {
        let current_date = OffsetDateTime::now_utc();
        // https://www.rfc-editor.org/rfc/rfc4120#section-5.2.4
        // Microseconds    ::= INTEGER (0..999999)
        let microseconds = current_date.microsecond().min(999_999);

        KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![KERBEROS_VERSION])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![KRB_ERROR_MSG_TYPE])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            susec: ExplicitContextTag5::from(Microseconds::from(microseconds.to_be_bytes().to_vec())),
            error_code: ExplicitContextTag6::from(ERROR_CODE),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(realm),
            sname: ExplicitContextTag10::from(sname),
            e_text: Optional::from(None),
            e_data: Optional::from(Some(ExplicitContextTag12::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&Asn1SequenceOf::from(if let Some(salt) = salt {
                    vec![
                        PaData {
                            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ETYPE_INFO2_TYPE.to_vec())),
                            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                                picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![EtypeInfo2Entry {
                                    etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![
                                        AES256_CTS_HMAC_SHA1_96 as u8,
                                    ])),
                                    salt: Optional::from(Some(ExplicitContextTag1::from(KerberosStringAsn1::from(
                                        IA5String::from_string(salt).unwrap(),
                                    )))),
                                    s2kparams: Optional::from(None),
                                }]))
                                .unwrap(),
                            )),
                        },
                        PaData {
                            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
                            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
                        },
                    ]
                } else {
                    Vec::new()
                }))
                .unwrap(),
            )))),
        })
    }

    fn validate_timestamp(
        creds: &PasswordCreds,
        sname: PrincipalName,
        realm: Realm,
        pa_datas: &Asn1SequenceOf<PaData>,
    ) -> Result<Vec<u8>, KrbError> {
        macro_rules! err_preauth {
            (failed) => {
                Self::make_err::<{ KDC_ERR_PREAUTH_FAILED }>(sname.clone(), realm.clone(), Some(creds.salt.clone()))
            };
            (required) => {
                Self::make_err::<{ KDC_ERR_PREAUTH_REQUIRED }>(sname.clone(), realm.clone(), Some(creds.salt.clone()))
            };
        }

        let enc_data: EncryptedData = picky_asn1_der::from_bytes(
            &pa_datas
                .0
                .iter()
                .find(|pa_data| pa_data.padata_type.0 .0 == PA_ENC_TIMESTAMP)
                .ok_or_else(|| err_preauth!(required))?
                .padata_data
                .0
                 .0,
        )
        .map_err(|_| err_preauth!(failed))?;

        let cipher = CipherSuite::try_from(enc_data.etype.0 .0.as_slice())
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

        Ok(key)
    }

    /// Performs AS exchange according to the RFC.
    ///
    /// https://www.rfc-editor.org/rfc/rfc4120#section-3.1
    pub fn as_exchange(&self, as_req: AsReq) -> Result<AsRep, KrbError> {
        let KdcReq {
            pvno: _,
            msg_type: _,
            padata,
            req_body,
        } = as_req.0;
        let KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from: _,
            till: _,
            rtime: _,
            nonce: _,
            etype: _,
            addresses: _,
            enc_authorization_data: _,
            additional_tickets: _,
        } = req_body.0;

        let sname = sname.0.expect("sname must present in AsReq").0;
        let service_key = self
            .keys
            .get(&UserName(sname.clone()))
            .expect("service's key must present in KDC database");
        let realm = realm.0;
        let username = UserName(cname.0.expect("cname is missing in AsReq").0);
        let creds = self
            .users
            .get(&username)
            .expect("user's credentials is not found in KDC database");

        KdcMock::validate_timestamp(
            creds,
            sname.clone(),
            realm.clone(),
            &padata
                .0
                .ok_or_else(|| {
                    Self::make_err::<{ KDC_ERR_PREAUTH_REQUIRED }>(sname.clone(), realm, Some(creds.salt.clone()))
                })?
                .0,
        )?;
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
            auth_time: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(auth_time))),
            starttime: Optional::from(None),
            endtime: ExplicitContextTag7::from(KerberosTime::from(GeneralizedTime::from(end_time))),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(None),
        };
        let ticket_enc_data = cipher
            .encrypt(
                service_key,
                TICKET_REP,
                &picky_asn1_der::to_vec(&ticket_enc_part).unwrap(),
            )
            .unwrap();

        let as_rep_enc_part = EncAsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
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
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AS_REP_MSG_TYPE])),
            padata: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(vec![PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ETYPE_INFO2_TYPE.to_vec())),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                    picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![EtypeInfo2Entry {
                        etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
                        salt: Optional::from(Some(ExplicitContextTag1::from(KerberosStringAsn1::from(
                            IA5String::from_string(creds.salt.clone()).unwrap(),
                        )))),
                        s2kparams: Optional::from(None),
                    }]))
                    .unwrap(),
                )),
            }])))),
            crealm: ExplicitContextTag3::from(realm.clone()),
            cname: ExplicitContextTag4::from(username.0),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
                realm: ExplicitContextTag1::from(realm),
                sname: ExplicitContextTag2::from(sname),
                enc_part: ExplicitContextTag3::from(EncryptedData {
                    etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
                    kvno: Optional::from(None),
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(ticket_enc_data)),
                }),
            })),
            enc_part: ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(as_rep_enc_data)),
            }),
        }))
    }

    fn tgs_preauth(
        &self,
        sname: PrincipalName,
        realm: Realm,
        pa_datas: &Asn1SequenceOf<PaData>,
    ) -> Result<(Vec<u8>, PrincipalName, i32), KrbError> {
        macro_rules! err_preauth {
            (failed) => {
                Self::make_err::<{ KDC_ERR_PREAUTH_FAILED }>(sname.clone(), realm.clone(), None)
            };
            (required) => {
                Self::make_err::<{ KDC_ERR_PREAUTH_REQUIRED }>(sname.clone(), realm.clone(), None)
            };
        }

        let ap_req: ApReq = picky_asn1_der::from_bytes(
            &pa_datas
                .0
                .iter()
                .find(|pa_data| pa_data.padata_type.0 .0 == PA_TGS_REQ_TYPE)
                .ok_or_else(|| err_preauth!(required))?
                .padata_data
                .0
                 .0,
        )
        .map_err(|_| err_preauth!(failed))?;

        let ApReqInner {
            pvno: _,
            msg_type: _,
            ap_options: _,
            ticket,
            authenticator,
        } = ap_req.0;
        let TicketInner {
            sname: ticket_sname,
            enc_part: ticket_enc_data,
            ..
        } = ticket.0 .0;

        let cipher = CipherSuite::try_from(ticket_enc_data.etype.0 .0.as_slice())
            .map_err(|_| err_preauth!(failed))?
            .cipher();

        let service_key = self
            .keys
            .get(&UserName(ticket_sname.0))
            .expect("service's key must present in KDC database");
        let ticket_enc_part: EncTicketPart = picky_asn1_der::from_bytes(
            &cipher
                .decrypt(service_key, TICKET_REP, &ticket_enc_data.cipher.0 .0)
                .expect("TGS REQ - TGT Ticket decryption should not fail"),
        )
        .expect("TGT Ticket enc part decoding should not fail");

        let EncTicketPart { key, cname, .. } = ticket_enc_part;
        let session_key = key.0.key_value.0 .0;

        let authenticator_enc_data = authenticator.0;
        let cipher = CipherSuite::try_from(authenticator_enc_data.etype.0 .0.as_slice())
            .map_err(|_| err_preauth!(failed))?
            .cipher();

        let authenticator: Authenticator = picky_asn1_der::from_bytes(
            &cipher
                .decrypt(
                    &session_key,
                    TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
                    &authenticator_enc_data.cipher.0 .0,
                )
                .expect("TGS REQ - Authenticator decryption should no fail"),
        )
        .expect("Authenticator decoding should not fail");

        Ok(if let Some(key) = authenticator.0.subkey.0 {
            (key.0.key_value.0 .0, cname.0, TGS_REP_ENC_SUB_KEY)
        } else {
            (session_key, cname.0, TGS_REP_ENC_SESSION_KEY)
        })
    }

    /// Performs TGS exchange according to the RFC.
    ///
    /// https://www.rfc-editor.org/rfc/rfc4120#section-3.3
    pub fn tgs_exchange(&self, tgs_req: TgsReq) -> Result<TgsRep, KrbError> {
        let KdcReq {
            pvno: _,
            msg_type: _,
            padata,
            req_body,
        } = tgs_req.0;
        let KdcReqBody {
            kdc_options,
            cname: _,
            realm: _,
            sname,
            from: _,
            till: _,
            rtime: _,
            nonce: _,
            etype: _,
            addresses: _,
            enc_authorization_data: _,
            additional_tickets,
        } = req_body.0;

        let sname = sname.0.expect("sname must present in TgsReq").0;
        let realm = Realm::from(IA5String::from_string(self.realm.clone()).unwrap());
        let (initial_key, cname, tgs_rep_key_usage) = self.tgs_preauth(
            sname.clone(),
            realm.clone(),
            &padata
                .0
                .ok_or_else(|| Self::make_err::<{ KDC_ERR_PREAUTH_REQUIRED }>(sname.clone(), realm.clone(), None))?
                .0,
        )?;

        let ticket_enc_key = if let Some(tgt_ticket) = additional_tickets.0 {
            let TicketInner { sname, enc_part, .. } = tgt_ticket
                .0
                 .0
                .into_iter()
                .next()
                .expect("array of additional tickets must not be empty")
                .0;
            let key = self
                .keys
                .get(&UserName(sname.0))
                .expect("service's key must present in KDC database");
            let EncryptedData {
                etype,
                cipher: ticket_enc_data,
                kvno: _,
            } = enc_part.0;

            let cipher = CipherSuite::try_from(etype.0 .0.as_slice())
                .expect("ticket etype should be valid")
                .cipher();

            let ticket_enc_part: EncTicketPart =
                picky_asn1_der::from_bytes(&cipher.decrypt(key, TICKET_REP, &ticket_enc_data.0 .0).unwrap())
                    .expect("TGT Ticket enc part decoding should not fail");
            ticket_enc_part.key.0.key_value.0 .0
        } else {
            self.keys
                .get(&UserName(sname.clone()))
                .expect("service's key must present in KDC database")
                .to_vec()
        };

        let mut rng = OsRng;
        let session_key = rng.gen::<[u8; 32]>();

        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
        let auth_time = OffsetDateTime::now_utc();
        let end_time = auth_time + Duration::days(1);

        let ticket_enc_part = EncTicketPart {
            flags: kdc_options.clone(),
            key: ExplicitContextTag1::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.to_vec())),
            }),
            crealm: ExplicitContextTag2::from(realm.clone()),
            cname: ExplicitContextTag3::from(cname.clone()),
            transited: ExplicitContextTag4::from(TransitedEncoding {
                // the client is unable to check these fields, so we can put any values we want
                tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
                contents: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1])),
            }),
            auth_time: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(auth_time))),
            starttime: Optional::from(None),
            endtime: ExplicitContextTag7::from(KerberosTime::from(GeneralizedTime::from(end_time))),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(None),
        };
        let ticket_enc_data = cipher
            .encrypt(
                &ticket_enc_key,
                TICKET_REP,
                &picky_asn1_der::to_vec(&ticket_enc_part).unwrap(),
            )
            .unwrap();

        let tgs_rep_enc_part = EncTgsRepPart::from(EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
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
        let tgs_rep_enc_data = cipher
            .encrypt(
                &initial_key,
                tgs_rep_key_usage,
                &picky_asn1_der::to_vec(&tgs_rep_enc_part).unwrap(),
            )
            .unwrap();

        Ok(TgsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGS_REP_MSG_TYPE])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(realm.clone()),
            cname: ExplicitContextTag4::from(cname),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
                realm: ExplicitContextTag1::from(realm),
                sname: ExplicitContextTag2::from(sname),
                enc_part: ExplicitContextTag3::from(EncryptedData {
                    etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
                    kvno: Optional::from(None),
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(ticket_enc_data)),
                }),
            })),
            enc_part: ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![AES256_CTS_HMAC_SHA1_96 as u8])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(tgs_rep_enc_data)),
            }),
        }))
    }
}
