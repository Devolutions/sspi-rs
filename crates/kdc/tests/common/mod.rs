//! A minimal Kerberos client used to drive the KDC through its public interface.
//!
//! It does not use `sspi`, so the message builder is independent of the code under test.

#![allow(dead_code, reason = "each test binary uses a different subset of the helpers")]
#![allow(
    unreachable_pub,
    reason = "the module is private to each test binary; `pub` marks the helper API"
)]
#![allow(clippy::panic, reason = "test helpers fail the test by panicking")]
#![allow(clippy::large_enum_variant, reason = "test-only reply wrapper")]

use std::time::Duration;

use kdc::config::{DomainUser, KerberosServer};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    ExplicitContextTag11, GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::key_usages::{
    AS_REP_ENC, AS_REQ_TIMESTAMP, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, TICKET_REP,
};
use picky_krb::constants::types::{
    AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, ENC_AS_REP_PART_TYPE, ENC_TGS_REP_PART_TYPE, NT_PRINCIPAL, NT_SRV_INST,
    PA_ENC_TIMESTAMP, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE,
};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, EncTicketPart, EncTicketPartInner, EncryptedData, EncryptionKey, KerberosFlags,
    KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc, PrincipalName, Realm, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::messages::{
    ApReq, ApReqInner, AsRep, AsReq, EncKdcRepPart, KdcProxyMessage, KdcReq, KdcReqBody, KrbError, TgsRep, TgsReq,
};
use time::OffsetDateTime;

pub const REALM: &str = "EXAMPLE.COM";
pub const HOSTNAME: &str = "gateway.example.com";
pub const USER: &str = "user";
pub const PASSWORD: &str = "password";
pub const SALT: &str = "EXAMPLE.COMuser";
pub const MAX_SKEW_SECS: u64 = 300;
pub const KRBTGT_KEY: [u8; 32] = [0x11; 32];
pub const SERVICE_KEY: [u8; 32] = [0x22; 32];

/// `KDCOptions` bit 28.
pub const ENC_TKT_IN_SKEY: u32 = 0x0000_0008;

pub fn domain_user(name: &str) -> DomainUser {
    DomainUser {
        username: format!("{name}@example.com"),
        password: PASSWORD.to_owned().into(),
        salt: SALT.to_owned(),
    }
}

pub fn kdc_config() -> KerberosServer {
    KerberosServer {
        realm: REALM.to_owned(),
        users: vec![domain_user(USER)],
        max_time_skew: MAX_SKEW_SECS,
        krbtgt_key: KRBTGT_KEY.to_vec().into(),
        ticket_decryption_key: Some(SERVICE_KEY.to_vec().into()),
        service_user: None,
    }
}

pub fn kstr(s: &str) -> KerberosStringAsn1 {
    KerberosStringAsn1::from(IA5String::from_string(s.to_owned()).unwrap())
}

pub fn realm(s: &str) -> Realm {
    kstr(s)
}

pub fn principal(name_type: u8, names: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(names.iter().map(|n| kstr(n)).collect::<Vec<_>>())),
    }
}

pub fn ktime(t: OffsetDateTime) -> KerberosTime {
    GeneralizedTimeAsn1::from(GeneralizedTime::from(t))
}

pub fn flags(bits: u32) -> KerberosFlags {
    KerberosFlags::from(BitString::with_bytes(bits.to_be_bytes().to_vec()))
}

pub fn etype_id(etype: &CipherSuite) -> Vec<u8> {
    vec![u8::from(etype.clone())]
}

/// The DER bytes of an etype number from `picky_krb::constants::etypes`.
pub fn etype_number(etype: usize) -> Vec<u8> {
    vec![etype_byte(etype)]
}

/// An etype number from `picky_krb::constants::etypes` as a byte.
pub fn etype_byte(etype: usize) -> u8 {
    u8::try_from(etype).expect("etype numbers used in tests fit a byte")
}

pub fn user_key(etype: &CipherSuite) -> Vec<u8> {
    etype
        .cipher()
        .generate_key_from_password(PASSWORD.as_bytes(), SALT.as_bytes())
        .unwrap()
}

pub fn etype_list(etypes: &[CipherSuite]) -> Asn1SequenceOf<IntegerAsn1> {
    Asn1SequenceOf::from(
        etypes
            .iter()
            .map(|e| IntegerAsn1::from(etype_id(e)))
            .collect::<Vec<_>>(),
    )
}

/// A well-formed AS-REQ body for [USER]: AES256 only, `krbtgt/REALM`, one hour lifetime.
pub fn as_req_body() -> KdcReqBody {
    KdcReqBody {
        kdc_options: ExplicitContextTag0::from(flags(0)),
        cname: Optional::from(Some(ExplicitContextTag1::from(principal(NT_PRINCIPAL, &[USER])))),
        realm: ExplicitContextTag2::from(realm(REALM)),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal(
            NT_SRV_INST,
            &["krbtgt", REALM],
        )))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(ktime(OffsetDateTime::now_utc() + Duration::from_secs(3600))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(vec![0x01, 0x02, 0x03, 0x04])),
        etype: ExplicitContextTag8::from(etype_list(&[CipherSuite::Aes256CtsHmacSha196])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    }
}

pub fn kdc_req(msg_type: u8, padata: Option<Vec<PaData>>, body: KdcReqBody) -> KdcReq {
    KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![5])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![msg_type])),
        padata: Optional::from(padata.map(|p| ExplicitContextTag3::from(Asn1SequenceOf::from(p)))),
        req_body: ExplicitContextTag4::from(body),
    }
}

pub fn as_req(padata: Option<Vec<PaData>>, body: KdcReqBody) -> AsReq {
    AsReq::from(kdc_req(AS_REQ_MSG_TYPE, padata, body))
}

pub fn tgs_req(padata: Option<Vec<PaData>>, body: KdcReqBody) -> TgsReq {
    TgsReq::from(kdc_req(TGS_REQ_MSG_TYPE, padata, body))
}

/// PA-ENC-TIMESTAMP encrypted with `key`.
pub fn enc_timestamp(etype: &CipherSuite, key: &[u8], client_time: OffsetDateTime) -> PaData {
    let plain = picky_asn1_der::to_vec(&PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(ktime(client_time)),
        pausec: Optional::from(None),
    })
    .unwrap();
    let cipher = etype.cipher().encrypt(key, AS_REQ_TIMESTAMP, &plain).unwrap();

    PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&encrypted_data(u8::from(etype.clone()), cipher)).unwrap(),
        )),
    }
}

/// PA-ENC-TIMESTAMP for [USER] with the correct password and the current time.
pub fn valid_enc_timestamp() -> PaData {
    let etype = CipherSuite::Aes256CtsHmacSha196;
    enc_timestamp(&etype, &user_key(&etype), OffsetDateTime::now_utc())
}

/// An `EncryptedData` with an arbitrary etype number.
pub fn encrypted_data(etype: u8, cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![etype])),
        kvno: Optional::from(None),
        cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
    }
}

/// Wraps the encoded Kerberos message in a KKDCP message that declares `prefix` as the message length.
pub fn kkdcp_message(raw: &[u8], prefix: u32) -> KdcProxyMessage {
    let mut framed = prefix.to_be_bytes().to_vec();
    framed.extend_from_slice(raw);

    KdcProxyMessage::from_raw_kerb_message(&framed).unwrap()
}

/// Wraps the encoded Kerberos message in a KKDCP message, sends it, and returns the raw Kerberos reply.
/// The length prefix of the reply is stripped.
pub fn exchange_raw(raw: &[u8], config: &KerberosServer) -> Vec<u8> {
    let message = kkdcp_message(raw, u32::try_from(raw.len()).unwrap());

    let reply = kdc::handle_kdc_proxy_message(message, config, HOSTNAME).unwrap();
    reply.kerb_message.0.0[4..].to_vec()
}

pub enum Reply<R> {
    Ok(R),
    Err(KrbError),
}

impl<R> Reply<R> {
    #[track_caller]
    pub fn unwrap_err_code(self) -> u32 {
        match self {
            Reply::Ok(_) => panic!("expected KRB-ERROR, got a successful reply"),
            Reply::Err(e) => e.0.error_code.0,
        }
    }

    #[track_caller]
    pub fn unwrap_ok(self) -> R {
        match self {
            Reply::Ok(r) => r,
            Reply::Err(e) => panic!("expected a successful reply, got KRB-ERROR {}", e.0.error_code.0),
        }
    }
}

/// Decodes a raw reply as either an AS-REP or a KRB-ERROR.
pub fn parse_as_reply(raw: &[u8]) -> Reply<AsRep> {
    match picky_asn1_der::from_bytes::<AsRep>(raw) {
        Ok(rep) => Reply::Ok(rep),
        Err(_) => Reply::Err(picky_asn1_der::from_bytes(raw).expect("reply is neither AS-REP nor KRB-ERROR")),
    }
}

pub fn send_as(req: &AsReq, config: &KerberosServer) -> Reply<AsRep> {
    parse_as_reply(&exchange_raw(&picky_asn1_der::to_vec(req).unwrap(), config))
}

pub fn send_tgs(req: &TgsReq, config: &KerberosServer) -> Reply<TgsRep> {
    let raw = exchange_raw(&picky_asn1_der::to_vec(req).unwrap(), config);
    match picky_asn1_der::from_bytes::<TgsRep>(&raw) {
        Ok(rep) => Reply::Ok(rep),
        Err(_) => Reply::Err(picky_asn1_der::from_bytes(&raw).expect("reply is neither TGS-REP nor KRB-ERROR")),
    }
}

pub fn decrypt_as_rep_part(rep: &AsRep, key: &[u8]) -> EncKdcRepPart {
    let enc = &rep.0.enc_part.0;
    let plain = decrypt(&enc.etype.0.0, key, AS_REP_ENC, &enc.cipher.0.0);
    picky_asn1_der::from_bytes::<ApplicationTag<EncKdcRepPart, ENC_AS_REP_PART_TYPE>>(&plain)
        .unwrap()
        .0
}

pub fn decrypt_tgs_rep_part(rep: &TgsRep, key: &[u8], key_usage: i32) -> EncKdcRepPart {
    let enc = &rep.0.enc_part.0;
    let plain = decrypt(&enc.etype.0.0, key, key_usage, &enc.cipher.0.0);
    picky_asn1_der::from_bytes::<ApplicationTag<EncKdcRepPart, ENC_TGS_REP_PART_TYPE>>(&plain)
        .unwrap()
        .0
}

pub fn decrypt_ticket(ticket: &Ticket, key: &[u8]) -> EncTicketPartInner {
    let enc = &ticket.0.enc_part.0;
    let plain = decrypt(&enc.etype.0.0, key, TICKET_REP, &enc.cipher.0.0);
    picky_asn1_der::from_bytes::<EncTicketPart>(&plain).unwrap().0
}

fn decrypt(etype: &[u8], key: &[u8], usage: i32, cipher: &[u8]) -> Vec<u8> {
    CipherSuite::try_from(etype)
        .unwrap()
        .cipher()
        .decrypt(key, usage, cipher)
        .unwrap()
}

/// A TGT forged by the test, so that tests control every field the KDC reads.
pub struct Tgt {
    pub cname: PrincipalName,
    pub session_key: Vec<u8>,
    pub end_time: OffsetDateTime,
    /// Whole-second authentication time, so that it survives the `GeneralizedTime` round trip unchanged.
    pub auth_time: OffsetDateTime,
    pub krbtgt_key: Vec<u8>,
    /// Client name, realm and time written into the authenticator; they default to the ticket's values.
    pub auth_cname: PrincipalName,
    pub auth_crealm: &'static str,
    pub auth_ctime: OffsetDateTime,
    /// Ticket version number, realm, `TicketFlags` bits and optional start time of the TGT itself.
    pub tkt_vno: u8,
    pub ticket_realm: &'static str,
    pub ticket_flags: u32,
    pub start_time: Option<OffsetDateTime>,
    /// Etype number of the sub-session key in the authenticator.
    pub subkey_type: u8,
    /// Etype number of the session key in the ticket.
    /// The session key must have the length of that etype.
    pub key_type: u8,
    /// Replaces the encrypted part of the ticket and the encrypted authenticator.
    pub raw_ticket_enc_part: Option<EncryptedData>,
    pub raw_authenticator: Option<EncryptedData>,
}

impl Tgt {
    pub fn valid() -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            cname: principal(NT_PRINCIPAL, &[USER]),
            session_key: vec![0x33; 32],
            end_time: now + Duration::from_secs(3600),
            auth_time: OffsetDateTime::from_unix_timestamp(now.unix_timestamp() - 1800).unwrap(),
            krbtgt_key: KRBTGT_KEY.to_vec(),
            auth_cname: principal(NT_PRINCIPAL, &[USER]),
            auth_crealm: REALM,
            auth_ctime: now,
            tkt_vno: 5,
            ticket_realm: REALM,
            ticket_flags: 0,
            start_time: None,
            subkey_type: 18,
            key_type: 18,
            raw_ticket_enc_part: None,
            raw_authenticator: None,
        }
    }

    pub fn ticket(&self) -> Ticket {
        let enc_part = EncTicketPart::from(EncTicketPartInner {
            flags: ExplicitContextTag0::from(flags(self.ticket_flags)),
            key: ExplicitContextTag1::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![self.key_type])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(self.session_key.clone())),
            }),
            crealm: ExplicitContextTag2::from(realm(REALM)),
            cname: ExplicitContextTag3::from(self.cname.clone()),
            transited: ExplicitContextTag4::from(TransitedEncoding {
                tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
                contents: ExplicitContextTag1::from(OctetStringAsn1::from(vec![])),
            }),
            auth_time: ExplicitContextTag5::from(ktime(self.auth_time)),
            starttime: Optional::from(self.start_time.map(|start| ExplicitContextTag6::from(ktime(start)))),
            endtime: ExplicitContextTag7::from(ktime(self.end_time)),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(None),
        });
        let cipher = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .encrypt(
                &self.krbtgt_key,
                TICKET_REP,
                &picky_asn1_der::to_vec(&enc_part).unwrap(),
            )
            .unwrap();

        Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![self.tkt_vno])),
            realm: ExplicitContextTag1::from(realm(self.ticket_realm)),
            sname: ExplicitContextTag2::from(principal(NT_SRV_INST, &["krbtgt", REALM])),
            enc_part: ExplicitContextTag3::from(
                self.raw_ticket_enc_part
                    .clone()
                    .unwrap_or_else(|| encrypted_data(u8::from(CipherSuite::Aes256CtsHmacSha196), cipher)),
            ),
        })
    }

    /// PA-TGS-REQ for this TGT.
    /// `auth_key` encrypts the authenticator; `subkey` goes into it.
    pub fn pa_tgs_req(&self, auth_key: &[u8], subkey: Option<&[u8]>) -> PaData {
        let authenticator = Authenticator::from(AuthenticatorInner {
            authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            crealm: ExplicitContextTag1::from(realm(self.auth_crealm)),
            cname: ExplicitContextTag2::from(self.auth_cname.clone()),
            cksum: Optional::from(None),
            cusec: ExplicitContextTag4::from(IntegerAsn1::from(vec![0])),
            ctime: ExplicitContextTag5::from(ktime(self.auth_ctime)),
            subkey: Optional::from(subkey.map(|k| {
                ExplicitContextTag6::from(EncryptionKey {
                    key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![self.subkey_type])),
                    key_value: ExplicitContextTag1::from(OctetStringAsn1::from(k.to_vec())),
                })
            })),
            seq_number: Optional::from(None),
            authorization_data: Optional::from(None),
        });
        let cipher = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .encrypt(
                auth_key,
                TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
                &picky_asn1_der::to_vec(&authenticator).unwrap(),
            )
            .unwrap();

        let ap_req = ApReq::from(ApReqInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
            ap_options: ExplicitContextTag2::from(flags(0)),
            ticket: ExplicitContextTag3::from(self.ticket()),
            authenticator: ExplicitContextTag4::from(
                self.raw_authenticator
                    .clone()
                    .unwrap_or_else(|| encrypted_data(u8::from(CipherSuite::Aes256CtsHmacSha196), cipher)),
            ),
        });

        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_TGS_REQ_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&ap_req).unwrap())),
        }
    }
}

/// A PA-DATA with arbitrary content.
pub fn raw_pa_data(padata_type: &[u8], data: Vec<u8>) -> PaData {
    PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(padata_type.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(data)),
    }
}

/// The `padata` field of a request holding `list`.
pub fn padata_field(list: Vec<PaData>) -> Optional<Option<ExplicitContextTag3<Asn1SequenceOf<PaData>>>> {
    Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(list))))
}

/// A well-formed TGS-REQ body for `TERMSRV/HOSTNAME`.
pub fn tgs_req_body() -> KdcReqBody {
    let mut body = as_req_body();
    body.cname = Optional::from(None);
    body.sname = Optional::from(Some(ExplicitContextTag3::from(principal(
        NT_SRV_INST,
        &["TERMSRV", HOSTNAME],
    ))));
    body
}

/// A TGS-REQ for `TERMSRV/HOSTNAME` with a valid PA-TGS-REQ for `tgt`.
pub fn valid_tgs_request(tgt: &Tgt) -> TgsReq {
    tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), tgs_req_body())
}

/// A user-to-user TGS-REQ that carries the TGT of the service as the additional ticket.
pub fn u2u_request(tgt: &Tgt, additional: &Tgt) -> TgsReq {
    let mut body = tgs_req_body();
    body.kdc_options.0 = flags(ENC_TKT_IN_SKEY);
    body.additional_tickets = Optional::from(Some(ExplicitContextTag11::from(Asn1SequenceOf::from(vec![
        additional.ticket(),
    ]))));
    tgs_req(Some(vec![tgt.pa_tgs_req(&tgt.session_key, None)]), body)
}
