use std::time::Duration;

use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag9,
    ExplicitContextTag10, ExplicitContextTag11, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::key_usages::TICKET_REP;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    EncTicketPart, EncTicketPartInner, EncryptedData, EncryptionKey, HostAddresses, KerberosFlags, KerberosTime,
    LastReq, LastReqInner, PrincipalName, Realm, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::messages::EncKdcRepPart;
use time::OffsetDateTime;

use crate::KERBEROS_VERSION;
use crate::error::KdcError;

// `TicketFlags` bit numbers, counted from the most significant bit.
// [RFC 4120 §5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3).

/// `invalid` ticket flag: the ticket is not valid until validated.
pub(super) const TICKET_FLAG_INVALID: usize = 7;
/// `initial` ticket flag: the ticket was issued by the AS exchange rather than on the basis of a TGT.
pub(super) const TICKET_FLAG_INITIAL: usize = 9;
/// `pre-authent` ticket flag: the client was pre-authenticated before the ticket was issued.
pub(super) const TICKET_FLAG_PRE_AUTHENT: usize = 10;
/// `hw-authent` ticket flag: the client was authenticated with a hardware token.
pub(super) const TICKET_FLAG_HW_AUTHENT: usize = 11;

/// Encodes the ticket flags with the given bit numbers set.
/// The KDC chooses the flags itself: they are not the client's `KDCOptions`.
pub(super) fn ticket_flags(bits: &[usize]) -> KerberosFlags {
    let value = bits.iter().fold(0u32, |acc, bit| acc | (1 << (31 - bit)));

    KerberosFlags::from(BitString::with_bytes(value.to_be_bytes().to_vec()))
}

pub(super) struct MakeTicketParams<'ticket_enc_key> {
    /// Realm of the server the ticket is issued for.
    pub realm: Realm,
    /// Realm of the client `cname`.
    pub client_realm: Realm,
    pub session_key: Vec<u8>,
    pub ticket_encryption_key: &'ticket_enc_key [u8],
    /// Etype of `ticket_encryption_key`.
    pub ticket_encryption_etype: CipherSuite,
    pub flags: KerberosFlags,
    pub sname: PrincipalName,
    pub cname: PrincipalName,
    pub etype: CipherSuite,
    pub auth_time: OffsetDateTime,
    pub start_time: OffsetDateTime,
    pub end_time: OffsetDateTime,
}

pub(super) fn make_ticket(params: MakeTicketParams<'_>) -> Result<Ticket, KdcError> {
    let MakeTicketParams {
        realm,
        client_realm,
        session_key,
        ticket_encryption_key,
        ticket_encryption_etype,
        flags,
        sname,
        cname,
        etype,
        auth_time,
        start_time,
        end_time,
    } = params;

    let ticket_enc_part = EncTicketPart::from(EncTicketPartInner {
        flags: ExplicitContextTag0::from(flags),
        key: ExplicitContextTag1::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(etype)])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key)),
        }),
        crealm: ExplicitContextTag2::from(client_realm),
        cname: ExplicitContextTag3::from(cname),
        transited: ExplicitContextTag4::from(TransitedEncoding {
            // the client is unable to check these fields, so we can put any values we want
            tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
            contents: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1])),
        }),
        auth_time: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(auth_time))),
        starttime: Optional::from(Some(ExplicitContextTag6::from(KerberosTime::from(
            GeneralizedTime::from(start_time),
        )))),
        endtime: ExplicitContextTag7::from(KerberosTime::from(GeneralizedTime::from(end_time))),
        renew_till: Optional::from(None),
        caddr: Optional::from(None),
        authorization_data: Optional::from(None),
    });

    // RFC (https://datatracker.ietf.org/doc/html/rfc4120#section-3.1.3):
    // > ...the server will encrypt the ciphertext part of the ticket using the encryption key extracted from the server
    // > principal's record in the Kerberos database using the encryption type associated with the server principal's key.
    // > (This choice is NOT affected by the etype field in the request.)
    let ticket_enc_data = ticket_encryption_etype.cipher().encrypt(
        ticket_encryption_key,
        TICKET_REP,
        &picky_asn1_der::to_vec(&ticket_enc_part)?,
    )?;

    Ok(Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        realm: ExplicitContextTag1::from(realm),
        sname: ExplicitContextTag2::from(sname),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(ticket_encryption_etype)])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(ticket_enc_data)),
        }),
    }))
}

pub(super) struct RepEncPartParams {
    pub etype: CipherSuite,
    pub session_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub flags: KerberosFlags,
    pub auth_time: OffsetDateTime,
    pub start_time: OffsetDateTime,
    pub end_time: OffsetDateTime,
    pub realm: Realm,
    pub sname: PrincipalName,
    pub addresses: Option<HostAddresses>,
}

/// Encrypts the `EncKDCRepPart` with `encryption_key`, whose etype is `encryption_etype` (the client's key, not `params.etype`).
pub(super) fn make_rep_enc_part<const TAG: u8>(
    params: RepEncPartParams,
    encryption_etype: &CipherSuite,
    encryption_key: &[u8],
    key_usage: i32,
) -> Result<Vec<u8>, KdcError> {
    let RepEncPartParams {
        etype,
        session_key,
        nonce,
        flags,
        auth_time,
        start_time,
        end_time,
        realm,
        sname,
        addresses,
    } = params;

    let enc_part = ApplicationTag::<_, TAG>::from(EncKdcRepPart {
        key: ExplicitContextTag0::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(etype.clone())])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key)),
        }),
        // RFC 4120 KRB_KDC_REP Definition (https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2):
        // > This field is returned by the KDC and specifies the time(s) of the last request by a principal.
        // > Depending on what information is available, this might be the last time that a request for a TGT,
        // > was made, or the last time that a request based on a TGT was successful...
        // > It is similar in spirit to the last login time displayed when logging in to timesharing systems.
        //
        // We do not track logons history. Moreover, this information is largely irrelevant to the actual authentication process.
        // So, we set the last request time to the ticket's auth time minus one minute.
        last_req: ExplicitContextTag1::from(LastReq::from(vec![LastReqInner {
            lr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
            lr_value: ExplicitContextTag1::from(KerberosTime::from(GeneralizedTime::from(
                auth_time - Duration::from_secs(60),
            ))),
        }])),
        // RFC (https://datatracker.ietf.org/doc/html/rfc4120#section-3.1):
        // > The encrypted part of the KRB_AS_REP message also contains the nonce
        // > that MUST be matched with the nonce from the KRB_AS_REQ message.
        nonce: ExplicitContextTag2::from(IntegerAsn1::from(nonce)),
        key_expiration: Optional::from(None),
        flags: ExplicitContextTag4::from(flags),
        auth_time: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(auth_time))),
        start_time: Optional::from(Some(ExplicitContextTag6::from(KerberosTime::from(
            GeneralizedTime::from(start_time),
        )))),
        end_time: ExplicitContextTag7::from(KerberosTime::from(GeneralizedTime::from(end_time))),
        renew_till: Optional::from(None),
        srealm: ExplicitContextTag9::from(realm),
        sname: ExplicitContextTag10::from(sname),
        // RFC (https://datatracker.ietf.org/doc/html/rfc4120#section-3.1.3):
        // > ...It then formats a KRB_AS_REP message, copying the addresses in the request into the caddr of the response...
        caddr: Optional::from(addresses.map(|addresses| ExplicitContextTag11::from(Asn1SequenceOf::from(addresses.0)))),
        encrypted_pa_data: Optional::from(None),
    });

    let enc_data = encryption_etype
        .cipher()
        .encrypt(encryption_key, key_usage, &picky_asn1_der::to_vec(&enc_part)?)?;

    Ok(enc_data)
}
