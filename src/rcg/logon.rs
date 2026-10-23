//! Remote Credential Guard logon credential.
//!
//! MS-CSSP [2.2.1.2.3 TSRemoteGuardCreds] and its behavior note 22 require the `logonCred` of
//! `TSRemoteGuardCreds` to be a `KERB_TICKET_LOGON`
//! whose `ServiceTicket` is a ticket to the computer account and whose `TicketGrantingTicket` is a
//! `KRB-CRED` encrypted with the session key of that service ticket. The `EncryptionKey` of the
//! `KrbCredInfo` is a `KERB_RPC_ENCRYPTION_KEY` (MS-RDPEAR [2.2.1.2.8 KERB_RPC_ENCRYPTION_KEY]), and the
//! TGT session key never leaves the client: its value is an opaque handle owned by the session.
//!
//! This logon construction was accepted in the bounded Windows integration described in [`crate::rcg`].
//! That result does not establish full native equivalence, realm-policy coverage, or reconnect support.
//! The implementation uses these explicit choices rather than native Windows ticket-cache selection:
//! - the computer account ticket is requested as `HOST/<target host>` (`NT-SRV-HST`), separately from the
//!   CredSSP ticket, because the CredSSP ticket may be a user-to-user ticket;
//! - the delegated TGT is a forwarded `krbtgt/<client realm>` ticket;
//! - the `KrbCredInfo` key is encoded as an RFC 4120 `EncryptionKey` whose `keyvalue` is the handle;
//! - `KERB_TICKET_LOGON.Flags` is `KERB_LOGON_FLAG_REDIRECTED`.
//!
//! [2.2.1.2.3 TSRemoteGuardCreds]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/7ef8229c-44ea-4c1b-867f-00369b882b38
//! [2.2.1.2.8 KERB_RPC_ENCRYPTION_KEY]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/

use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    ExplicitContextTag9, GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::cred_ssp::TS_REMOTE_GUARD_CREDS;
use picky_krb::constants::key_usages::{
    TGS_REP_ENC_SESSION_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_SRV_HST, NT_SRV_INST, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE};
use picky_krb::credssp::TsCredentials;
use picky_krb::crypto::CipherSuite;
use picky_krb::crypto::aes::checksum_sha_aes;
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, Checksum, EncryptedData, EncryptionKey, KerberosFlags,
    KerberosStringAsn1, KerberosTime, KrbResult, PaData, PrincipalName, Realm, ResultExt, Ticket,
};
use picky_krb::messages::{
    ApReq, ApReqInner, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcReq, KdcReqBody, TgsRep, TgsReq,
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::asn1::{
    EncKrbCredPart, EncKrbCredPartInner, KRB_CRED_ENC_PART_KEY_USAGE, KRB_CRED_MSG_TYPE, KrbCred, KrbCredInfo,
    KrbCredInner, TsRemoteGuardCreds, TsRemoteGuardPackageCred,
};
use super::key_store::KeyRole;
use super::ntlm::{NTLM_PACKAGE_NAME, NtlmCredential, NtlmRedirectionPolicy};
use super::{CapturedTgt, ClientBinding, KERBEROS_PACKAGE_NAME, etype_of, integer_to_i32, wrap};
use crate::generator::YieldPointLocal;
use crate::kerberos::client::generators::{generate_nonce, nonce_to_asn1};
use crate::kerberos::flags::KdcOptions;
use crate::kerberos::utils::serialize_message;
use crate::kerberos::{KERBEROS_VERSION, TGT_SERVICE_NAME};
use crate::utils::parse_target_name;
use crate::{Error, ErrorKind, Kerberos, KerberosState, Secret};

/// `KerbTicketLogon` value of `KERB_LOGON_SUBMIT_TYPE`.
pub(crate) const KERB_TICKET_LOGON_MESSAGE_TYPE: u32 = 10;
/// `KERB_LOGON_FLAG_REDIRECTED`: the ticket logon comes from a redirected (Remote Credential Guard) logon.
pub(crate) const KERB_LOGON_FLAG_REDIRECTED: u32 = 2;
/// Size of the fixed part of `KERB_TICKET_LOGON` on 64-bit Windows: four `ULONG`s and two pointers.
pub(crate) const KERB_TICKET_LOGON_HEADER_LEN: usize = 32;

/// Service name of the computer account ticket.
const COMPUTER_SERVICE_NAME: &str = "HOST";

/// Requested ticket lifetime. The KDC caps it to the lifetime of the TGT.
const REQUESTED_TICKET_LIFETIME: Duration = Duration::hours(10);

/// Default TGS-REQ options of this crate: renewable and canonicalize.
const DEFAULT_TGS_OPTIONS: KdcOptions = KdcOptions::RENEWABLE.union(KdcOptions::CANONICALIZE);

/// The `FORWARDED` ticket flag (RFC 4120 [5.3 Tickets]).
///
/// [5.3 Tickets]: https://www.rfc-editor.org/rfc/rfc4120#section-5.3
const TICKET_FLAG_FORWARDED_BIT: usize = 2;

/// HMAC-SHA1-96-AES128 checksum type ([RFC 3962]).
///
/// [RFC 3962]: https://www.rfc-editor.org/rfc/rfc3962
const HMAC_SHA1_96_AES128: u8 = 15;
/// HMAC-SHA1-96-AES256 checksum type ([RFC 3962]).
///
/// [RFC 3962]: https://www.rfc-editor.org/rfc/rfc3962
const HMAC_SHA1_96_AES256: u8 = 16;

fn kerberos_string(value: &str) -> crate::Result<KerberosStringAsn1> {
    Ok(KerberosStringAsn1::from(IA5String::from_string(value.to_owned())?))
}

fn principal_name(name_type: u8, names: &[&str]) -> crate::Result<PrincipalName> {
    Ok(PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
            names
                .iter()
                .map(|name| kerberos_string(name))
                .collect::<crate::Result<Vec<_>>>()?,
        )),
    })
}

fn kerberos_time(time: OffsetDateTime) -> KerberosTime {
    KerberosTime::from(GeneralizedTime::from(time))
}

fn checksum_type(cipher_suite: &CipherSuite) -> crate::Result<u8> {
    match cipher_suite {
        CipherSuite::Aes256CtsHmacSha196 => Ok(HMAC_SHA1_96_AES256),
        CipherSuite::Aes128CtsHmacSha196 => Ok(HMAC_SHA1_96_AES128),
        _ => Err(Error::new(
            ErrorKind::AlgorithmMismatch,
            "remote credential guard requires AES session keys",
        )),
    }
}

fn names_match(actual: &PrincipalName, expected: &PrincipalName) -> bool {
    let actual = &actual.name_string.0.0;
    let expected = &expected.name_string.0.0;

    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.0.as_bytes().eq_ignore_ascii_case(expected.0.as_bytes()))
}

/// Parameters of a TGS-REQ made with a captured TGT.
pub(super) struct TgsRequestOptions<'a> {
    pub(super) tgt: &'a CapturedTgt,
    pub(super) client: &'a ClientBinding,
    pub(super) sname: PrincipalName,
    pub(super) kdc_options: KdcOptions,
    pub(super) nonce: u32,
    pub(super) now: OffsetDateTime,
}

/// Builds a TGS-REQ (RFC 4120 [3.3.1 Generation of KRB_TGS_REQ Message]).
///
/// The PA-TGS-REQ authenticator carries a keyed checksum of the request body (key usage 6), and the
/// request offers only AES256 and AES128.
///
/// [3.3.1 Generation of KRB_TGS_REQ Message]: https://www.rfc-editor.org/rfc/rfc4120#section-3.3.1
pub(super) fn build_tgs_req(options: TgsRequestOptions<'_>) -> crate::Result<TgsReq> {
    let TgsRequestOptions {
        tgt,
        client,
        sname,
        kdc_options,
        nonce,
        now,
    } = options;

    let aes_size = wrap::aes_size(&tgt.cipher_suite)?;
    let till = now
        .checked_add(REQUESTED_TICKET_LIFETIME)
        .ok_or_else(|| Error::new(ErrorKind::TimeSkew, "ticket end time is out of range"))?;

    let req_body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            kdc_options.bits().to_be_bytes().to_vec(),
        ))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(Realm::from(IA5String::from_string(tgt.realm.clone())?)),
        sname: Optional::from(Some(ExplicitContextTag3::from(sname))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(till))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(nonce_to_asn1(nonce)),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![u8::from(&CipherSuite::Aes256CtsHmacSha196)]),
            IntegerAsn1::from(vec![u8::from(&CipherSuite::Aes128CtsHmacSha196)]),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    };

    let checksum = checksum_sha_aes(
        tgt.session_key.as_ref(),
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR_CKSUM,
        &picky_asn1_der::to_vec(&req_body)?,
        &aes_size,
    )?;

    let microseconds = now.microsecond();
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(client.realm_asn1()?),
        cname: ExplicitContextTag2::from(client.name.clone()),
        cksum: Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![checksum_type(&tgt.cipher_suite)?])),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum)),
        }))),
        cusec: ExplicitContextTag4::from(IntegerAsn1::from_bytes_be_unsigned(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(kerberos_time(now)),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });

    let encoded_authenticator = Zeroizing::new(picky_asn1_der::to_vec(&authenticator)?);
    let encrypted_authenticator = tgt.cipher_suite.cipher().encrypt(
        tgt.session_key.as_ref(),
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &encoded_authenticator,
    )?;

    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![0x00, 0x00, 0x00, 0x00]))),
        ticket: ExplicitContextTag3::from(tgt.ticket.clone()),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&tgt.cipher_suite)])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    });

    let pa_tgs_req = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_TGS_REQ_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&ap_req)?)),
    };

    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![pa_tgs_req])))),
        req_body: ExplicitContextTag4::from(req_body),
    }))
}

/// A verified TGS-REP.
pub(super) struct TgsReply {
    pub(super) ticket: Ticket,
    /// The decrypted reply. Its `key` value is emptied: the key is in `session_key`.
    pub(super) part: EncKdcRepPart,
    pub(super) cipher_suite: CipherSuite,
    pub(super) session_key: Secret<Vec<u8>>,
}

/// Decrypts and checks a TGS-REP obtained with `tgt` for a request with `nonce`.
///
/// The reply must be for `client`, be encrypted with the TGT session key, echo the nonce, name the
/// requested service, and carry an AES session key.
pub(super) fn process_tgs_rep(
    tgs_rep: TgsRep,
    tgt: &CapturedTgt,
    client: &ClientBinding,
    requested_sname: &PrincipalName,
    nonce: u32,
) -> crate::Result<TgsReply> {
    let tgs_rep = tgs_rep.0;

    if !tgs_rep
        .crealm
        .0
        .0
        .as_bytes()
        .eq_ignore_ascii_case(client.realm.as_bytes())
        || !names_match(&tgs_rep.cname.0, &client.name)
    {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "the TGS-REP client does not match the authenticated user",
        ));
    }

    if integer_to_i32(&tgs_rep.enc_part.0.etype.0)? != etype_of(&tgt.cipher_suite) {
        return Err(Error::new(
            ErrorKind::AlgorithmMismatch,
            "the TGS-REP is not encrypted with the encryption type of the TGT session key",
        ));
    }

    let plaintext = Zeroizing::new(
        tgt.cipher_suite
            .cipher()
            .decrypt(
                tgt.session_key.as_ref(),
                TGS_REP_ENC_SESSION_KEY,
                &tgs_rep.enc_part.0.cipher.0.0,
            )
            .map_err(|_| Error::new(ErrorKind::DecryptFailure, "failed to decrypt the TGS-REP"))?,
    );

    // RFC 4120 5.4.2: some KDCs use the EncASRepPart tag in TGS-REPs.
    let mut part = match picky_asn1_der::from_bytes::<EncTgsRepPart>(&plaintext) {
        Ok(part) => part.0,
        Err(_) => {
            picky_asn1_der::from_bytes::<EncAsRepPart>(&plaintext)
                .map_err(|_| Error::new(ErrorKind::InvalidToken, "invalid TGS-REP encrypted part"))?
                .0
        }
    };

    let expected_nonce =
        i32::try_from(nonce).map_err(|_| Error::new(ErrorKind::InternalError, "nonce is out of the Int32 range"))?;
    if integer_to_i32(&part.nonce.0)? != expected_nonce {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "the TGS-REP nonce does not match the request",
        ));
    }

    if !names_match(&part.sname.0, requested_sname) || !names_match(&tgs_rep.ticket.0.0.sname.0, requested_sname) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "the TGS-REP ticket is not for the requested service",
        ));
    }

    let cipher_suite = super::aes_cipher_suite(integer_to_i32(&part.key.0.key_type.0)?)?;
    let session_key = Secret::new(std::mem::take(&mut part.key.0.key_value.0.0));
    if session_key.as_ref().len() != cipher_suite.cipher().key_size() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "the TGS-REP session key length does not match its encryption type",
        ));
    }

    Ok(TgsReply {
        ticket: tgs_rep.ticket.0,
        part,
        cipher_suite,
        session_key,
    })
}

/// Builds the `KRB-CRED` that delegates `forwarded_tgt`.
///
/// The `KrbCredInfo` key is `(encryption type, key_handle)`, never the TGT session key. The encrypted part
/// is protected with the session key of the computer account ticket (key usage 14).
pub(super) fn build_krb_cred(
    client: &ClientBinding,
    forwarded_tgt: &TgsReply,
    key_handle: &[u8],
    service_ticket: &TgsReply,
    now: OffsetDateTime,
) -> crate::Result<Vec<u8>> {
    let part = &forwarded_tgt.part;
    let microseconds = now.microsecond();

    let info = KrbCredInfo {
        key: ExplicitContextTag0::from(EncryptionKey {
            key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&forwarded_tgt.cipher_suite)])),
            key_value: ExplicitContextTag1::from(OctetStringAsn1::from(key_handle.to_vec())),
        }),
        prealm: Optional::from(Some(ExplicitContextTag1::from(client.realm_asn1()?))),
        pname: Optional::from(Some(ExplicitContextTag2::from(client.name.clone()))),
        flags: Optional::from(Some(ExplicitContextTag3::from(part.flags.0.clone()))),
        auth_time: Optional::from(Some(ExplicitContextTag4::from(part.auth_time.0.clone()))),
        start_time: Optional::from(part.start_time.0.clone().map(|time| ExplicitContextTag5::from(time.0))),
        end_time: Optional::from(Some(ExplicitContextTag6::from(part.end_time.0.clone()))),
        renew_till: Optional::from(part.renew_till.0.clone().map(|time| ExplicitContextTag7::from(time.0))),
        srealm: Optional::from(Some(ExplicitContextTag8::from(part.srealm.0.clone()))),
        sname: Optional::from(Some(ExplicitContextTag9::from(part.sname.0.clone()))),
        caddr: Optional::from(None),
    };

    let enc_part = EncKrbCredPart::from(EncKrbCredPartInner {
        ticket_info: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![info])),
        nonce: Optional::from(None),
        timestamp: Optional::from(Some(ExplicitContextTag2::from(kerberos_time(now)))),
        usec: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from_bytes_be_unsigned(
            microseconds.to_be_bytes().to_vec(),
        )))),
        s_address: Optional::from(None),
        r_address: Optional::from(None),
    });

    let encoded_enc_part = Zeroizing::new(picky_asn1_der::to_vec(&enc_part)?);
    let cipher = service_ticket.cipher_suite.cipher().encrypt(
        service_ticket.session_key.as_ref(),
        KRB_CRED_ENC_PART_KEY_USAGE,
        &encoded_enc_part,
    )?;

    Ok(picky_asn1_der::to_vec(&KrbCred::from(KrbCredInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![KRB_CRED_MSG_TYPE])),
        tickets: ExplicitContextTag2::from(Asn1SequenceOf::from(vec![forwarded_tgt.ticket.clone()])),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(&service_ticket.cipher_suite)])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
        }),
    }))?)
}

/// Builds a self-relative `KERB_TICKET_LOGON` structure.
///
/// The layout is the 64-bit Windows layout: `MessageType`, `Flags`, `ServiceTicketLength`,
/// `TicketGrantingTicketLength` (little-endian `ULONG`s), then the `ServiceTicket` and `TicketGrantingTicket`
/// pointers encoded as 64-bit offsets from the start of the structure, followed by the two buffers.
pub(super) fn build_kerb_ticket_logon(service_ticket: &[u8], ticket_granting_ticket: &[u8]) -> crate::Result<Vec<u8>> {
    let length_error = || Error::new(ErrorKind::InvalidParameter, "ticket is too large for KERB_TICKET_LOGON");

    let service_ticket_len = u32::try_from(service_ticket.len()).map_err(|_| length_error())?;
    let ticket_granting_ticket_len = u32::try_from(ticket_granting_ticket.len()).map_err(|_| length_error())?;
    let service_ticket_offset = u64::try_from(KERB_TICKET_LOGON_HEADER_LEN).map_err(|_| length_error())?;
    let ticket_granting_ticket_offset = service_ticket_offset
        .checked_add(u64::from(service_ticket_len))
        .ok_or_else(length_error)?;

    let mut logon =
        Vec::with_capacity(KERB_TICKET_LOGON_HEADER_LEN + service_ticket.len() + ticket_granting_ticket.len());
    logon.extend_from_slice(&KERB_TICKET_LOGON_MESSAGE_TYPE.to_le_bytes());
    logon.extend_from_slice(&KERB_LOGON_FLAG_REDIRECTED.to_le_bytes());
    logon.extend_from_slice(&service_ticket_len.to_le_bytes());
    logon.extend_from_slice(&ticket_granting_ticket_len.to_le_bytes());
    logon.extend_from_slice(&service_ticket_offset.to_le_bytes());
    logon.extend_from_slice(&ticket_granting_ticket_offset.to_le_bytes());
    logon.extend_from_slice(service_ticket);
    logon.extend_from_slice(ticket_granting_ticket);

    Ok(logon)
}

/// Builds a DER-encoded `TSCredentials` with `credType` 6 and a Kerberos `TSRemoteGuardCreds`.
///
/// `ntlm_supplemental_credential` is an encoded `NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL` sent in
/// `supplementalCreds`.
pub(super) fn build_ts_credentials(
    kerb_ticket_logon: &[u8],
    ntlm_supplemental_credential: Option<&[u8]>,
) -> crate::Result<Zeroizing<Vec<u8>>> {
    let utf16 = |name: &str| name.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();

    let supplemental_creds = ntlm_supplemental_credential.map(|credential| {
        ExplicitContextTag1::from(Asn1SequenceOf::from(vec![TsRemoteGuardPackageCred {
            package_name: ExplicitContextTag0::from(OctetStringAsn1::from(utf16(NTLM_PACKAGE_NAME))),
            cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(credential.to_vec())),
        }]))
    });

    let remote_guard_creds = TsRemoteGuardCreds {
        logon_cred: ExplicitContextTag0::from(TsRemoteGuardPackageCred {
            package_name: ExplicitContextTag0::from(OctetStringAsn1::from(utf16(KERBEROS_PACKAGE_NAME))),
            cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(kerb_ticket_logon.to_vec())),
        }),
        supplemental_creds: Optional::from(supplemental_creds),
    };
    let encoded_creds = Zeroizing::new(picky_asn1_der::to_vec(&remote_guard_creds)?);

    let ts_credentials = TsCredentials {
        cred_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![TS_REMOTE_GUARD_CREDS])),
        credentials: ExplicitContextTag1::from(OctetStringAsn1::from(encoded_creds.to_vec())),
    };

    Ok(Zeroizing::new(picky_asn1_der::to_vec(&ts_credentials)?))
}

fn parse_tgs_rep(response: &[u8]) -> crate::Result<TgsRep> {
    // The first 4 bytes are the message length.
    let response = response.get(4..).ok_or_else(|| {
        Error::new(
            ErrorKind::InternalError,
            "the KDC reply message is too small: expected at least 4 bytes",
        )
    })?;

    // KRB-ERROR replies are reported as errors.
    let mut deserializer = picky_asn1_der::Deserializer::new_from_bytes(response);
    let tgs_rep = <KrbResult<TgsRep> as ResultExt<'_, TgsRep>>::deserialize(&mut deserializer)?;

    Ok(tgs_rep?)
}

impl Kerberos {
    /// Requests the delegated tickets and builds the `TSCredentials` of Remote Credential Guard.
    ///
    /// Must be called once, after the authentication completed. Any failure disables Remote Credential Guard
    /// for this context.
    pub(crate) async fn build_remote_guard_credentials(
        &mut self,
        yield_point: &mut YieldPointLocal,
        target_name: &str,
        ntlm: Option<&NtlmRedirectionPolicy>,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        let result = self
            .build_remote_guard_credentials_impl(yield_point, target_name, ntlm)
            .await;

        if result.is_err()
            && let Some(state) = self.remote_guard.as_deref_mut()
        {
            state.poison();
        }

        result
    }

    async fn build_remote_guard_credentials_impl(
        &mut self,
        yield_point: &mut YieldPointLocal,
        target_name: &str,
        ntlm: Option<&NtlmRedirectionPolicy>,
    ) -> crate::Result<Zeroizing<Vec<u8>>> {
        if self.state != KerberosState::Final {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "remote credential guard credentials require an established Kerberos context",
            ));
        }

        let state = self.remote_guard_mut()?;
        state.check_usable()?;
        if state.is_logon_built() {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                "remote credential guard credentials were already built",
            ));
        }

        let missing = || {
            Error::new(
                ErrorKind::InternalError,
                "remote credential guard authentication state is incomplete",
            )
        };
        let client = state.binding.clone().ok_or_else(missing)?;
        let service_tgt = state.service_tgt.take().ok_or_else(missing)?;
        let home_tgt = state.home_tgt.take().ok_or_else(missing)?;

        let mut rng = super::rng()?;

        // Ticket to the computer account of the target, from the KDC of the target realm.
        let (_, host) = parse_target_name(target_name)?;
        let computer_sname = principal_name(NT_SRV_HST, &[COMPUTER_SERVICE_NAME, host])?;
        let nonce = generate_nonce(&mut rng);
        let tgs_req = build_tgs_req(TgsRequestOptions {
            tgt: &service_tgt,
            client: &client,
            sname: computer_sname.clone(),
            kdc_options: DEFAULT_TGS_OPTIONS | KdcOptions::FORWARDABLE,
            nonce,
            now: self.current_kdc_time()?,
        })?;
        let response = self
            .send_for_realm(yield_point, &service_tgt.realm, &serialize_message(&tgs_req)?)
            .await?;
        let service_ticket = process_tgs_rep(parse_tgs_rep(&response)?, &service_tgt, &client, &computer_sname, nonce)?;

        // Forwarded TGT of the client realm.
        let tgt_sname = principal_name(NT_SRV_INST, &[TGT_SERVICE_NAME, &home_tgt.realm])?;
        let nonce = generate_nonce(&mut rng);
        let tgs_req = build_tgs_req(TgsRequestOptions {
            tgt: &home_tgt,
            client: &client,
            sname: tgt_sname.clone(),
            kdc_options: DEFAULT_TGS_OPTIONS | KdcOptions::FORWARDABLE | KdcOptions::FORWARDED,
            nonce,
            now: self.current_kdc_time()?,
        })?;
        let response = self
            .send_for_realm(yield_point, &home_tgt.realm, &serialize_message(&tgs_req)?)
            .await?;
        let forwarded_tgt = process_tgs_rep(parse_tgs_rep(&response)?, &home_tgt, &client, &tgt_sname, nonce)?;

        if !forwarded_tgt.part.flags.0.0.is_set(TICKET_FLAG_FORWARDED_BIT) {
            return Err(Error::new(
                ErrorKind::NoCredentials,
                "the KDC did not issue a forwarded TGT: the TGT may not be forwardable",
            ));
        }

        let now = self.current_kdc_time()?;
        let ntlm_credential = ntlm
            .map(|policy| NtlmCredential::from_identity(self.auth_identity.as_ref(), policy, &mut rng))
            .transpose()?
            .flatten();
        let state = self.remote_guard_mut()?;

        let key_handle = state.key_store.insert(
            forwarded_tgt.cipher_suite.clone(),
            forwarded_tgt.session_key.clone(),
            KeyRole::TicketGranting,
            &mut rng,
        )?;
        let krb_cred = build_krb_cred(&client, &forwarded_tgt, &key_handle, &service_ticket, now)?;
        let logon = build_kerb_ticket_logon(&picky_asn1_der::to_vec(&service_ticket.ticket)?, &krb_cred)?;
        let credentials = build_ts_credentials(
            &logon,
            ntlm_credential
                .as_ref()
                .map(NtlmCredential::supplemental_credential)
                .as_deref(),
        )?;

        state.ntlm = ntlm_credential;
        state.mark_logon_built();

        Ok(credentials)
    }
}
