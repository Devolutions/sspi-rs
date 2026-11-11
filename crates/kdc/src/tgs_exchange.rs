use std::time::Duration;

use argon2::password_hash::rand_core::{OsRng, RngCore as _};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{
    TGS_REP_ENC_SESSION_KEY, TGS_REP_ENC_SUB_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, TICKET_REP,
};
use picky_krb::constants::types::{ENC_TGS_REP_PART_TYPE, PA_TGS_REQ_TYPE, TGS_REP_MSG_TYPE, TGS_REQ_MSG_TYPE};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, EncTicketPart, EncTicketPartInner, EncryptedData, PaData, PrincipalName, Realm, TicketInner,
};
use picky_krb::messages::{ApReq, ApReqInner, KdcRep, KdcReq, KdcReqBody, TgsRep, TgsReq};
use time::OffsetDateTime;

use crate::config::KerberosServer;
use crate::error::KdcError;
use crate::ticket::{
    MakeTicketParams, RepEncPartParams, TICKET_FLAG_HW_AUTHENT, TICKET_FLAG_INVALID, TICKET_FLAG_PRE_AUTHENT,
    make_rep_enc_part, make_ticket, ticket_flags,
};
use crate::{
    KDC_OPTION_ENC_TKT_IN_SKEY, KERBEROS_VERSION, KerberosFlagsExt, TGT_SERVICE_NAME, client_username,
    supported_cipher_suite, validate_kdc_options, validate_request_from_and_till, validate_request_sname,
};

/// Kerberos service name for the Terminal Server.
const TERMSRV: &str = "TERMSRV";

/// Resulting data after the TGS pre-authentication.
struct TgsPreAuth {
    /// Extracted key from the PA-DATA.
    ///
    /// This key is used for `TgsRep::enc_part` encryption.
    session_key: Vec<u8>,
    /// Client's name.
    ///
    /// Client's name is encoded in the encrypted part of the PA-DATA ticket (TGT ticket).
    cname: PrincipalName,
    /// Client's realm, copied from the TGT.
    crealm: Realm,
    /// Time of the initial authentication, copied from the TGT.
    auth_time: OffsetDateTime,
    /// TGT expiration time.
    /// The issued ticket must not outlive it.
    tgt_end_time: OffsetDateTime,
    /// Etype of the key that encrypts `TgsRep::enc_part`.
    reply_etype: CipherSuite,
    /// Bit numbers of the ticket flags carried over from the TGT.
    carried_flags: Vec<usize>,
    /// Encryption key usage.
    ///
    /// The key usage depends on whether the PA-DATA ApReq Authenticator sub-key was specified or not.
    tgs_rep_key_usage: i32,
}

/// Validates a TGT presented to the TGS (in the PA-TGS-REQ or as an additional ticket) and decrypts it.
///
/// RFC: [Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3).
fn open_tgt(
    ticket: &TicketInner,
    realm: &str,
    krbtgt_key: &[u8],
    max_time_skew: u64,
) -> Result<(EncTicketPartInner, OffsetDateTime), KdcError> {
    let TicketInner {
        tkt_vno,
        realm: ticket_realm,
        sname,
        enc_part,
    } = ticket;

    // > If the version number is not the protocol version number the KRB_AP_ERR_BADVERSION error is returned.
    if tkt_vno.0.0 != [KERBEROS_VERSION] {
        return Err(KdcError::BadTicketVersion);
    }

    // We issue and accept only our own realm's tickets: cross-realm referrals are not supported.
    let ticket_realm = ticket_realm.0.to_string();
    if !ticket_realm.eq_ignore_ascii_case(realm) {
        return Err(KdcError::WrongRealm(ticket_realm));
    }

    // * The first string in sname must be equal to TGT_SERVICE_NAME.
    // * The second string in sname must be equal to KDC realm.
    validate_request_sname(&sname.0, &[TGT_SERVICE_NAME, realm])?;

    let cipher = supported_cipher_suite(enc_part.0.etype.0.0.as_slice())?.cipher();

    let ticket_enc_part: EncTicketPart = picky_asn1_der::from_bytes(
        &cipher
            .decrypt(krbtgt_key, TICKET_REP, &enc_part.0.cipher.0.0)
            .map_err(|_| KdcError::Modified("TGT ticket"))?,
    )
    .map_err(|_| KdcError::PreAuthFailed("failed to decode TGT enc part"))?;
    let enc_part = ticket_enc_part.0;

    let end_time = OffsetDateTime::try_from(enc_part.endtime.0.0.clone())
        .map_err(|err| KdcError::NeverValid(format!("TGT end time is not valid: {err}")))?;
    let now = OffsetDateTime::now_utc();
    let max_time_skew = Duration::from_secs(max_time_skew);

    // > if the current time is later than end time by more than the allowable clock skew,
    // > the KRB_AP_ERR_TKT_EXPIRED error is returned.
    if end_time + max_time_skew < now {
        return Err(KdcError::TicketExpired("TGT ticket has expired"));
    }

    // > If the starttime is later than the current time by more than the allowable clock skew,
    // > or if the INVALID flag is set in the ticket, the KRB_AP_ERR_TKT_NYV error is returned.
    // > (starttime is absent: the authtime is used instead.)
    let start_time = match enc_part.starttime.0.as_ref() {
        Some(start_time) => start_time.0.0.clone(),
        None => enc_part.auth_time.0.0.clone(),
    };
    let start_time = OffsetDateTime::try_from(start_time)
        .map_err(|err| KdcError::NeverValid(format!("TGT start time is not valid: {err}")))?;
    if enc_part.flags.0.is_bit_set(TICKET_FLAG_INVALID) || now + max_time_skew < start_time {
        return Err(KdcError::TicketNotYetValid("TGT ticket is not valid yet"));
    }

    Ok((enc_part, end_time))
}

/// Performs TGS pre-authentication: validates incoming PA-DATAs and extracts needed parameters.
fn tgs_preauth(
    realm: &str,
    pa_datas: &Asn1SequenceOf<PaData>,
    krbtgt_key: &[u8],
    max_time_skew: u64,
) -> Result<TgsPreAuth, KdcError> {
    let ap_req: ApReq = picky_asn1_der::from_bytes(
        &pa_datas
            .0
            .iter()
            .find(|pa_data| pa_data.padata_type.0.0 == PA_TGS_REQ_TYPE)
            .ok_or(KdcError::PreAuthRequired("missing PA_TGS_REQ pa-data"))?
            .padata_data
            .0
            .0,
    )
    .map_err(|_| KdcError::PreAuthFailed("failed to decode PA_TGS_REQ AP_REQ"))?;

    let ApReqInner {
        pvno: _,
        msg_type: _,
        ap_options: _,
        ticket,
        authenticator,
    } = ap_req.0;
    let (
        EncTicketPartInner {
            flags: tgt_flags,
            key,
            crealm: ticket_crealm,
            cname,
            auth_time,
            ..
        },
        end_time,
    ) = open_tgt(&ticket.0.0, realm, krbtgt_key, max_time_skew)?;

    // RFC 4120 (https://www.rfc-editor.org/rfc/rfc4120#section-2.1):
    // > the INITIAL flag is clear, but the PRE-AUTHENT and HW-AUTHENT flags are carried forward from the TGT.
    let carried_flags: Vec<usize> = [TICKET_FLAG_PRE_AUTHENT, TICKET_FLAG_HW_AUTHENT]
        .into_iter()
        .filter(|bit| tgt_flags.0.is_bit_set(*bit))
        .collect();
    let now = OffsetDateTime::now_utc();
    let auth_time =
        OffsetDateTime::try_from(auth_time.0.0).map_err(|_| KdcError::PreAuthFailed("TGT auth time is not valid"))?;
    let session_key_type = key.0.key_type.0.0;
    let session_key = key.0.key_value.0.0;

    let authenticator_enc_data = authenticator.0;
    let cipher = supported_cipher_suite(authenticator_enc_data.etype.0.0.as_slice())?.cipher();

    let authenticator: Authenticator = picky_asn1_der::from_bytes(
        &cipher
            .decrypt(
                &session_key,
                TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
                &authenticator_enc_data.cipher.0.0,
            )
            .map_err(|_| KdcError::Modified("TGS_REQ authenticator"))?,
    )
    .map_err(|_| KdcError::PreAuthFailed("failed to decode TGS_REQ PA-DATA Authenticator"))?;

    // RFC 4120 Receipt of KRB_AP_REQ Message (https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3):
    // > The name and realm of the client from the ticket are compared against the same fields in the authenticator.
    // > If they don't match, the KRB_AP_ERR_BADMATCH error is returned.
    if authenticator.0.crealm.0.to_string() != ticket_crealm.0.to_string() || authenticator.0.cname.0 != cname.0 {
        return Err(KdcError::BadMatch(
            "the authenticator client name does not match the TGT client name",
        ));
    }
    // > If the local (server) time and the client time in the authenticator differ by more than the allowable clock skew,
    // > the KRB_AP_ERR_SKEW error is returned.
    let client_time = OffsetDateTime::try_from(authenticator.0.ctime.0.0)
        .map_err(|_| KdcError::PreAuthFailed("TGS_REQ authenticator time is not valid"))?;
    if Duration::from_secs(max_time_skew) < (now - client_time).abs() {
        return Err(KdcError::ClockSkew("TGS_REQ authenticator: clock skew too great"));
    }

    // No replay cache and no authenticator checksum verification: a replayed authenticator only yields tickets for the same client within the clock skew.

    let (session_key, reply_key_type, tgs_rep_key_usage) = if let Some(key) = authenticator.0.subkey.0 {
        (key.0.key_value.0.0, key.0.key_type.0.0, TGS_REP_ENC_SUB_KEY)
    } else {
        (session_key, session_key_type, TGS_REP_ENC_SESSION_KEY)
    };
    // RFC 4120 (https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3):
    // > The ... enc-part ... is encrypted in the sub-session key from the Authenticator, or if absent,
    // > the session key from the ticket-granting ticket.
    // Weak etypes are refused even for a client-chosen key (RFC 4120 §3.1.3).
    let reply_etype = supported_cipher_suite(reply_key_type.as_slice())?;

    Ok(TgsPreAuth {
        session_key,
        reply_etype,
        carried_flags,
        cname: cname.0,
        crealm: ticket_crealm.0,
        auth_time,
        tgt_end_time: end_time,
        tgs_rep_key_usage,
    })
}

/// Performs TGS exchange according to the RFC 4120.
///
/// RFC: [The Ticket-Granting Service (TGS) Exchange](https://www.rfc-editor.org/rfc/rfc4120#section-3.3).
pub(super) fn handle_tgs_req(
    tgs_req: &TgsReq,
    kdc_config: &KerberosServer,
    hostname: &str,
) -> Result<TgsRep, KdcError> {
    let KdcReq {
        pvno,
        msg_type,
        padata,
        req_body,
    } = &tgs_req.0;

    if pvno.0.0 != [KERBEROS_VERSION] {
        return Err(KdcError::BadKrbVersion {
            version: pvno.0.0.clone(),
            expected: KERBEROS_VERSION,
        });
    }

    if msg_type.0.0 != [TGS_REQ_MSG_TYPE] {
        return Err(KdcError::BadMsgType {
            msg_type: msg_type.0.0.clone(),
            expected: TGS_REQ_MSG_TYPE,
        });
    }

    let KdcReqBody {
        kdc_options,
        cname: _,
        realm: realm_asn1,
        sname,
        from,
        till,
        rtime: _,
        nonce,
        etype,
        addresses,
        enc_authorization_data: _,
        additional_tickets,
    } = &req_body.0;

    validate_kdc_options(&kdc_options.0, true)?;

    let realm = realm_asn1.0.0.as_utf8();
    if !realm.eq_ignore_ascii_case(&kdc_config.realm) {
        return Err(KdcError::WrongRealm(realm.to_owned()));
    }

    let sname = &sname
        .0
        .as_ref()
        .ok_or(KdcError::InvalidSname("sname is missing in TGS_REQ".to_owned()))?
        .0;
    // The TGS_REQ service name must meet the following requirements:
    // * The first string in sname must be equal to [TERMSRV].
    // * The second string in sname must be equal to Devolutions Gateway hostname.
    validate_request_sname(sname, &[TERMSRV, hostname])?;

    let pa_datas = &padata
        .0
        .as_ref()
        .ok_or_else(|| KdcError::PreAuthRequired("TGS_REQ PA-DATA is missing"))?
        .0;
    let TgsPreAuth {
        session_key: initial_key,
        reply_etype,
        carried_flags,
        cname,
        crealm,
        auth_time: tgt_auth_time,
        tgt_end_time,
        tgs_rep_key_usage,
    } = tgs_preauth(
        &kdc_config.realm,
        pa_datas,
        kdc_config.krbtgt_key.as_ref(),
        kdc_config.max_time_skew,
    )?;

    // [RFC 4120: KRB_KDC_REQ Definition](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1):
    // > KDCOptions      ::= KerberosFlags
    // > ...
    // >         -- enc-tkt-in-skey(28),
    let (ticket_enc_key, ticket_enc_etype) = if kdc_options.0.is_bit_set(KDC_OPTION_ENC_TKT_IN_SKEY) {
        // RFC 4120 (https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3.2):
        // the additional ticket is a TGT of the service, so it is validated like the TGT from the PA-TGS-REQ.
        let additional_ticket = &additional_tickets
            .0
            .as_ref()
            .and_then(|tickets| tickets.0.0.first())
            .ok_or(KdcError::BadOption(
                "enc-tkt-in-skey is set but additional-tickets is missing or empty",
            ))?
            .0;

        let (additional_tgt, _) = open_tgt(
            additional_ticket,
            realm,
            kdc_config.krbtgt_key.as_ref(),
            kdc_config.max_time_skew,
        )?;

        // RFC 4120 (https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3):
        // > ...the name of the requested server will be compared to the name of the client in the additional ticket.
        // > If it is different, the request will be rejected.
        //
        // The requested server is always `TERMSRV/<hostname>`, so the additional ticket is compared with
        // the configured service user instead. Without a service user, the TGT of any client is accepted:
        // the issued ticket is then encrypted with a key that the requester may choose.
        if let Some(service_user) = &kdc_config.service_user {
            let additional_client = client_username(&additional_tgt.cname.0, &additional_tgt.crealm.0.to_string())?;
            if !additional_client.eq_ignore_ascii_case(&service_user.username) {
                return Err(KdcError::ServerNoMatch(
                    "the additional ticket is not the TGT of the user-to-user service",
                ));
            }
        }

        // The ticket is encrypted with the session key of the additional TGT, in the etype of that key.
        let key_etype = supported_cipher_suite(additional_tgt.key.0.key_type.0.0.as_slice())?;

        (additional_tgt.key.0.key_value.0.0, key_etype)
    } else {
        let key = kdc_config
            .ticket_decryption_key
            .as_ref()
            .map(|key| key.as_ref().clone())
            .ok_or(KdcError::InternalError("TGS ticket encryption key is not specified"))?;

        (key, CipherSuite::Aes256CtsHmacSha196)
    };

    let tgs_req_nonce = nonce.0.0.clone();
    let etype = etype
        .0
        .0
        .iter()
        .find_map(|offered| supported_cipher_suite(&offered.0).ok())
        .ok_or(KdcError::NoSuitableEtype)?;
    let cipher = etype.cipher();
    let realm = realm_asn1.0.clone();

    // RFC 4120 Generation of KRB_TGS_REP Message (https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3):
    // > The authtime field is copied from the ticket-granting ticket,
    // > and the endtime ... is the minimum of the requested ... and the endtime of the TGT.
    let (start_time, requested_end_time) =
        validate_request_from_and_till(from.0.as_deref(), &till.0, kdc_config.max_time_skew)?;
    let auth_time = tgt_auth_time;
    let end_time = requested_end_time.min(tgt_end_time);
    // A TGT expired within the clock skew passes `open_tgt`, but then the capped end time is before the start time.
    // `validate_request_from_and_till` checked the lifetime before the cap.
    if end_time < start_time {
        return Err(KdcError::NeverValid(
            "the TGT ends before the requested ticket starts".to_owned(),
        ));
    }

    let mut rng = OsRng;
    let mut session_key = vec![0; cipher.key_size()];
    rng.fill_bytes(&mut session_key);

    let tgs_rep_enc_part = make_rep_enc_part::<ENC_TGS_REP_PART_TYPE>(
        RepEncPartParams {
            etype: etype.clone(),
            session_key: session_key.clone(),
            nonce: tgs_req_nonce,
            flags: ticket_flags(&carried_flags),
            start_time,
            auth_time,
            end_time,
            realm: realm.clone(),
            sname: sname.clone(),
            addresses: addresses.0.clone().map(|addresses| addresses.0),
        },
        &reply_etype,
        &initial_key,
        tgs_rep_key_usage,
    )?;

    Ok(TgsRep::from(KdcRep {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGS_REP_MSG_TYPE])),
        padata: Optional::from(None),
        crealm: ExplicitContextTag3::from(crealm.clone()),
        cname: ExplicitContextTag4::from(cname.clone()),
        ticket: ExplicitContextTag5::from(make_ticket(MakeTicketParams {
            realm,
            client_realm: crealm,
            session_key,
            ticket_encryption_key: &ticket_enc_key,
            ticket_encryption_etype: ticket_enc_etype,
            flags: ticket_flags(&carried_flags),
            start_time,
            sname: sname.clone(),
            cname,
            etype: etype.clone(),
            auth_time,
            end_time,
        })?),
        enc_part: ExplicitContextTag6::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![u8::from(reply_etype)])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(tgs_rep_enc_part)),
        }),
    }))
}
