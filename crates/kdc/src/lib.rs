mod as_exchange;
pub mod config;
mod error;
#[cfg(test)]
mod tests;
mod tgs_exchange;
mod ticket;

use std::time::Duration;

use picky_asn1::wrapper::{ExplicitContextTag0, GeneralizedTimeAsn1, OctetStringAsn1};
use picky_asn1_der::Asn1DerError;
use picky_krb::constants::types::{NT_ENTERPRISE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{KerberosFlags, PrincipalName};
use picky_krb::messages::{AsReq, KdcProxyMessage, TgsReq};
use time::OffsetDateTime;

use crate::as_exchange::handle_as_req;
use crate::config::{DomainUser, KerberosServer};
use crate::error::KdcError;
use crate::tgs_exchange::handle_tgs_req;

/// Kerberos versions.
///
/// [5.4.1. KRB_KDC_REQ Definition](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1):
/// ```not_rust
/// pvno            [1] INTEGER (5) ,
/// ```
const KERBEROS_VERSION: u8 = 0x05;
/// Name of the ticket-granting service.
///
/// [Name of the TGS](https://www.rfc-editor.org/rfc/rfc4120#section-7.3):
/// > The principal identifier of the ticket-granting service shall be composed of three parts:
/// > the realm of the KDC issuing the TGS ticket, and a two-part name of type NT-SRV-INST,
/// > with the first part "krbtgt" and the second part the name of the realm that will accept the TGT.
const TGT_SERVICE_NAME: &str = "krbtgt";

/// Returns the username of the client principal in the `user@domain` form used by [`DomainUser`].
fn client_username(cname: &PrincipalName, realm: &str) -> Result<String, KdcError> {
    let username = if cname.name_type.0.0 == [NT_PRINCIPAL] {
        let cname = &cname
            .name_string
            .0
            .first()
            .ok_or(KdcError::ClientPrincipalUnknown(
                "the incoming KDC request does not contain client principal name".to_owned(),
            ))?
            .0;
        format!("{cname}@{realm}")
    } else if cname.name_type.0.0 == [NT_ENTERPRISE] {
        cname
            .name_string
            .0
            .first()
            .ok_or(KdcError::ClientPrincipalUnknown(
                "the incoming KDC request does not contain client principal name".to_owned(),
            ))?
            .0
            .to_string()
    } else {
        return Err(KdcError::InvalidCnameType(cname.name_type.0.0.clone()));
    };

    Ok(username)
}

fn find_user_credentials<'a>(
    cname: &PrincipalName,
    realm: &str,
    kdc_config: &'a KerberosServer,
) -> Result<&'a DomainUser, KdcError> {
    let username = client_username(cname, realm)?;

    kdc_config
        .users
        .iter()
        .find(|user| user.username.eq_ignore_ascii_case(&username))
        .ok_or(KdcError::ClientPrincipalUnknown(format!(
            "the requested client principal name ({username}) is not found in KDC database",
        )))
}

/// Validates incoming `from` and `till` values of the [KdcReqBody].
/// Returns `auth_time` and `end_time` for the issued ticket.
///
/// RFC: [Generation of KRB_AS_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3).
fn validate_request_from_and_till(
    from: Option<&GeneralizedTimeAsn1>,
    till: &GeneralizedTimeAsn1,
    max_time_skew: u64,
) -> Result<(OffsetDateTime, OffsetDateTime), KdcError> {
    let now = OffsetDateTime::now_utc();
    let max_time_skew = Duration::from_secs(max_time_skew);

    let auth_time = if let Some(from) = from {
        let from = OffsetDateTime::try_from(from.0.clone())
            .map_err(|err| KdcError::NeverValid(format!("KdcReq::from time is not valid: {err}")))?;
        // RFC (https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3):
        // > If the requested starttime is absent, indicates a time in the past,
        // > or is within the window of acceptable clock skew for the KDC ...,
        // > then the starttime of the ticket is set to the authentication server's current time.
        if from < now + max_time_skew {
            now
        } else {
            // RFC (https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3):
            // > If it indicates a time in the future beyond the acceptable clock skew, ..., then the error
            // > KDC_ERR_CANNOT_POSTDATE is returned.
            return Err(KdcError::CannotPostdate("KdcReq::from time is too far in the future"));
        }
    } else {
        // RFC (https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3):
        // > If the requested starttime is absent, ..., then the starttime of the ticket is set to the authentication server's current time.
        now
    };

    let till = OffsetDateTime::try_from(till.0.clone())
        .map_err(|err| KdcError::NeverValid(format!("KdcReq::till time is not valid: {err}")))?;
    let max_end_time = now + Duration::from_secs(60 * 60 /* 1 hour */);
    // RFC (https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3):
    // > The expiration time of the ticket will be set to the earlier of the requested endtime and a time determined by local policy...
    let end_time = till.min(max_end_time);

    // RFC (https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3):
    // > If the requested expiration time minus the starttime (as determined above) is less than a site-determined minimum lifetime,
    // > an error message with code KDC_ERR_NEVER_VALID is returned.
    //
    // We do not have a ticket minimum lifetime value configured, so we only check that the `end_time` is after the `auth_time`.
    if end_time < auth_time {
        return Err(KdcError::NeverValid("end_time is earlier than auth_time".to_owned()));
    }

    Ok((auth_time, end_time))
}

/// `KDCOptions` bit numbers for operations on an existing ticket, which this KDC does not implement:
/// [`forwarded(2)`, `proxy(4)`, `postdated(6)`, `renew(30)`, `validate(31)`](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1).
const UNSUPPORTED_KDC_OPTIONS: [usize; 5] = [2, 4, 6, 30, 31];
/// `enc-tkt-in-skey` bit number of `KDCOptions`.
pub(crate) const KDC_OPTION_ENC_TKT_IN_SKEY: usize = 28;

/// Returns whether the KDC issues keys of the `etype`: only AES256 and AES128 (CTS-HMAC-SHA1-96).
///
/// [RFC 4120 §3.1.3](https://datatracker.ietf.org/doc/html/rfc4120#section-3.1.3) forbids weak session key etypes.
fn is_supported_etype(etype: &CipherSuite) -> bool {
    matches!(
        etype,
        CipherSuite::Aes256CtsHmacSha196 | CipherSuite::Aes128CtsHmacSha196
    )
}

/// Returns the cipher suite for the etype number from the network if the KDC supports it.
///
/// Check the etype before decrypting untrusted data: unsupported ciphers (for example DES3 in `picky-krb`) panic on malformed input.
fn supported_cipher_suite(etype: &[u8]) -> Result<CipherSuite, KdcError> {
    CipherSuite::try_from(etype)
        .ok()
        .filter(is_supported_etype)
        .ok_or(KdcError::NoSuitableEtype)
}

/// Bit access for [`KerberosFlags`], which `KDCOptions` and `TicketFlags` are encoded as.
pub(crate) trait KerberosFlagsExt {
    /// Returns whether bit number `bit` (counted from the most significant bit) is set.
    ///
    /// Unlike `BitString::is_set`, it does not panic on a malformed BIT STRING from the network.
    fn is_bit_set(&self, bit: usize) -> bool;
}

impl KerberosFlagsExt for KerberosFlags {
    fn is_bit_set(&self, bit: usize) -> bool {
        self.0
            .as_bytes()
            // The first byte is the number of unused bits.
            .get(1..)
            .and_then(|payload| payload.get(bit / 8))
            .is_some_and(|byte| byte & (0x80 >> (bit % 8)) != 0)
    }
}

/// Rejects `KDCOptions` that the KDC cannot honor.
///
/// `enc-tkt-in-skey` is meaningful only for the TGS exchange (user-to-user authentication).
/// The other options are accepted and ignored. In particular, `renewable` is accepted because `sspi` always sends it,
/// but the issued tickets are never renewable.
///
/// RFC: [KDC_ERR_BADOPTION](https://www.rfc-editor.org/rfc/rfc4120#section-5.9.1).
fn validate_kdc_options(options: &KerberosFlags, allow_enc_tkt_in_skey: bool) -> Result<(), KdcError> {
    if UNSUPPORTED_KDC_OPTIONS.iter().any(|bit| options.is_bit_set(*bit)) {
        return Err(KdcError::BadOption("the requested KDC option is not supported"));
    }

    if !allow_enc_tkt_in_skey && options.is_bit_set(KDC_OPTION_ENC_TKT_IN_SKEY) {
        return Err(KdcError::BadOption("enc-tkt-in-skey is valid only in TGS_REQ"));
    }

    Ok(())
}

/// Validates the service name of the incoming [KdcReqBody].
fn validate_request_sname(sname: &PrincipalName, expected_snames: &[&str]) -> Result<(), KdcError> {
    if sname.name_type.0.0 != [NT_SRV_INST] {
        return Err(KdcError::InvalidSnameType(sname.name_type.0.0.clone()));
    }

    let mut sname = sname.name_string.0.0.iter().map(|name| name.to_string());

    for expected_sname in expected_snames {
        let service_name = sname
            .next()
            .ok_or_else(|| KdcError::InvalidSname(format!("'{expected_sname}' is not present in KDC request sname")))?;

        if !service_name.eq_ignore_ascii_case(expected_sname) {
            return Err(KdcError::InvalidSname(format!(
                "KDC request sname ({service_name}) is not equal to '{expected_sname}'",
            )));
        }
    }

    if let Some(service_name) = sname.next() {
        return Err(KdcError::InvalidSname(format!(
            "unexpected {service_name} service name: KDC request sname has too many names inside",
        )));
    }

    Ok(())
}

/// Handles [KdcProxyMessage] by mimicking the KDC.
///
/// The incoming [KdcProxyMessage] must contain either [AsReq] or [TgsReq] Kerberos message inside,
/// preceded by its 4-byte big-endian length.
///
/// # Errors
///
/// Returns an error when the 4-byte length prefix is missing or does not match the length of the message,
/// or when encoding the reply fails.
/// Kerberos-level errors, including a message that is neither an AS-REQ nor a TGS-REQ,
/// are returned to the client as an encoded KRB-ERROR inside the resulting [KdcProxyMessage].
pub fn handle_kdc_proxy_message(
    msg: KdcProxyMessage,
    kdc_config: &KerberosServer,
    hostname: &str,
) -> Result<KdcProxyMessage, Asn1DerError> {
    let KdcProxyMessage {
        kerb_message,
        target_domain,
        dclocator_hint,
    } = msg;
    // The Kerberos message is preceded by its 4-byte big-endian length.
    // RFC: [TCP transport](https://www.rfc-editor.org/rfc/rfc4120#section-7.2.2).
    let (length_prefix, raw_krb_message) = kerb_message
        .0
        .0
        .split_first_chunk::<4>()
        .ok_or(Asn1DerError::TruncatedData)?;
    let declared_len = usize::try_from(u32::from_be_bytes(*length_prefix)).map_err(|_| Asn1DerError::InvalidData)?;
    if declared_len > raw_krb_message.len() {
        return Err(Asn1DerError::TruncatedData);
    }
    if declared_len < raw_krb_message.len() {
        return Err(Asn1DerError::InvalidData);
    }

    let reply_message = if let Ok(as_req) = picky_asn1_der::from_bytes::<AsReq>(raw_krb_message) {
        match handle_as_req(&as_req, kdc_config) {
            Ok(as_rep) => picky_asn1_der::to_vec(&as_rep)?,
            Err(kdc_err) => picky_asn1_der::to_vec(&kdc_err.into_krb_error(&as_req.0.req_body, kdc_config))?,
        }
    } else if let Ok(tgs_req) = picky_asn1_der::from_bytes::<TgsReq>(raw_krb_message) {
        match handle_tgs_req(&tgs_req, kdc_config, hostname) {
            Ok(tgs_rep) => picky_asn1_der::to_vec(&tgs_rep)?,
            Err(kdc_err) => picky_asn1_der::to_vec(&kdc_err.into_krb_error(&tgs_req.0.req_body, kdc_config))?,
        }
    } else {
        picky_asn1_der::to_vec(&KdcError::invalid_raw_krb_message_error(kdc_config.realm.clone()))?
    };

    let len = reply_message.len();
    let mut kerb_message = vec![0; len + 4];
    kerb_message[0..4].copy_from_slice(&u32::try_from(len).expect("usize-to-u32").to_be_bytes());
    kerb_message[4..].copy_from_slice(&reply_message);

    Ok(KdcProxyMessage {
        kerb_message: ExplicitContextTag0::from(OctetStringAsn1::from(kerb_message)),
        target_domain,
        dclocator_hint,
    })
}
