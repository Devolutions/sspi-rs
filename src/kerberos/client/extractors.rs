use std::io::Read;

use picky_asn1::wrapper::{Asn1SequenceOf, IntegerAsn1, ObjectIdentifierAsn1};
use picky_asn1_der::Asn1RawDer;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::error_codes::KDC_ERR_PREAUTH_REQUIRED;
use picky_krb::constants::key_usages::{AP_REP_ENC, AS_REP_ENC, KRB_PRIV_ENC_PART, TGS_REP_ENC_SESSION_KEY};
use picky_krb::constants::types::PA_ETYPE_INFO2_TYPE;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{EncApRepPart, EncKrbPrivPart, EtypeInfo2, PaData, PrincipalName, Ticket};
use picky_krb::messages::{
    ApRep, AsRep, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KrbError, KrbPriv, TgsRep, TgtRep,
};
use zeroize::Zeroizing;

use crate::kerberos::client::generators::{nonce_matches, nonce_values_match};
use crate::kerberos::{DEFAULT_ENCRYPTION_TYPE, EncryptionParams};
use crate::{Error, ErrorKind, Result, Secret};

enum Salt {
    Default,
    Explicit(String),
}

impl Salt {
    fn resolve(self, realm: &str, cname: &PrincipalName) -> String {
        match self {
            Self::Default => {
                let mut salt = realm.to_owned();
                for component in &cname.name_string.0.0 {
                    salt.push_str(component.0.as_utf8());
                }
                salt
            }
            Self::Explicit(salt) => salt,
        }
    }
}

/// Extracts password salt from the KRB error.
///
/// We need a salt to derive the correct encryption key from user's password. Usually, the salt is domain+username, but the custom salt
/// value can be set in KDC database. So, we always extract the correct salt from the [KrbError] message. More info in [RFC 4120 PA-ETYPE-INFO2](https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.5):
///
/// > The ETYPE-INFO2 pre-authentication type is sent by the KDC in a KRB-ERROR indicating a requirement for additional pre-authentication.
/// > It is usually used to notify a client of which key to use for the encryption of an encrypted timestamp for the purposes of sending a
/// > PA-ENC-TIMESTAMP pre-authentication value.
pub fn extract_salt_from_krb_error(error: &KrbError) -> Result<Option<String>> {
    Ok(match extract_etype_info_from_krb_error(error)? {
        Some((Salt::Explicit(salt), _)) => Some(salt),
        Some((Salt::Default, _)) | None => None,
    })
}

/// What the KDC tells in the pre-authentication error about the key of the PA-ENC-TIMESTAMP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreauthHint {
    /// The salt of the password key.
    pub salt: String,
    /// The encryption type of the password key, if the KDC names one that the client supports.
    pub cipher_suite: Option<CipherSuite>,
}

pub(crate) fn extract_preauth_hint(
    error: &KrbError,
    realm: &str,
    cname: &PrincipalName,
) -> Result<Option<PreauthHint>> {
    Ok(
        extract_etype_info_from_krb_error(error)?.map(|(salt, cipher_suite)| PreauthHint {
            salt: salt.resolve(realm, cname),
            cipher_suite,
        }),
    )
}

/// Extracts the salt and the encryption type from the first entry of the PA-ETYPE-INFO2 that the client supports.
///
/// The client offers AES256 and AES128 in its AS-REQ, so only those can be named.
/// If the KDC names none of them, the salt of the first entry is returned without an encryption type.
fn extract_etype_info_from_krb_error(error: &KrbError) -> Result<Option<(Salt, Option<CipherSuite>)>> {
    trace!(?error, "KRB_ERROR");

    // Check if the error code is KDC_ERR_PREAUTH_REQUIRED. If not, propagate the KDC error.
    if error.0.error_code.0 != KDC_ERR_PREAUTH_REQUIRED {
        return Err(error.clone().into());
    }

    if let Some(e_data) = error.0.e_data.0.as_ref() {
        let pa_datas: Asn1SequenceOf<PaData> = picky_asn1_der::from_bytes(&e_data.0.0)?;

        if let Some(pa_etype_info_2) = pa_datas
            .0
            .into_iter()
            .find(|pa_data| pa_data.padata_type.0.0 == PA_ETYPE_INFO2_TYPE)
        {
            let etype_info_2: EtypeInfo2 = picky_asn1_der::from_bytes(&pa_etype_info_2.padata_data.0.0)?;

            let supported_entry =
                etype_info_2
                    .0
                    .iter()
                    .find_map(|entry| match CipherSuite::try_from(entry.etype.0.0.as_slice()) {
                        Ok(cipher_suite @ (CipherSuite::Aes256CtsHmacSha196 | CipherSuite::Aes128CtsHmacSha196)) => {
                            Some((entry, cipher_suite))
                        }
                        _ => None,
                    });
            let (entry, cipher_suite) = match supported_entry {
                Some((entry, cipher_suite)) => (Some(entry), Some(cipher_suite)),
                None => (etype_info_2.0.first(), None),
            };

            if let Some(entry) = entry {
                let salt = match &entry.salt.0 {
                    Some(salt) => Salt::Explicit(salt.0.to_string()),
                    None => Salt::Default,
                };

                return Ok(Some((salt, cipher_suite)));
            }
        }
    }

    Ok(None)
}

/// Decrypts and authenticates the AS-REP enc-part.
///
/// Accepts both tags permitted by [RFC 4120, section 5.4.2: "KRB_KDC_REP definition"][kdc-rep].
///
/// [kdc-rep]: https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2
pub(crate) fn decrypt_as_rep(as_rep: &AsRep, key: &[u8], enc_params: &EncryptionParams) -> Result<EncKdcRepPart> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = Zeroizing::new(cipher.decrypt(key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0.0)?);

    // MIT Kerberos tags the enc-part EncTGSRepPart (APPLICATION 26) instead of EncASRepPart (APPLICATION 25).
    // [5.4.2.  KRB_KDC_REP Definition](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.2)
    // Clients may accept either tag, and both wrap the same EncKDCRepPart.
    let enc_kdc_rep_part = match picky_asn1_der::from_bytes::<EncAsRepPart>(&enc_data) {
        Ok(enc_part) => enc_part.0,
        // Report the error for the expected tag.
        Err(error) => {
            picky_asn1_der::from_bytes::<EncTgsRepPart>(&enc_data)
                .map_err(|_| error)?
                .0
        }
    };

    Ok(enc_kdc_rep_part)
}

/// Extracts a session from the [AsRep].
#[instrument(level = "trace", ret, skip(password))]
pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    salt: &str,
    password: &str,
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    let key = password_key(password, salt, enc_params)?;

    extract_session_key_from_as_rep_with_key(as_rep, &key, enc_params)
}

/// Derives the long-term key from the password with the negotiated encryption type.
pub(crate) fn password_key(password: &str, salt: &str, enc_params: &EncryptionParams) -> Result<Vec<u8>> {
    Ok(enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher()
        .generate_key_from_password(password.as_bytes(), salt.as_bytes())?)
}

/// Extracts a session key from the [AsRep] using a pre-derived long-term key
/// (keytab-based client authentication).
#[instrument(level = "trace", ret, skip(key))]
pub fn extract_session_key_from_as_rep_with_key(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    Ok(decrypt_as_rep(as_rep, key, enc_params)?
        .key
        .0
        .key_value
        .0
        .to_vec()
        .into())
}

/// A session key together with its encryption type.
///
/// The type of the session key is its own: it is not the type of the long-term key that encrypted the reply,
/// and a service decides it for the service ticket (RFC 4120 section 5.4.2, `EncKDCRepPart.key`).
#[derive(Debug, Clone)]
pub(crate) struct SessionKey {
    pub key: Secret<Vec<u8>>,
    pub cipher_suite: CipherSuite,
}

impl SessionKey {
    fn from_encryption_key(key: &picky_krb::data_types::EncryptionKey) -> Result<Self> {
        Ok(Self {
            cipher_suite: CipherSuite::try_from(key.key_type.0.0.as_slice())?,
            key: key.key_value.0.to_vec().into(),
        })
    }
}

/// Extracts the session key from the [AsRep] after checking that its nonce is the AS-REQ nonce.
///
/// [RFC 4120, Section 3.1.5](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.5):
/// the client must verify that the nonce in the encrypted part is the one it sent.
/// Otherwise, a reply to an earlier request is accepted.
pub(crate) fn extract_checked_session_key(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
    expected_nonce: u32,
) -> Result<SessionKey> {
    let enc_part = decrypt_as_rep(as_rep, key, enc_params)?;

    if !nonce_matches(&enc_part.nonce.0, expected_nonce) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "AS-REP nonce does not match the AS-REQ nonce",
        ));
    }

    SessionKey::from_encryption_key(&enc_part.key.0)
}

/// Extracts the session key from the [TgsRep] after checking it against the request.
///
/// [RFC 4120, Section 3.3.5](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.5):
/// the client verifies that the nonce in the encrypted part is the one it sent.
/// The service name and realm of the encrypted part must also be those of the enclosed ticket,
/// because only the encrypted part is protected and the client acts on the name of the ticket.
pub(crate) fn extract_checked_tgs_session_key(
    tgs_rep: &TgsRep,
    session_key: &Secret<Vec<u8>>,
    expected_nonce: &IntegerAsn1,
) -> Result<SessionKey> {
    let enc_part = decrypt_tgs_rep(tgs_rep, session_key)?;

    if !nonce_values_match(&enc_part.nonce.0, expected_nonce) {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "TGS-REP nonce does not match the TGS-REQ nonce",
        ));
    }

    let ticket = &tgs_rep.0.ticket.0.0;
    if enc_part.srealm.0 != ticket.realm.0 || enc_part.sname.0.name_string.0 != ticket.sname.0.name_string.0 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "the service name of the TGS-REP ticket does not match the encrypted part",
        ));
    }

    SessionKey::from_encryption_key(&enc_part.key.0)
}

/// Extracts a session from the [TgsRep].
#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_tgs_rep(
    tgs_rep: &TgsRep,
    session_key: &Secret<Vec<u8>>,
    _enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    Ok(decrypt_tgs_rep(tgs_rep, session_key)?.key.0.key_value.0.to_vec().into())
}

/// Decrypts the encrypted part of the TGS-REP with the session key of the TGT.
///
/// The cipher is the one that the KDC states for the encrypted part, which is the type of that key.
fn decrypt_tgs_rep(tgs_rep: &TgsRep, session_key: &Secret<Vec<u8>>) -> Result<EncKdcRepPart> {
    let cipher = CipherSuite::try_from(tgs_rep.0.enc_part.0.etype.0.0.as_slice())?.cipher();

    let enc_data = cipher
        .decrypt(
            session_key.as_ref(),
            TGS_REP_ENC_SESSION_KEY,
            &tgs_rep.0.enc_part.0.cipher.0.0,
        )
        .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{e:?}")))?;

    trace!(?enc_data, "Plain TgsRep::EncData");

    let enc_tgs_rep_part: EncTgsRepPart = picky_asn1_der::from_bytes(&enc_data)?;

    Ok(enc_tgs_rep_part.0)
}

/// Extracts encryption type and salt from [AsRep].
///
/// More info in [RFC 4120 Receipt of KRB_AS_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.5):
///
/// > If any padata fields are present, they may be used to derive the proper secret key to decrypt the message.
#[instrument(level = "trace", ret)]
pub fn extract_encryption_params_from_as_rep(as_rep: &AsRep) -> Result<(u8, String)> {
    extract_encryption_params_from_as_rep_with_salt(as_rep, "")
}

/// Uses the pre-authentication salt only when the reply omits PA-ETYPE-INFO2.
///
/// An omitted salt field in an ETYPE-INFO2 entry selects the principal's default
/// salt, whereas a present empty string selects an empty salt.
/// See [RFC 4120, section 5.2.7.5: "PA-ETYPE-INFO2"][etype-info2] and
/// [section 4: "Encryption and Checksum Specifications"][encryption].
///
/// [etype-info2]: https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.5
/// [encryption]: https://www.rfc-editor.org/rfc/rfc4120#section-4
pub(crate) fn extract_encryption_params_from_as_rep_with_salt(
    as_rep: &AsRep,
    preauth_salt: &str,
) -> Result<(u8, String)> {
    match as_rep
        .0
        .padata
        .0
        .as_ref()
        .map(|v| {
            v.0.0
                .iter()
                .find(|e| e.padata_type.0.0 == PA_ETYPE_INFO2_TYPE)
                .map(|pa_data| pa_data.padata_data.0.0.clone())
        })
        .unwrap_or_default()
    {
        Some(data) => {
            let pa_etype_info2: EtypeInfo2 = picky_asn1_der::from_bytes(&data)?;
            let pa_etype_info2 = pa_etype_info2
                .0
                .first()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "missing EtypeInfo2Entry in EtypeInfo2"))?;

            let salt = match &pa_etype_info2.salt.0 {
                Some(salt) => Salt::Explicit(salt.0.to_string()),
                None => Salt::Default,
            };
            Ok((
                pa_etype_info2.etype.0.0.first().copied().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidParameter,
                        "missing encryption type in EtypeInfo2Entry",
                    )
                })?,
                salt.resolve(as_rep.0.crealm.0.0.as_utf8(), &as_rep.0.cname.0),
            ))
        }
        None => Ok((
            as_rep
                .0
                .enc_part
                .0
                .etype
                .0
                .0
                .first()
                .copied()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "missing encryption type in AS-REP"))?,
            preauth_salt.to_owned(),
        )),
    }
}

/// Extract a status code from the [KrbPriv] message.
pub fn extract_status_code_from_krb_priv_response(
    krb_priv: &KrbPriv,
    auth_key: &[u8],
    encryption_params: &EncryptionParams,
) -> Result<u16> {
    let encryption_type = encryption_params
        .encryption_type
        .clone()
        .unwrap_or(CipherSuite::try_from(usize::from(
            *krb_priv
                .0
                .enc_part
                .0
                .etype
                .0
                .0
                .first()
                .unwrap_or(&((&DEFAULT_ENCRYPTION_TYPE).into())),
        ))?);

    let cipher = encryption_type.cipher();

    let enc_part: EncKrbPrivPart =
        picky_asn1_der::from_bytes(&cipher.decrypt(auth_key, KRB_PRIV_ENC_PART, &krb_priv.0.enc_part.0.cipher.0.0)?)?;
    let user_data = enc_part.0.user_data.0.0;

    let Some((status_code, _)) = user_data.split_first_chunk::<2>() else {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "Invalid KRB_PRIV message: user-data first is too short (expected at least 2 bytes)",
        ));
    };

    Ok(u16::from_be_bytes(*status_code))
}

/// Decrypt and decodes the encrypted part of the encoded [ApRep] message.
#[instrument(level = "trace", ret)]
pub fn decrypt_ap_rep(
    ap_rep: &ApRep,
    session_key: &Secret<Vec<u8>>,
    enc_params: &EncryptionParams,
) -> Result<EncApRepPart> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let res = cipher
        .decrypt(session_key.as_ref(), AP_REP_ENC, &ap_rep.0.enc_part.cipher.0.0)
        .map_err(|err| {
            Error::new(
                ErrorKind::DecryptFailure,
                format!("cannot decrypt ap_rep.enc_part: {err:?}"),
            )
        })?;

    Ok(picky_asn1_der::from_bytes(&res)?)
}

/// Extracts a sub-session key from the [EncApRepPart].
#[instrument(level = "trace", ret)]
pub fn extract_sub_session_key_from_ap_rep(ap_rep_enc_part: &EncApRepPart) -> Result<Secret<Vec<u8>>> {
    Ok(ap_rep_enc_part
        .0
        .subkey
        .0
        .clone()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing sub-key in ap_req"))?
        .0
        .key_value
        .0
        .0
        .into())
}

/// Extracts the encryption type of the sub-session key from the [EncApRepPart].
///
/// The acceptor chooses its subkey, so the type can differ from the one of the session key.
#[instrument(level = "trace", ret)]
pub(crate) fn extract_sub_session_key_type_from_ap_rep(ap_rep_enc_part: &EncApRepPart) -> Result<CipherSuite> {
    let subkey = ap_rep_enc_part
        .0
        .subkey
        .0
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing sub-key in ap_req"))?;

    Ok(CipherSuite::try_from(subkey.0.key_type.0.0.as_slice())?)
}

/// Extracts a sequence number from the [EncApRepPart].
#[instrument(level = "trace", ret)]
pub fn extract_seq_number_from_ap_rep(ap_rep_enc_part: &EncApRepPart) -> Result<u32> {
    let seq_number_bytes = ap_rep_enc_part
        .0
        .seq_number
        .0
        .clone()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "missing seq-number in ap_rep"))?
        .0
        .0;

    seq_number_from_integer_bytes(&seq_number_bytes).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidToken,
            format!("invalid ApRep sequence number: {:?}", seq_number_bytes),
        )
    })
}

/// Converts the content octets of a DER INTEGER holding a 32-bit sequence number into a [u32].
///
/// DER uses the minimal number of octets, so a peer encodes a small sequence number in fewer than
/// 4 octets (the Windows acceptor sends 3 octets for values below `0x800000`, about 1 in 256 AP-REPs).
/// A value encoded as unsigned (RFC 4120 `UInt32`) can take a fifth leading `00` octet, and a value
/// encoded as signed (Windows `Int32`) can be a short negative number, which is sign-extended here.
fn seq_number_from_integer_bytes(bytes: &[u8]) -> Option<u32> {
    match bytes {
        [0x00, rest @ ..] if rest.len() == 4 => rest.try_into().ok().map(u32::from_be_bytes),
        [first, ..] if bytes.len() <= 4 => {
            let mut buf = if first & 0x80 != 0 { [0xff; 4] } else { [0x00; 4] };
            buf[4 - bytes.len()..].copy_from_slice(bytes);
            Some(u32::from_be_bytes(buf))
        }
        _ => None,
    }
}

/// Extracts TGT Ticket from encoded [NegTokenTarg1].
///
/// Returned OID means the selected authentication mechanism by the target server. More info:
/// * [3.2.1. Syntax](https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1): `responseToken` field;
///
/// We use this oid to choose between the regular Kerberos 5 and Kerberos 5 User-to-User authentication.
#[instrument(level = "trace", ret)]
pub fn extract_tgt_ticket_with_oid(mut resp_token: &[u8]) -> Result<Option<(Ticket, ObjectIdentifierAsn1)>> {
    if resp_token.is_empty() {
        return Ok(None);
    }

    let oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut resp_token)?;
    let oid: ObjectIdentifierAsn1 = picky_asn1_der::from_bytes(&oid.0.0)?;

    let mut t = [0, 0];

    resp_token.read_exact(&mut t)?;

    let tgt_rep: TgtRep = picky_asn1_der::from_reader(&mut resp_token)?;

    Ok(Some((tgt_rep.ticket.0, oid)))
}

#[cfg(test)]
mod tests {
    use picky_asn1::date::GeneralizedTime;
    use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag3, IntegerAsn1, Optional};
    use picky_krb::data_types::{EncApRepPartInner, KerberosTime};
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn seq_number_accepts_any_der_length() {
        for (bytes, expected) in [
            // Minimal DER from the Windows acceptor, previously rejected.
            (&[0x05, 0x84, 0xbc][..], 0x0005_84bc),
            (&[0x00], 0),
            (&[0x7f], 0x7f),
            (&[0x00, 0x80], 0x80),
            (&[0x12, 0x34, 0x56, 0x78], 0x1234_5678),
            // Full width, as sent by older sspi-rs acceptors.
            (&[0x9a, 0xbc, 0xde, 0xf0], 0x9abc_def0),
            // Unsigned encoding with a leading zero octet.
            (&[0x00, 0x9a, 0xbc, 0xde, 0xf0], 0x9abc_def0),
            // Short negative values from a signed Int32 encoder.
            (&[0xff], u32::MAX),
            (&[0x80, 0x00, 0x00], 0xff80_0000),
        ] {
            assert_eq!(seq_number_from_integer_bytes(bytes), Some(expected), "{bytes:02x?}");
        }
    }

    #[test]
    fn seq_number_rejects_out_of_range() {
        for bytes in [
            &[][..],
            &[0x01, 0x00, 0x00, 0x00, 0x00],
            &[0xff, 0x80, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        ] {
            assert_eq!(seq_number_from_integer_bytes(bytes), None, "{bytes:02x?}");
        }
    }

    #[test]
    fn ap_rep_with_short_seq_number() {
        let enc_ap_rep_part = EncApRepPart::from(EncApRepPartInner {
            ctime: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(OffsetDateTime::now_utc()))),
            cusec: ExplicitContextTag1::from(IntegerAsn1::from(vec![0x00])),
            subkey: Optional::from(None),
            seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(vec![
                0x1a, 0xad, 0x10,
            ])))),
        });

        assert_eq!(extract_seq_number_from_ap_rep(&enc_ap_rep_part).unwrap(), 0x001a_ad10);
    }
}

#[cfg(test)]
pub(crate) mod as_rep_regressions {
    use picky_asn1::bit_string::BitString;
    use picky_asn1::date::GeneralizedTime;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{
        ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4,
        ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag9, ExplicitContextTag10,
        ExplicitContextTag12, IntegerAsn1, OctetStringAsn1, Optional,
    };
    use picky_krb::data_types::{
        EncryptedData, EncryptionKey, EtypeInfo2Entry, KerberosFlags, KerberosStringAsn1, KerberosTime, LastReq,
        Microseconds, TicketInner,
    };
    use picky_krb::messages::{KdcRep, KrbErrorInner};
    use time::OffsetDateTime;

    use super::*;

    const SESSION_KEY: [u8; 32] = [0x3d; 32];
    const PASSWORD: &str = "Correct horse battery staple!";
    const SALT: &str = "fixture-long-term-salt";

    fn principal(components: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![1])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
                components.iter().map(|s| krb_string(s)).collect::<Vec<_>>(),
            )),
        }
    }

    fn krb_string(value: &str) -> KerberosStringAsn1 {
        KerberosStringAsn1::from(IA5String::from_string(value.to_owned()).unwrap())
    }

    // Outer None means no hint; Some(None) means an entry with no salt field.
    fn hint(salt: Option<Option<&str>>) -> Asn1SequenceOf<PaData> {
        Asn1SequenceOf::from(
            salt.map(|salt| PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ETYPE_INFO2_TYPE.to_vec())),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                    picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![EtypeInfo2Entry {
                        etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                        salt: Optional::from(salt.map(|s| ExplicitContextTag1::from(krb_string(s)))),
                        s2kparams: Optional::from(None),
                    }]))
                    .unwrap(),
                )),
            })
            .into_iter()
            .collect::<Vec<_>>(),
        )
    }

    fn fixed_time(seconds: i64) -> KerberosTime {
        KerberosTime::from(GeneralizedTime::from(
            OffsetDateTime::from_unix_timestamp(seconds).unwrap(),
        ))
    }

    fn encrypted_as_rep(tag: u8, salt: &str) -> (AsRep, Vec<u8>) {
        encrypted_as_rep_with_session_key(tag, salt, &CipherSuite::Aes256CtsHmacSha196)
    }

    /// An AS-REP encrypted with the AES256 long-term key, whose session key has the given encryption type.
    fn encrypted_as_rep_with_session_key(tag: u8, salt: &str, session_key_suite: &CipherSuite) -> (AsRep, Vec<u8>) {
        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
        let key = cipher
            .generate_key_from_password(PASSWORD.as_bytes(), salt.as_bytes())
            .unwrap();
        let part = EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![session_key_suite.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(
                    SESSION_KEY[..session_key_suite.cipher().key_size()].to_vec(),
                )),
            }),
            last_req: ExplicitContextTag1::from(LastReq::from(Vec::new())),
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(vec![1, 2, 3, 4])),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(KerberosFlags::from(BitString::with_bytes(vec![0x40, 0, 0, 0]))),
            auth_time: ExplicitContextTag5::from(fixed_time(1_700_000_000)),
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(fixed_time(1_700_003_600)),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(krb_string("RePlY.EXAMPLE")),
            sname: ExplicitContextTag10::from(principal(&["krbtgt", "RePlY.EXAMPLE"])),
            caddr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        };
        let mut plaintext = if tag == 26 {
            picky_asn1_der::to_vec(&EncTgsRepPart::from(part)).unwrap()
        } else {
            picky_asn1_der::to_vec(&EncAsRepPart::from(part)).unwrap()
        };
        // Changing the plaintext tag before encryption keeps the invalid-tag case authenticated.
        if !matches!(tag, 25 | 26) {
            plaintext[0] = 0x60 | tag;
        }
        let encrypted = |data| EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(data)),
        };
        let reply = AsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![11])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(krb_string("RePlY.EXAMPLE")),
            cname: ExplicitContextTag4::from(principal(&["Service", "Instance"])),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
                realm: ExplicitContextTag1::from(krb_string("RePlY.EXAMPLE")),
                sname: ExplicitContextTag2::from(principal(&["krbtgt", "RePlY.EXAMPLE"])),
                enc_part: ExplicitContextTag3::from(encrypted(vec![0x55; 32])),
            })),
            enc_part: ExplicitContextTag6::from(encrypted(cipher.encrypt(&key, AS_REP_ENC, &plaintext).unwrap())),
        });
        (reply, key)
    }

    fn preauth_error(data: Option<Asn1SequenceOf<PaData>>) -> KrbError {
        KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![30])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(fixed_time(1_700_000_000)),
            susec: ExplicitContextTag5::from(Microseconds::from(vec![0])),
            error_code: ExplicitContextTag6::from(KDC_ERR_PREAUTH_REQUIRED),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(krb_string("KDC.EXAMPLE")),
            sname: ExplicitContextTag10::from(principal(&["krbtgt", "KDC.EXAMPLE"])),
            e_text: Optional::from(None),
            e_data: Optional::from(
                data.map(|data| {
                    ExplicitContextTag12::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&data).unwrap()))
                }),
            ),
        })
    }

    #[test]
    fn extract_preauth_hint_distinguishes_absent_default_empty_and_custom_salt() {
        for (data, expected) in [
            (None, None),
            (Some(hint(None)), None),
            (Some(hint(Some(None))), Some("ExAmPlE.COMAliceAdmin")),
            (Some(hint(Some(Some("")))), Some("")),
            (Some(hint(Some(Some("custom-preauth")))), Some("custom-preauth")),
        ] {
            assert_eq!(
                extract_preauth_hint(&preauth_error(data), "ExAmPlE.COM", &principal(&["Alice", "Admin"]))
                    .unwrap()
                    .map(|hint| hint.salt),
                expected.map(str::to_owned)
            );
        }
    }

    /// An ETYPE-INFO2 with an entry for each `(etype, salt)`.
    fn etype_info2(entries: &[(u8, Option<&str>)]) -> Asn1SequenceOf<PaData> {
        Asn1SequenceOf::from(vec![PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ETYPE_INFO2_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&Asn1SequenceOf::from(
                    entries
                        .iter()
                        .map(|(etype, salt)| EtypeInfo2Entry {
                            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![*etype])),
                            salt: Optional::from(salt.map(|salt| ExplicitContextTag1::from(krb_string(salt)))),
                            s2kparams: Optional::from(None),
                        })
                        .collect::<Vec<_>>(),
                ))
                .unwrap(),
            )),
        }])
    }

    // RFC 4120 §5.2.7.5: the entries tell which key to use for the PA-ENC-TIMESTAMP.
    // The client takes the first entry with an encryption type that it supports.
    #[rstest::rstest]
    #[case::first_entry(&[(17, Some("salt-a")), (18, Some("salt-b"))], Some(("salt-a", Some(CipherSuite::Aes128CtsHmacSha196))))]
    #[case::skips_unsupported_encryption_types(&[(23, Some("rc4-salt")), (18, Some("salt-b"))], Some(("salt-b", Some(CipherSuite::Aes256CtsHmacSha196))))]
    #[case::default_salt_of_the_chosen_entry(&[(23, Some("rc4-salt")), (17, None)], Some(("ExAmPlE.COMAliceAdmin", Some(CipherSuite::Aes128CtsHmacSha196))))]
    #[case::nothing_supported_keeps_the_salt_of_the_first_entry(&[(23, Some("rc4-salt")), (3, Some("des-salt"))], Some(("rc4-salt", None)))]
    #[case::no_entries(&[], None)]
    fn the_hint_names_the_key_for_the_pre_authentication(
        #[case] entries: &[(u8, Option<&str>)],
        #[case] expected: Option<(&str, Option<CipherSuite>)>,
    ) {
        let error = preauth_error(Some(etype_info2(entries)));

        let hint = extract_preauth_hint(&error, "ExAmPlE.COM", &principal(&["Alice", "Admin"])).unwrap();

        assert_eq!(
            hint,
            expected.map(|(salt, cipher_suite)| PreauthHint {
                salt: salt.to_owned(),
                cipher_suite,
            })
        );
    }

    #[test]
    fn extract_salt_from_krb_error_preserves_legacy_optional_string_contract() {
        for (data, expected) in [
            (None, None),
            (Some(hint(None)), None),
            (Some(hint(Some(None))), None),
            (Some(hint(Some(Some("")))), Some("")),
            (Some(hint(Some(Some("legacy-custom")))), Some("legacy-custom")),
        ] {
            assert_eq!(
                extract_salt_from_krb_error(&preauth_error(data)).unwrap(),
                expected.map(str::to_owned)
            );
        }
    }

    #[test]
    fn extract_encryption_params_from_as_rep_with_salt_uses_negotiated_fallback() {
        let (mut reply, _) = encrypted_as_rep(25, SALT);
        for padata in [None, Some(ExplicitContextTag2::from(hint(None)))] {
            reply.0.padata = Optional::from(padata);
            for salt in ["negotiated-preauth-salt", ""] {
                assert_eq!(
                    extract_encryption_params_from_as_rep_with_salt(&reply, salt).unwrap(),
                    (18, salt.to_owned())
                );
            }
        }
    }

    #[test]
    fn extract_encryption_params_from_as_rep_with_salt_preserves_explicit_reply_salt() {
        for expected in ["", "reply-only-salt"] {
            let (mut reply, _) = encrypted_as_rep(25, expected);
            reply.0.padata = Optional::from(Some(ExplicitContextTag2::from(hint(Some(Some(expected))))));
            let (etype, salt) = extract_encryption_params_from_as_rep_with_salt(&reply, "preauth-only-salt").unwrap();
            assert_eq!((etype, salt.as_str()), (18, expected));
            assert_eq!(
                extract_session_key_from_as_rep(&reply, &salt, PASSWORD, &EncryptionParams::default_for_client())
                    .unwrap()
                    .as_ref(),
                &SESSION_KEY
            );
        }
    }

    #[test]
    fn extract_encryption_params_from_as_rep_with_salt_defaults_missing_reply_salt_field() {
        let (mut reply, _) = encrypted_as_rep(26, "RePlY.EXAMPLEServiceInstance");
        reply.0.padata = Optional::from(Some(ExplicitContextTag2::from(hint(Some(None)))));
        let (etype, salt) = extract_encryption_params_from_as_rep_with_salt(&reply, "preauth-only-salt").unwrap();
        assert_eq!((etype, salt.as_str()), (18, "RePlY.EXAMPLEServiceInstance"));
        assert_eq!(
            extract_session_key_from_as_rep(&reply, &salt, PASSWORD, &EncryptionParams::default_for_client())
                .unwrap()
                .as_ref(),
            &SESSION_KEY
        );
    }

    #[test]
    fn extract_encryption_params_from_as_rep_preserves_one_argument_api() {
        let (mut reply, _) = encrypted_as_rep(25, SALT);
        for expected in ["explicit-salt", ""] {
            reply.0.padata = Optional::from(Some(ExplicitContextTag2::from(hint(Some(Some(expected))))));
            assert_eq!(
                extract_encryption_params_from_as_rep(&reply).unwrap(),
                (18, expected.to_owned())
            );
        }
    }

    #[test]
    fn decrypt_as_rep_preserves_fields_for_both_application_tags() {
        for tag in [25, 26] {
            let (reply, key) = encrypted_as_rep(tag, SALT);
            let part = decrypt_as_rep(&reply, &key, &EncryptionParams::default_for_client()).unwrap();
            assert_eq!(part.key.0.key_value.0.0, SESSION_KEY);
            assert_eq!(part.nonce.0.0, [1, 2, 3, 4]);
            assert_eq!(part.srealm.0, krb_string("RePlY.EXAMPLE"));
            assert_eq!(part.sname.0, principal(&["krbtgt", "RePlY.EXAMPLE"]));
            assert_eq!(part.auth_time.0, fixed_time(1_700_000_000));
            assert_eq!(part.end_time.0, fixed_time(1_700_003_600));
            assert_eq!(part.flags.0.0.as_bytes(), &[0, 0x40, 0, 0, 0]);
            assert!(part.start_time.0.is_none());
        }
    }

    #[test]
    fn kerberos_password_extractor_returns_expected_session_key_for_both_application_tags() {
        for tag in [25, 26] {
            let (reply, _) = encrypted_as_rep(tag, SALT);
            assert_eq!(
                extract_session_key_from_as_rep(&reply, SALT, PASSWORD, &EncryptionParams::default_for_client())
                    .unwrap()
                    .as_ref(),
                &SESSION_KEY
            );
        }
    }

    #[test]
    fn kerberos_derived_key_extractor_returns_expected_session_key_for_both_application_tags() {
        for tag in [25, 26] {
            let (reply, key) = encrypted_as_rep(tag, SALT);
            assert_eq!(
                extract_session_key_from_as_rep_with_key(&reply, &key, &EncryptionParams::default_for_client())
                    .unwrap()
                    .as_ref(),
                &SESSION_KEY
            );
        }
    }

    #[test]
    fn kerberos_session_key_extractors_reject_unsupported_application_tag() {
        let params = EncryptionParams::default_for_client();
        for tag in [24, 27] {
            let (reply, key) = encrypted_as_rep(tag, SALT);
            assert!(
                extract_session_key_from_as_rep_with_key(&reply, &key, &params).is_err(),
                "tag {tag}"
            );
            assert!(
                extract_session_key_from_as_rep(&reply, SALT, PASSWORD, &params).is_err(),
                "tag {tag}"
            );
        }
    }

    #[test]
    fn kerberos_session_key_extractors_reject_wrong_key_and_tampered_ciphertext() {
        let params = EncryptionParams::default_for_client();
        for tag in [25, 26] {
            let (mut reply, key) = encrypted_as_rep(tag, SALT);
            assert!(extract_session_key_from_as_rep_with_key(&reply, &[0x77; 32], &params).is_err());
            assert!(extract_session_key_from_as_rep(&reply, SALT, "wrong-password", &params).is_err());
            reply.0.enc_part.0.cipher.0.0[8] ^= 1;
            assert!(extract_session_key_from_as_rep_with_key(&reply, &key, &params).is_err());
            assert!(extract_session_key_from_as_rep(&reply, SALT, PASSWORD, &params).is_err());
        }
    }

    #[test]
    fn salt_extractors_reject_invalid_challenges() {
        let mut wrong_error = preauth_error(Some(hint(Some(Some("must-not-use")))));
        wrong_error.0.error_code = ExplicitContextTag6::from(24_u32);
        let mut malformed_method_data = preauth_error(None);
        malformed_method_data.0.e_data =
            Optional::from(Some(ExplicitContextTag12::from(OctetStringAsn1::from(vec![0xff]))));
        let mut malformed_hint = hint(Some(None));
        malformed_hint.0[0].padata_data = ExplicitContextTag2::from(OctetStringAsn1::from(vec![0xff]));
        for error in [wrong_error, malformed_method_data, preauth_error(Some(malformed_hint))] {
            assert!(extract_preauth_hint(&error, "ExAmPlE.COM", &principal(&["Alice", "Admin"])).is_err());
            assert!(extract_salt_from_krb_error(&error).is_err());
        }

        let mut empty_hint = hint(Some(None));
        empty_hint.0[0].padata_data = ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&Asn1SequenceOf::<EtypeInfo2Entry>::from(Vec::new())).unwrap(),
        ));
        let error = preauth_error(Some(empty_hint));
        assert_eq!(
            extract_preauth_hint(&error, "ExAmPlE.COM", &principal(&["Alice", "Admin"]))
                .unwrap()
                .map(|hint| hint.salt),
            None
        );
        assert_eq!(extract_salt_from_krb_error(&error).unwrap(), None);
    }

    #[test]
    fn reply_encryption_params_reject_malformed_or_missing_values() {
        let (mut reply, _) = encrypted_as_rep(25, SALT);
        for entry in [
            None,
            Some(EtypeInfo2Entry {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(Vec::new())),
                salt: Optional::from(None),
                s2kparams: Optional::from(None),
            }),
        ] {
            let mut padata = hint(Some(None));
            padata.0[0].padata_data = ExplicitContextTag2::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&Asn1SequenceOf::from(entry.into_iter().collect::<Vec<_>>())).unwrap(),
            ));
            reply.0.padata = Optional::from(Some(ExplicitContextTag2::from(padata)));
            assert_eq!(
                extract_encryption_params_from_as_rep_with_salt(&reply, "must-not-fallback")
                    .unwrap_err()
                    .error_type,
                ErrorKind::InvalidParameter
            );
        }
        let mut malformed = hint(Some(None));
        malformed.0[0].padata_data = ExplicitContextTag2::from(OctetStringAsn1::from(vec![0xff]));
        reply.0.padata = Optional::from(Some(ExplicitContextTag2::from(malformed)));
        assert!(extract_encryption_params_from_as_rep_with_salt(&reply, "must-not-fallback").is_err());

        // A nonempty method-data list without ETYPE-INFO2 still uses the negotiated salt.
        let mut unrelated = hint(Some(None));
        unrelated.0[0].padata_type = ExplicitContextTag1::from(IntegerAsn1::from(vec![2]));
        reply.0.padata = Optional::from(Some(ExplicitContextTag2::from(unrelated)));
        assert_eq!(
            extract_encryption_params_from_as_rep_with_salt(&reply, "fallback-with-unrelated-padata").unwrap(),
            (18, "fallback-with-unrelated-padata".to_owned())
        );
        reply.0.padata = Optional::from(None);
        reply.0.enc_part.0.etype = ExplicitContextTag0::from(IntegerAsn1::from(Vec::new()));
        assert_eq!(
            extract_encryption_params_from_as_rep_with_salt(&reply, "must-not-fallback")
                .unwrap_err()
                .error_type,
            ErrorKind::InvalidParameter
        );
    }

    #[test]
    fn the_sub_session_key_type_is_the_type_of_the_acceptor_subkey() {
        use picky_krb::data_types::EncApRepPartInner;

        let ap_rep_enc_part = |subkey: Option<u8>| {
            EncApRepPart::from(EncApRepPartInner {
                ctime: ExplicitContextTag0::from(fixed_time(1_700_000_000)),
                cusec: ExplicitContextTag1::from(IntegerAsn1::from(vec![0])),
                subkey: Optional::from(subkey.map(|key_type| {
                    ExplicitContextTag2::from(EncryptionKey {
                        key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![key_type])),
                        key_value: ExplicitContextTag1::from(OctetStringAsn1::from(vec![0x77; 16])),
                    })
                })),
                seq_number: Optional::from(None),
            })
        };

        assert_eq!(
            extract_sub_session_key_type_from_ap_rep(&ap_rep_enc_part(Some(17))).unwrap(),
            CipherSuite::Aes128CtsHmacSha196
        );
        assert_eq!(
            extract_sub_session_key_type_from_ap_rep(&ap_rep_enc_part(None))
                .unwrap_err()
                .error_type,
            ErrorKind::InvalidToken
        );
    }

    // The long-term key encrypts the reply, but the session key has its own type (RFC 4120 section 5.4.2).
    #[test]
    fn checked_extractor_reports_the_encryption_type_of_the_session_key() {
        let (reply, key) = encrypted_as_rep_with_session_key(25, SALT, &CipherSuite::Aes128CtsHmacSha196);

        let session_key =
            extract_checked_session_key(&reply, &key, &EncryptionParams::default_for_client(), 0x0102_0304).unwrap();

        assert_eq!(session_key.cipher_suite, CipherSuite::Aes128CtsHmacSha196);
        assert_eq!(session_key.key.as_ref(), &SESSION_KEY[..16]);
    }

    // RFC 4120 §3.1.5: the client verifies that the nonce in the encrypted part matches the AS-REQ nonce.
    // The fixture reply carries the nonce 0x01020304.
    #[test]
    fn checked_extractor_returns_the_session_key_for_the_matching_nonce() {
        for tag in [25, 26] {
            let (reply, key) = encrypted_as_rep(tag, SALT);

            assert_eq!(
                extract_checked_session_key(&reply, &key, &EncryptionParams::default_for_client(), 0x0102_0304)
                    .unwrap()
                    .key
                    .as_ref(),
                &SESSION_KEY
            );
        }
    }

    // A reply to an earlier request has a different nonce, but is otherwise authentic.
    #[rstest::rstest]
    #[case::last_octet_differs(0x0102_0305)]
    #[case::zero(0)]
    #[case::high_bit_set(0x8102_0304)]
    fn checked_extractor_rejects_a_mismatched_nonce(#[case] expected_nonce: u32) {
        let (reply, key) = encrypted_as_rep(25, SALT);

        let error = extract_checked_session_key(&reply, &key, &EncryptionParams::default_for_client(), expected_nonce)
            .unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    /// A TGS-REP for `krbtgt/NEXT.EXAMPLE` encrypted with the session key of the TGT.
    ///
    /// The enclosed ticket is named `ticket_sname@ticket_realm`, the encrypted part `enc_sname@enc_realm`.
    pub(crate) fn encrypted_tgs_rep(
        nonce: Vec<u8>,
        ticket_sname: &[&str],
        ticket_realm: &str,
    ) -> (TgsRep, Secret<Vec<u8>>) {
        encrypted_tgs_rep_with_key(
            nonce,
            "NEXT.EXAMPLE",
            &["krbtgt", "NEXT.EXAMPLE"],
            ticket_sname,
            ticket_realm,
            &CipherSuite::Aes256CtsHmacSha196,
        )
    }

    /// Like [encrypted_tgs_rep], for the given service of the encrypted part and the given session key type.
    pub(crate) fn encrypted_tgs_rep_with_key(
        nonce: Vec<u8>,
        enc_realm: &str,
        enc_sname: &[&str],
        ticket_sname: &[&str],
        ticket_realm: &str,
        session_key_suite: &CipherSuite,
    ) -> (TgsRep, Secret<Vec<u8>>) {
        let tgt_session_key = Secret::new(vec![0x44; 32]);
        let part = EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![session_key_suite.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(
                    SESSION_KEY[..session_key_suite.cipher().key_size()].to_vec(),
                )),
            }),
            last_req: ExplicitContextTag1::from(LastReq::from(Vec::new())),
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(nonce)),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(KerberosFlags::from(BitString::with_bytes(vec![0x40, 0, 0, 0]))),
            auth_time: ExplicitContextTag5::from(fixed_time(1_700_000_000)),
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(fixed_time(1_700_003_600)),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(krb_string(enc_realm)),
            sname: ExplicitContextTag10::from(principal(enc_sname)),
            caddr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        };
        let encrypted = |data| EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(data)),
        };
        let plaintext = picky_asn1_der::to_vec(&EncTgsRepPart::from(part)).unwrap();
        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();

        let reply = TgsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![13])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(krb_string("HOME.EXAMPLE")),
            cname: ExplicitContextTag4::from(principal(&["alice"])),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
                realm: ExplicitContextTag1::from(krb_string(ticket_realm)),
                sname: ExplicitContextTag2::from(principal(ticket_sname)),
                enc_part: ExplicitContextTag3::from(encrypted(vec![0x55; 32])),
            })),
            enc_part: ExplicitContextTag6::from(encrypted(
                cipher
                    .encrypt(tgt_session_key.as_ref(), TGS_REP_ENC_SESSION_KEY, &plaintext)
                    .unwrap(),
            )),
        });

        (reply, tgt_session_key)
    }

    fn nonce(value: u32) -> IntegerAsn1 {
        crate::kerberos::client::generators::nonce_to_asn1(value)
    }

    // RFC 4120 §3.3.5: the client verifies that the nonce in the encrypted part is the TGS-REQ nonce.
    #[test]
    fn checked_tgs_extractor_returns_the_session_key_for_the_matching_nonce() {
        let (reply, tgt_session_key) = encrypted_tgs_rep(vec![1, 2, 3, 4], &["krbtgt", "NEXT.EXAMPLE"], "NEXT.EXAMPLE");

        let key = extract_checked_tgs_session_key(&reply, &tgt_session_key, &nonce(0x0102_0304)).unwrap();

        assert_eq!(key.key.as_ref(), &SESSION_KEY);
    }

    #[test]
    fn checked_tgs_extractor_rejects_a_mismatched_nonce() {
        let (reply, tgt_session_key) = encrypted_tgs_rep(vec![1, 2, 3, 4], &["krbtgt", "NEXT.EXAMPLE"], "NEXT.EXAMPLE");

        let error = extract_checked_tgs_session_key(&reply, &tgt_session_key, &nonce(0x0102_0305)).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    // The referral logic reads the service name of the enclosed ticket, which is not protected.
    // The service name of the encrypted part is, so the two must agree (RFC 4120 §5.4.2).
    #[rstest::rstest]
    #[case::other_service(&["krbtgt", "OTHER.EXAMPLE"], "NEXT.EXAMPLE")]
    #[case::other_realm(&["krbtgt", "NEXT.EXAMPLE"], "OTHER.EXAMPLE")]
    fn checked_tgs_extractor_rejects_a_ticket_that_differs_from_the_encrypted_part(
        #[case] ticket_sname: &[&str],
        #[case] ticket_realm: &str,
    ) {
        let (reply, tgt_session_key) = encrypted_tgs_rep(vec![1, 2, 3, 4], ticket_sname, ticket_realm);

        let error = extract_checked_tgs_session_key(&reply, &tgt_session_key, &nonce(0x0102_0304)).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }
}
