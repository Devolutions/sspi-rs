use std::io::Read;

use picky_asn1::wrapper::{Asn1SequenceOf, ObjectIdentifierAsn1};
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
    Ok(match extract_salt_hint_from_krb_error(error)? {
        Some(Salt::Explicit(salt)) => Some(salt),
        Some(Salt::Default) | None => None,
    })
}

pub(crate) fn extract_preauth_salt(error: &KrbError, realm: &str, cname: &PrincipalName) -> Result<Option<String>> {
    Ok(extract_salt_hint_from_krb_error(error)?.map(|salt| salt.resolve(realm, cname)))
}

fn extract_salt_hint_from_krb_error(error: &KrbError) -> Result<Option<Salt>> {
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
            if let Some(params) = etype_info_2.0.first() {
                return Ok(Some(match &params.salt.0 {
                    Some(salt) => Salt::Explicit(salt.0.to_string()),
                    None => Salt::Default,
                }));
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

    let enc_data = cipher.decrypt(key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0.0)?;

    // AS-REP specifies EncASRepPart (APPLICATION 25), but MIT uses EncTGSRepPart
    // (APPLICATION 26) for backwards compatibility, as some other implementations
    // do. RFC 4120 section 5.4.2 permits accepting both: "In the interest of
    // compatibility, implementors MAY relax the check on the tag number of the
    // decrypted ENC-PART."
    Ok(match picky_asn1_der::from_bytes::<EncAsRepPart>(&enc_data) {
        Ok(as_rep_enc_part) => as_rep_enc_part.0,
        Err(_) => picky_asn1_der::from_bytes::<EncTgsRepPart>(&enc_data)?.0,
    })
}

/// Extracts a session from the [AsRep].
#[instrument(level = "trace", ret, skip(password))]
pub fn extract_session_key_from_as_rep(
    as_rep: &AsRep,
    salt: &str,
    password: &str,
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let key = cipher.generate_key_from_password(password.as_bytes(), salt.as_bytes())?;

    extract_session_key_from_as_rep_with_key(as_rep, &key, enc_params)
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

/// Extracts a session from the [TgsRep].
#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_tgs_rep(
    tgs_rep: &TgsRep,
    session_key: &Secret<Vec<u8>>,
    enc_params: &EncryptionParams,
) -> Result<Secret<Vec<u8>>> {
    let cipher = enc_params
        .encryption_type
        .as_ref()
        .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
        .cipher();

    let enc_data = cipher
        .decrypt(
            session_key.as_ref(),
            TGS_REP_ENC_SESSION_KEY,
            &tgs_rep.0.enc_part.0.cipher.0.0,
        )
        .map_err(|e| Error::new(ErrorKind::DecryptFailure, format!("{e:?}")))?;

    trace!(?enc_data, "Plain TgsRep::EncData");

    let enc_as_rep_part: EncTgsRepPart = picky_asn1_der::from_bytes(&enc_data)?;

    Ok(enc_as_rep_part.0.key.0.key_value.0.to_vec().into())
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
mod as_rep_regressions {
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
        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
        let key = cipher
            .generate_key_from_password(PASSWORD.as_bytes(), salt.as_bytes())
            .unwrap();
        let part = EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(SESSION_KEY.to_vec())),
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
    fn extract_preauth_salt_distinguishes_absent_default_empty_and_custom() {
        for (data, expected) in [
            (None, None),
            (Some(hint(None)), None),
            (Some(hint(Some(None))), Some("ExAmPlE.COMAliceAdmin")),
            (Some(hint(Some(Some("")))), Some("")),
            (Some(hint(Some(Some("custom-preauth")))), Some("custom-preauth")),
        ] {
            assert_eq!(
                extract_preauth_salt(&preauth_error(data), "ExAmPlE.COM", &principal(&["Alice", "Admin"])).unwrap(),
                expected.map(str::to_owned)
            );
        }
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
            assert!(extract_preauth_salt(&error, "ExAmPlE.COM", &principal(&["Alice", "Admin"])).is_err());
            assert!(extract_salt_from_krb_error(&error).is_err());
        }

        let mut empty_hint = hint(Some(None));
        empty_hint.0[0].padata_data = ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&Asn1SequenceOf::<EtypeInfo2Entry>::from(Vec::new())).unwrap(),
        ));
        let error = preauth_error(Some(empty_hint));
        assert_eq!(
            extract_preauth_salt(&error, "ExAmPlE.COM", &principal(&["Alice", "Admin"])).unwrap(),
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
}
