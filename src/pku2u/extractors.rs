use std::convert::TryInto;
use std::mem::size_of;

use picky_asn1_der::Asn1RawDer;
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::constants::types::PA_PK_AS_REP;
use picky_krb::data_types::{KrbResult, ResultExt};
use picky_krb::messages::AsRep;
use picky_krb::pkinit::{DhRepInfo, PaPkAsRep};
use serde::Deserialize;

use crate::kerberos::EncryptionParams;
use crate::kerberos::client::extractors::decrypt_as_rep;
use crate::pk_init::DH_NONCE_LEN;
use crate::{Error, ErrorKind, Result, Secret};

pub(super) fn extract_krb_rep<'a, T: Deserialize<'a>>(mut data: &'a [u8]) -> Result<(T, &'a [u8])> {
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;

    Ok((picky_asn1_der::from_bytes(data)?, data))
}

pub(super) fn extract_krb_result<'a, T: Deserialize<'a>>(mut data: &'a [u8]) -> Result<(KrbResult<T>, &'a [u8])> {
    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut data)?;
    let mut deserializer = picky_asn1_der::Deserializer::new_from_bytes(data);

    Ok((
        <KrbResult<T> as ResultExt<'a, T>>::deserialize(&mut deserializer)?,
        data,
    ))
}

#[instrument(level = "trace", ret)]
pub fn extract_pa_pk_as_rep(as_rep: &AsRep) -> Result<PaPkAsRep> {
    Ok(picky_asn1_der::from_bytes(
        &as_rep
            .0
            .padata
            .0
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "pa-datas is not present in as-rep"))?
            .iter()
            .find(|pa_data| pa_data.padata_type.0.0 == PA_PK_AS_REP)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    "PA_PK_AS_REP is not present in pa-datas of the as-rep",
                )
            })?
            .padata_data
            .0
            .0,
    )?)
}

#[instrument(level = "trace", ret)]
pub fn extract_server_nonce(dh_rep_info: &DhRepInfo) -> Result<[u8; DH_NONCE_LEN]> {
    let nonce = dh_rep_info
        .server_dh_nonce
        .0
        .as_ref()
        .map(|nonce| nonce.0.0.clone())
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "DH server nonce is not present"))?;

    if nonce.len() != DH_NONCE_LEN {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid server dh nonce length: {}. Expected: {}",
                nonce.len(),
                DH_NONCE_LEN
            ),
        ));
    }

    Ok(nonce.try_into().unwrap())
}

#[instrument(level = "trace", ret)]
pub fn extract_session_key_from_as_rep(
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

pub(super) fn extract_session_key_and_nonce_from_as_rep(
    as_rep: &AsRep,
    key: &[u8],
    enc_params: &EncryptionParams,
) -> Result<(Secret<Vec<u8>>, u32)> {
    let enc_as_rep_part = decrypt_as_rep(as_rep, key, enc_params)?;
    let nonce_bytes = enc_as_rep_part.nonce.0.as_unsigned_bytes_be();
    if nonce_bytes.len() > size_of::<u32>() {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "AS-REP nonce does not fit into a u32",
        ));
    }
    let mut nonce = [0; size_of::<u32>()];
    nonce[size_of::<u32>() - nonce_bytes.len()..].copy_from_slice(nonce_bytes);

    Ok((
        enc_as_rep_part.key.0.key_value.0.to_vec().into(),
        u32::from_be_bytes(nonce),
    ))
}

#[cfg(test)]
mod tests {
    use picky_krb::constants::gss_api::{AP_REQ_TOKEN_ID, AS_REQ_TOKEN_ID};

    use super::extract_krb_rep;
    use crate::ClientRequestFlags;
    use crate::kerberos::client::generators::{GenerateAsReqOptions, generate_as_req, generate_as_req_kdc_body};
    use crate::pku2u::generators::generate_neg;

    /// Regression test for a framing bug in [`generate_neg`]: it used to wrap the [KrbMessage](picky_krb::gss_api::KrbMessage)
    /// using the generic (`EXPLICIT`-style) `ApplicationTag` from `picky_asn1_der`, producing a doubly-nested,
    /// non-conformant token that [`extract_krb_rep`]/[`extract_krb_result`](super::extract_krb_result) (and any
    /// spec-compliant PKU2U peer) could not parse back. `generate_neg` must keep using [ApplicationTag0](picky_krb::gss_api::ApplicationTag0)
    /// (RFC 2743 `IMPLICIT` tagging) so that everything this module encodes round-trips through what it decodes.
    #[test]
    fn generate_neg_round_trips_through_extract_krb_rep() {
        let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: "WELLKNOWN:PKU2U",
            username: "AzureAD\\issuer\\subject",
            cname_type: 0x80,
            snames: &["host"],
            nonce: 0x0102_0304,
            hostname: "hostname",
            context_requirements: ClientRequestFlags::empty(),
        })
        .unwrap();
        let as_req = generate_as_req(Vec::new(), kdc_req_body);

        let encoded = picky_asn1_der::to_vec(&generate_neg(as_req.clone(), AS_REQ_TOKEN_ID)).unwrap();
        let (decoded, _): (picky_krb::messages::AsReq, _) = extract_krb_rep(&encoded).unwrap();
        assert_eq!(decoded, as_req);

        // Any token id round-trips the same way (e.g. AP-REQ/AP-REP use a different one than AS-REQ/AS-REP).
        let encoded = picky_asn1_der::to_vec(&generate_neg(as_req.clone(), AP_REQ_TOKEN_ID)).unwrap();
        let (decoded, _): (picky_krb::messages::AsReq, _) = extract_krb_rep(&encoded).unwrap();
        assert_eq!(decoded, as_req);
    }

    #[test]
    fn bare_application_tagged_value_decodes_as_krb_result_ok() {
        use picky_krb::constants::gss_api::AS_REP_TOKEN_ID;
        use picky_krb::data_types::KrbResult;

        use super::extract_krb_result;

        let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: "WELLKNOWN:PKU2U",
            username: "AzureAD\\issuer\\subject",
            cname_type: 0x80,
            snames: &["host"],
            nonce: 0x0102_0304,
            hostname: "hostname",
            context_requirements: ClientRequestFlags::empty(),
        })
        .unwrap();
        // AsReq is unused as the choice discriminant here; we just need *some* Application-tagged
        // value with a distinct tag number from KrbError (30) to stand in for AsRep (11) in this test.
        let as_req = generate_as_req(Vec::new(), kdc_req_body);

        // `KrbResult<T>` cannot be serialized directly (`Result<T, E>`'s blanket serde impl isn't
        // supported by picky_asn1_der's Serializer). But since `KrbResult<T> = Result<T, KrbError>`
        // is a *natural* choice between two distinctly Application-tagged alternatives (no extra
        // wrapper tag), a bare, directly-encoded `T` must already parse back as `KrbResult::Ok`.
        let encoded = picky_asn1_der::to_vec(&generate_neg(as_req.clone(), AS_REP_TOKEN_ID)).unwrap();
        let (decoded, _): (KrbResult<picky_krb::messages::AsReq>, _) = extract_krb_result(&encoded).unwrap();
        assert_eq!(decoded.unwrap(), as_req);
    }
}

#[cfg(test)]
mod as_rep_regressions {
    use picky_asn1::bit_string::BitString;
    use picky_asn1::date::GeneralizedTime;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
        ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag9,
        ExplicitContextTag10, IntegerAsn1, OctetStringAsn1, Optional,
    };
    use picky_krb::constants::key_usages::AS_REP_ENC;
    use picky_krb::crypto::CipherSuite;
    use picky_krb::data_types::{
        EncryptedData, EncryptionKey, KerberosFlags, KerberosStringAsn1, KerberosTime, LastReq, PrincipalName, Ticket,
        TicketInner,
    };
    use picky_krb::messages::{EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcRep};
    use time::OffsetDateTime;

    use super::{AsRep, EncryptionParams, ErrorKind, extract_session_key_and_nonce_from_as_rep};
    use crate::pku2u::extract_session_key_from_as_rep;

    const LONG_TERM_KEY: [u8; 32] = [0x29; 32];
    const SESSION_KEY: [u8; 32] = [0xb6; 32];

    fn encrypted_as_rep(tag: u8, nonce: &[u8]) -> AsRep {
        let realm = KerberosStringAsn1::from(IA5String::from_string("WELLKNOWN:PKU2U".to_owned()).unwrap());
        let name = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![1])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                IA5String::from_string("AzureAD\\issuer\\subject".to_owned()).unwrap(),
            )])),
        };
        let time = KerberosTime::from(GeneralizedTime::from(
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        ));
        let part = EncKdcRepPart {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(SESSION_KEY.to_vec())),
            }),
            last_req: ExplicitContextTag1::from(LastReq::from(Vec::new())),
            nonce: ExplicitContextTag2::from(IntegerAsn1::from(nonce.to_vec())),
            key_expiration: Optional::from(None),
            flags: ExplicitContextTag4::from(KerberosFlags::from(BitString::with_bytes(vec![0x40, 0, 0, 0]))),
            auth_time: ExplicitContextTag5::from(time.clone()),
            start_time: Optional::from(None),
            end_time: ExplicitContextTag7::from(KerberosTime::from(GeneralizedTime::from(
                OffsetDateTime::from_unix_timestamp(1_700_003_600).unwrap(),
            ))),
            renew_till: Optional::from(None),
            srealm: ExplicitContextTag9::from(realm.clone()),
            sname: ExplicitContextTag10::from(name.clone()),
            caddr: Optional::from(None),
            encrypted_pa_data: Optional::from(None),
        };
        let mut plaintext = if tag == 26 {
            picky_asn1_der::to_vec(&EncTgsRepPart::from(part)).unwrap()
        } else {
            picky_asn1_der::to_vec(&EncAsRepPart::from(part)).unwrap()
        };
        if !matches!(tag, 25 | 26) {
            plaintext[0] = 0x60 | tag;
        }
        let encrypted = |data| EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(data)),
        };
        AsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![11])),
            padata: Optional::from(None),
            crealm: ExplicitContextTag3::from(realm.clone()),
            cname: ExplicitContextTag4::from(name.clone()),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
                realm: ExplicitContextTag1::from(realm),
                sname: ExplicitContextTag2::from(name),
                enc_part: ExplicitContextTag3::from(encrypted(vec![0x55; 32])),
            })),
            enc_part: ExplicitContextTag6::from(encrypted(
                CipherSuite::Aes256CtsHmacSha196
                    .cipher()
                    .encrypt(&LONG_TERM_KEY, AS_REP_ENC, &plaintext)
                    .unwrap(),
            )),
        })
    }

    #[test]
    fn pku2u_public_key_extractor_returns_expected_session_key_for_both_application_tags() {
        for tag in [25, 26] {
            let reply = encrypted_as_rep(tag, &[1, 2, 3, 4]);
            assert_eq!(
                extract_session_key_from_as_rep(&reply, &LONG_TERM_KEY, &EncryptionParams::default_for_client())
                    .unwrap()
                    .as_ref(),
                &SESSION_KEY
            );
        }
    }

    #[test]
    fn pku2u_key_and_nonce_extractor_preserves_nonce_boundaries() {
        for tag in [25, 26] {
            for (bytes, expected) in [
                (&[0][..], 0),
                (&[1], 1),
                (&[1, 2, 3, 4], 0x0102_0304),
                (&[0x7f, 0xff, 0xff, 0xff], 0x7fff_ffff),
                (&[0, 0x80, 0, 0, 0], 0x8000_0000),
                (&[0, 0xff, 0xff, 0xff, 0xff], u32::MAX),
            ] {
                let reply = encrypted_as_rep(tag, bytes);
                let (key, nonce) = extract_session_key_and_nonce_from_as_rep(
                    &reply,
                    &LONG_TERM_KEY,
                    &EncryptionParams::default_for_client(),
                )
                .unwrap();
                assert_eq!(key.as_ref(), &SESSION_KEY, "tag {tag}, nonce {expected}");
                assert_eq!(nonce, expected, "tag {tag}");
            }
        }
    }

    #[test]
    fn pku2u_session_key_extractors_reject_unsupported_application_tag() {
        let params = EncryptionParams::default_for_client();
        for tag in [24, 27] {
            let reply = encrypted_as_rep(tag, &[1, 2, 3, 4]);
            assert!(
                extract_session_key_from_as_rep(&reply, &LONG_TERM_KEY, &params).is_err(),
                "tag {tag}"
            );
            assert!(
                extract_session_key_and_nonce_from_as_rep(&reply, &LONG_TERM_KEY, &params).is_err(),
                "tag {tag}"
            );
        }
    }

    #[test]
    fn pku2u_session_key_extractors_reject_wrong_key_and_tampered_ciphertext() {
        let params = EncryptionParams::default_for_client();
        for tag in [25, 26] {
            let mut reply = encrypted_as_rep(tag, &[1, 2, 3, 4]);
            assert!(extract_session_key_from_as_rep(&reply, &[0x88; 32], &params).is_err());
            assert!(extract_session_key_and_nonce_from_as_rep(&reply, &[0x88; 32], &params).is_err());
            reply.0.enc_part.0.cipher.0.0[8] ^= 1;
            assert!(extract_session_key_from_as_rep(&reply, &LONG_TERM_KEY, &params).is_err());
            assert!(extract_session_key_and_nonce_from_as_rep(&reply, &LONG_TERM_KEY, &params).is_err());
        }
    }

    #[test]
    fn pku2u_nonce_extractor_rejects_nonce_above_u32_max() {
        for tag in [25, 26] {
            for nonce in [
                &[1, 0, 0, 0, 0][..],
                &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ] {
                let reply = encrypted_as_rep(tag, nonce);
                let params = EncryptionParams::default_for_client();
                let error = extract_session_key_and_nonce_from_as_rep(&reply, &LONG_TERM_KEY, &params).unwrap_err();
                assert_eq!(error.error_type, ErrorKind::InvalidToken);
                // The key-only API deliberately does not interpret the nonce.
                assert_eq!(
                    extract_session_key_from_as_rep(&reply, &LONG_TERM_KEY, &params)
                        .unwrap()
                        .as_ref(),
                    &SESSION_KEY
                );
            }
        }
    }
}
