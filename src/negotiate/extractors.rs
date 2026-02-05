use oid::ObjectIdentifier;
use picky::oids;
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, KrbMessage, MechTypeList, NegTokenInit};
use picky_krb::messages::TgtReq;

use crate::negotiate::PackageListConfig;
use crate::ntlm::NtlmConfig;
use crate::{Error, ErrorKind, NegotiatedProtocol, Ntlm};

/// Extract TGT request and mech types from the first token returned by the Kerberos client.
#[instrument(ret, level = "trace")]
pub(super) fn decode_initial_neg_init(data: &[u8]) -> crate::Result<(Option<TgtReq>, MechTypeList)> {
    let token: ApplicationTag0<GssApiNegInit> = picky_asn1_der::from_bytes(data)?;
    let NegTokenInit {
        mech_types,
        req_flags: _,
        mech_token,
        mech_list_mic: _,
    } = token.0.neg_token_init.0;

    let mech_types = mech_types
        .0
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidToken,
                "mech_types is missing in GssApiNegInit message",
            )
        })?
        .0;

    let tgt_req = if let Some(mech_token) = mech_token.0 {
        let encoded_tgt_req = mech_token.0 .0;
        let neg_token_init = KrbMessage::<TgtReq>::decode_application_krb_message(&encoded_tgt_req)?;

        let token_oid = &neg_token_init.0.krb5_oid.0;
        let krb5_u2u = oids::krb5_user_to_user();
        if *token_oid != krb5_u2u {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "invalid oid inside mech_token: expected krb5 u2u ({:?}) but got {:?}",
                    krb5_u2u, token_oid
                ),
            ));
        }

        Some(neg_token_init.0.krb_msg)
    } else {
        None
    };

    Ok((tgt_req, mech_types))
}

/// Selects the preferred authentication protocol OID based on the provided protocols list, allowed protocols,
/// and available protocols.
///
/// The Kerberos protocol will be selected only if it is allowed in the package list, its OID is present in the mech types,
/// and the internal protocol is configured to Kerberos. We cannot _just_ configure it from env vars as we do it for
/// the client-side Kerberos because the server-side Kerberos requires many configuration fields.
///
/// 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5) is preferred over 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5).
pub(super) fn negotiate_mech_type(
    mech_list: &MechTypeList,
    package_list: PackageListConfig,
    internal_protocol: &mut NegotiatedProtocol,
) -> crate::Result<ObjectIdentifier> {
    let ms_krb5 = oids::ms_krb5();
    if mech_list.0.iter().any(|mech_type| mech_type.0 == ms_krb5)
        && package_list.kerberos
        && internal_protocol.is_kerberos()
    {
        return Ok(ms_krb5);
    }

    let krb5 = oids::krb5();
    if mech_list.0.iter().any(|mech_type| mech_type.0 == krb5)
        && package_list.kerberos
        && internal_protocol.is_kerberos()
    {
        return Ok(krb5);
    }

    let ntlm_oid = oids::ntlm_ssp();
    if mech_list.0.iter().any(|mech_type| mech_type.0 == ntlm_oid) && package_list.ntlm {
        if let NegotiatedProtocol::Kerberos(kerberos) = internal_protocol {
            // Negotiate is configured to use Kerberos, but only NTLM is possible (fallback to NTLM).
            *internal_protocol = NegotiatedProtocol::Ntlm(Ntlm::with_config(NtlmConfig {
                client_computer_name: Some(kerberos.config.client_computer_name.clone()),
            }));
        }

        return Ok(ntlm_oid);
    }

    Err(Error::new(
        ErrorKind::InvalidToken,
        "no supported authentication protocols found in mech list",
    ))
}
