use oid::ObjectIdentifier;
use picky::oids;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, IntegerAsn1,
    ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::Asn1RawDer;
use picky_krb::constants::gss_api::{ACCEPT_INCOMPLETE, TGT_REP_TOKEN_ID, TGT_REQ_TOKEN_ID};
use picky_krb::constants::types::{NT_SRV_INST, TGT_REQ_MSG_TYPE};
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{TgtRep, TgtReq};

use crate::{Error, ErrorKind, Result, KERBEROS_VERSION};

/// Generates supported mechanism type list.
pub(super) fn generate_mech_type_list(kerberos: bool, no_ntlm_fallback: bool) -> Result<MechTypeList> {
    if no_ntlm_fallback && !kerberos {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "no_ntlm_fallback is set, but Kerberos is not enabled",
        ));
    }

    let mut mech_types = Vec::new();

    if kerberos {
        mech_types.push(MechType::from(oids::ms_krb5()));
        mech_types.push(MechType::from(oids::krb5()));
        // NEGOEX is not supported.
        // mech_types.push(MechType::from(oids::negoex()));
    }

    if !no_ntlm_fallback {
        mech_types.push(MechType::from(oids::ntlm_ssp()));
    }

    Ok(MechTypeList::from(Asn1SequenceOf::from(mech_types)))
}

/// Generates the initial SPNEGO token.
///
/// The `sname` parameter is optional. If it is present, then the Kerberos U2U is in use, and `TgtReq` will be generated
/// for the input `sname` and placed in the `mech_token` field.
pub(super) fn generate_neg_token_init(
    sname: Option<&[&str]>,
    mech_list: MechTypeList,
) -> Result<ApplicationTag0<GssApiNegInit>> {
    let mech_token = if let Some(sname) = sname {
        let sname = sname
            .iter()
            .map(|sname| Ok(KerberosStringAsn1::from(IA5String::from_string(sname.to_string())?)))
            .collect::<Result<Vec<_>>>()?;

        let krb5_neg_token_init = ApplicationTag0(KrbMessage {
            krb5_oid: ObjectIdentifierAsn1::from(oids::krb5_user_to_user()),
            krb5_token_id: TGT_REQ_TOKEN_ID,
            krb_msg: TgtReq {
                pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
                msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGT_REQ_MSG_TYPE])),
                server_name: ExplicitContextTag2::from(PrincipalName {
                    name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                    name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(sname)),
                }),
            },
        });

        Some(ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&krb5_neg_token_init)?,
        )))
    } else {
        None
    };

    Ok(ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(oids::spnego()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(mech_list))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(mech_token),
            mech_list_mic: Optional::from(None),
        }),
    }))
}

pub(super) fn generate_neg_token_targ_1(response_token: Option<Vec<u8>>) -> NegTokenTarg1 {
    NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(
            response_token.map(|token| ExplicitContextTag2::from(OctetStringAsn1::from(token))),
        ),
        mech_list_mic: Optional::from(None),
    })
}

pub(super) fn generate_final_neg_token_targ(
    neg_result: Vec<u8>,
    response_token: Option<Vec<u8>>,
    mech_list_mic: Option<Vec<u8>>,
) -> NegTokenTarg1 {
    NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(neg_result)))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(
            response_token.map(|token| ExplicitContextTag2::from(OctetStringAsn1::from(token))),
        ),
        mech_list_mic: Optional::from(mech_list_mic.map(|v| ExplicitContextTag3::from(OctetStringAsn1::from(v)))),
    })
}

pub(super) fn generate_neg_token_targ(mech_type: ObjectIdentifier, tgt_rep: Option<TgtRep>) -> Result<NegTokenTarg1> {
    let response_token = tgt_rep
        .map(|tgt_rep| {
            Result::Ok(ExplicitContextTag2::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&ApplicationTag0(KrbMessage {
                    krb5_oid: ObjectIdentifierAsn1::from(oids::krb5_user_to_user()),
                    krb5_token_id: TGT_REP_TOKEN_ID,
                    krb_msg: tgt_rep,
                }))?,
            )))
        })
        .transpose()?;
    Ok(NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(Some(ExplicitContextTag1::from(MechType::from(mech_type)))),
        response_token: Optional::from(response_token),
        mech_list_mic: Optional::from(None),
    }))
}
