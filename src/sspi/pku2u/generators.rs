use std::convert::TryFrom;
use std::str::FromStr;

use oid::ObjectIdentifier;
use picky_asn1::restricted_string::{BMPString, IA5String};
use picky_asn1::wrapper::{
    Asn1SequenceOf, Asn1SetOf, BMPStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ImplicitContextTag0, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_x509::oids::{AT_COMMON_NAME, NEGOEX, SPNEGO};
use picky_krb::constants::types::NT_SRV_INST;
use picky_krb::data_types::{KerberosStringAsn1, PrincipalName, Realm};
use picky_krb::gss_api::{ApplicationTag0, GssApiNegInit, MechType, MechTypeList, NegTokenInit};
use picky_krb::pkinit::{Pku2uNegoBody, Pku2uNegoReq, Pku2uNegoReqMetadata, Pku2uValue, Pku2uValueInner};

use crate::kerberos::SERVICE_NAME;
use crate::Result;

/// [The PKU2U Realm Name](https://datatracker.ietf.org/doc/html/draft-zhu-pku2u-09#section-3)
/// The PKU2U realm name is defined as a reserved Kerberos realm name, and it has the value of "WELLKNOWN:PKU2U".
pub const WELLKNOWN_REALM: &str = "WELLKNOWN:PKU2U";

/// "MS-Organization-P2P-Access [2021]" in UTF-16
pub const MS_ORGANIZATION_P2P_ACCESS: &str =
    "\0M\0S\0-\0O\0r\0g\0a\0n\0i\0z\0a\0t\0i\0o\0n\0-\0P\02\0P\0-\0A\0c\0c\0e\0s\0s\0 \0[\02\00\02\01\0]";

// returns supported authentication types
pub fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![
        MechType::from(ObjectIdentifier::try_from(NEGOEX).unwrap()),
        // MechType::from(ObjectIdentifier::try_from(NTLM_SSP).unwrap()),
    ])
}

pub fn generate_pku2u_nego_req(username: &str) -> Result<Pku2uNegoReq> {
    let inner = Pku2uValue {
        inner: Asn1SetOf::from(vec![Pku2uValueInner {
            identifier: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(AT_COMMON_NAME).unwrap()),
            value: BMPStringAsn1::from(BMPString::from_str(MS_ORGANIZATION_P2P_ACCESS).unwrap()),
        }]),
    };

    Ok(Pku2uNegoReq {
        metadata: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![Pku2uNegoReqMetadata {
            inner: ImplicitContextTag0::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&inner)?)),
        }])),
        body: ExplicitContextTag1::from(Pku2uNegoBody {
            realm: ExplicitContextTag0::from(Realm::from(IA5String::from_str(WELLKNOWN_REALM).unwrap())),
            sname: ExplicitContextTag1::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_str(SERVICE_NAME).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_str(username).unwrap()),
                ])),
            }),
        }),
    })
}

pub fn generate_neg_token_init(mech_token: Vec<u8>) -> Result<ApplicationTag0<GssApiNegInit>> {
    Ok(ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(SPNEGO).unwrap()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(get_mech_list()))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(mech_token)))),
            mech_list_mic: Optional::from(None),
        }),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn neg_token_init_generation() {
        //
    }
}
